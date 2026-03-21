import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import fs from "node:fs";
import crypto from "node:crypto";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie"; // 新增

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// --- 可动态管理的权限配置 ---
// 首先尝试从 config.json 读取，允许环境变量覆盖
let AUTH_INFO = {
    users: [],
    cookieName: "scramjet_auth",
    token: "verified_access_888"
};

const SESSIONS = new Map(); // sessionId -> { user, role }

try {
    const configPath = new URL("../config.json", import.meta.url);
    if (fs.existsSync(configPath)) {
        const configData = fs.readFileSync(configPath, "utf-8");
        const parsedConfig = JSON.parse(configData);
        // Ensure roles are assigned properly from config
        parsedConfig.users = (parsedConfig.users || []).map(u => ({ ...u, role: u.role || (u.user === 'admin' ? 'admin' : 'user') }));
        Object.assign(AUTH_INFO, parsedConfig);
    }
} catch (err) {
    console.warn("读取或解析 config.json 失败:", err.message);
}

// 允许环境变量覆盖（使得 Docker 配置依然兼容）
// 如果环境变量提供了 AUTH_USER 和 AUTH_PASS，则将它们作为最优先的单用户添加或覆盖到数组中
if (process.env.AUTH_USER && process.env.AUTH_PASS) {
    // 覆盖第一个元素（如果存在）或直接添加入数组
    if (AUTH_INFO.users.length > 0) {
       AUTH_INFO.users[0] = { user: process.env.AUTH_USER, pass: process.env.AUTH_PASS, role: "admin" };
    } else {
       AUTH_INFO.users.push({ user: process.env.AUTH_USER, pass: process.env.AUTH_PASS, role: "admin" });
    }
} else if (process.env.AUTH_USER || process.env.AUTH_PASS) {
    console.warn("[警告] 必须同时提供环境变量 AUTH_USER 和 AUTH_PASS 才能通过环境变量配置用户。");
}

// 确保至少有一个配置的用户，否则给一个警告
if (AUTH_INFO.users.length === 0) {
    console.warn("[警告] 未配置任何认证用户! 请在 config.json 或是环境变量中设置账号。为了安全，已自动设置一个随机生成的密码");
    AUTH_INFO.users.push({ user: "admin", pass: Math.random().toString(36).slice(-10), role: "admin" });
    console.warn(`[系统自动生成] user: ${AUTH_INFO.users[0].user}, pass: ${AUTH_INFO.users[0].pass}`);
}

AUTH_INFO.cookieName = process.env.AUTH_COOKIE || AUTH_INFO.cookieName;
AUTH_INFO.token = process.env.AUTH_TOKEN || AUTH_INFO.token;

logging.set_level(logging.NONE);
Object.assign(wisp.options, {
	allow_udp_streams: false,
	hostname_blacklist: [/example\.com/],
	dns_servers: ["1.1.1.3", "1.0.0.3"],
});

const fastify = Fastify({
	serverFactory: (handler) => {
		return createServer()
			.on("request", (req, res) => {
				res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
				res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
				handler(req, res);
			})
			.on("upgrade", (req, socket, head) => {
                // --- 关键：对 Wisp 连接进行 Cookie 校验 ---
                const cookieHeader = req.headers.cookie || "";
                const isAuthenticated = cookieHeader.includes(`${AUTH_INFO.cookieName}=${AUTH_INFO.token}`);

				if (req.url.endsWith("/wisp/") && isAuthenticated) {
                    wisp.routeRequest(req, socket, head);
                } else {
                    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
                    socket.destroy();
                }
			});
	},
});

// 注册 Cookie 插件
fastify.register(fastifyCookie);

// 1. 登录 API 接口
fastify.post("/api/login", async (request, reply) => {
    const { user, pass } = request.body;
    
    // 检查提交的用户和密码是否匹配数组中的任何一个
    const userObj = AUTH_INFO.users.find(
        (cred) => cred.user === user && cred.pass === pass
    );

    if (userObj) {
        // 创建身份会话
        const sessionId = crypto.randomBytes(16).toString('hex');
        SESSIONS.set(sessionId, { user: userObj.user, role: userObj.role || (userObj.user === 'admin' ? 'admin' : 'user') });

        reply.setCookie('scramjet_session', sessionId, {
            path: "/",
            httpOnly: true,
            maxAge: 86400
        });
        
        reply.setCookie(AUTH_INFO.cookieName, AUTH_INFO.token, {
            path: "/",
            httpOnly: true, // 安全：JS 无法读取
            maxAge: 86400  // 24小时有效
        });
        return { success: true };
    }
    return reply.code(401).send({ success: false });
});

// 1.5 注册 API 接口 (仅限管理员)
fastify.post("/api/register", async (request, reply) => {
    const sessionId = request.cookies['scramjet_session'];
    const session = SESSIONS.get(sessionId);
    
    if (!session || session.role !== 'admin') {
        return reply.code(403).send({ success: false, message: "只有管理员可以添加用户" });
    }

    const { user, pass } = request.body;
    const role = request.body.role || 'user';
    
    if (!user || user.trim() === "" || !pass || pass.trim() === "") {
        return reply.code(400).send({ success: false, message: "用户名和密码不能为空" });
    }

    // 检查提交的用户是否已经存在
    const isExistingUser = AUTH_INFO.users.some(
        (cred) => cred.user === user
    );

    if (isExistingUser) {
        return reply.code(409).send({ success: false, message: "用户名已存在" });
    }

    AUTH_INFO.users.push({ user, pass, role });

    try {
        const configPath = new URL("../config.json", import.meta.url);
        let configToSave = { ...AUTH_INFO }; 
        if (fs.existsSync(configPath)) {
            const configData = fs.readFileSync(configPath, "utf-8");
            const parsedConfig = JSON.parse(configData);
            configToSave = { ...parsedConfig, users: AUTH_INFO.users };
        }
        fs.writeFileSync(configPath, JSON.stringify(configToSave, null, 4), "utf-8");
    } catch (err) {
        console.error("保存注册信息到 config.json 失败:", err.message);
    }
    
    return { success: true };
});

// 1.8 登出 API 接口
fastify.post("/api/logout", async (request, reply) => {
    const sessionId = request.cookies['scramjet_session'];
    if (sessionId) {
        SESSIONS.delete(sessionId);
    }
    
    reply.clearCookie('scramjet_session', { path: "/" });
    reply.clearCookie(AUTH_INFO.cookieName, { path: "/" });
    
    return { success: true };
});

// 获取当前用户信息
fastify.get("/api/me", async (request, reply) => {
    const sessionId = request.cookies['scramjet_session'];
    const session = SESSIONS.get(sessionId);
    if (!session) {
        return reply.code(401).send({ error: "Unauthorized" });
    }
    return { user: session.user, role: session.role };
});

// 2. 全局权限拦截钩子
fastify.addHook("preHandler", async (request, reply) => {
    const url = request.url;

    // 白名单：登录页、登录请求、注册请求、静态资源不拦截
    if (url === "/login.html" || url.startsWith("/api/login") || url.startsWith("/api/register") || url.includes("favicon.ico")) {
        return;
    }

    const token = request.cookies[AUTH_INFO.cookieName];
    if (token !== AUTH_INFO.token) {
        // 如果是访问 HTML 页面，重定向到登录页
        if (url === "/" || url.endsWith(".html")) {
            return reply.redirect("/login.html");
        }
        // 其它请求直接拒绝
        return reply.code(403).send("Forbidden");
    }
});

// --- 原有的静态资源挂载 ---
fastify.register(fastifyStatic, {
	root: publicPath,
	decorateReply: true,
});

fastify.register(fastifyStatic, {
	root: scramjetPath,
	prefix: "/scram/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: libcurlPath,
	prefix: "/libcurl/",
	decorateReply: false,
});

fastify.register(fastifyStatic, {
	root: baremuxPath,
	prefix: "/baremux/",
	decorateReply: false,
});

fastify.setNotFoundHandler((res, reply) => {
	return reply.code(404).type("text/html").sendFile("404.html");
});

// --- 启动与监听逻辑保持不变 ---
fastify.server.on("listening", () => {
	const address = fastify.server.address();
	console.log("Listening on:");
	console.log(`\thttp://localhost:${address.port}`);
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
	console.log("SIGTERM signal received: closing HTTP server");
	fastify.close();
	process.exit(0);
}

let port = parseInt(process.env.PORT || "");
if (isNaN(port)) port = 8080;

fastify.listen({
	port: port,
	host: "0.0.0.0",
});