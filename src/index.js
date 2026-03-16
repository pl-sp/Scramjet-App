import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie"; // 新增

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// --- 简单权限配置 ---
const AUTH_INFO = {
    user: "admin",
    pass: "123456",
    cookieName: "scramjet_auth",
    token: "verified_access_888"
};

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
    if (user === AUTH_INFO.user && pass === AUTH_INFO.pass) {
        reply.setCookie(AUTH_INFO.cookieName, AUTH_INFO.token, {
            path: "/",
            httpOnly: true, // 安全：JS 无法读取
            maxAge: 86400  // 24小时有效
        });
        return { success: true };
    }
    return reply.code(401).send({ success: false });
});

// 2. 全局权限拦截钩子
fastify.addHook("preHandler", async (request, reply) => {
    const url = request.url;

    // 白名单：登录页、登录请求、静态资源不拦截
    if (url === "/login.html" || url.startsWith("/api/login") || url.includes("favicon.ico")) {
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