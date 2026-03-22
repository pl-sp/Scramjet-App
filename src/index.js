import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import fs from "node:fs";
import crypto from "node:crypto";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie";
import Database from "better-sqlite3";

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// --- 初始化 SQLite 数据库 ---
const dbPath = fileURLToPath(new URL("../scramjet.db", import.meta.url));
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// 初始化表
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
    );
`);

// --- 尝试从旧版的 config.json 迁移数据 ---
const configUrl = new URL("../config.json", import.meta.url);
const configPath = fileURLToPath(configUrl);
if (fs.existsSync(configPath)) {
    try {
        const configData = fs.readFileSync(configPath, "utf-8");
        const parsedConfig = JSON.parse(configData);
        if (parsedConfig.users && Array.isArray(parsedConfig.users)) {
            const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)');
            const insertMany = db.transaction((users) => {
                for (const u of users) {
                    insertUser.run(u.user, u.pass, u.role || (u.user === 'admin' ? 'admin' : 'user'));
                }
            });
            insertMany(parsedConfig.users);
            console.log("[系统升级] 已从 config.json 成功迁移用户数据到 SQLite 数据库");
        }
        // 重命名防止未来再次读取
        fs.renameSync(configPath, configPath + '.bak');
    } catch (err) {
        console.error("迁移 config.json 失败:", err.message);
    }
}

// 允许环境变量覆盖
if (process.env.AUTH_USER && process.env.AUTH_PASS) {
    db.prepare('INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)').run(process.env.AUTH_USER, process.env.AUTH_PASS, 'admin');
} else if (process.env.AUTH_USER || process.env.AUTH_PASS) {
    console.warn("[警告] 必须同时提供环境变量 AUTH_USER 和 AUTH_PASS 才能通过环境变量配置用户。");
}

// 确保至少有一个配置的用户
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
if (userCount === 0) {
    const defaultPassword = Math.random().toString(36).slice(-10);
    console.warn("[警告] 数据库中未配置任何认证用户! 已自动生成初始 admin 账户。为了安全，已自动设置随机生成的密码");
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run('admin', defaultPassword, 'admin');
    console.warn(`[系统自动生成] user: admin, pass: ${defaultPassword}`);
}

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
                // 读取 scramjet_session cookie 进行校验
                const cookieHeader = req.headers.cookie || "";
                let sessionId = null;
                const match = cookieHeader.match(/scramjet_session=([^;]+)/);
                if (match) sessionId = match[1];

                let isAuthenticated = false;
                if (sessionId) {
                    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND expires_at > ?').get(sessionId, Date.now());
                    if (session) {
                        isAuthenticated = true;
                    }
                }

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

// --- 辅助鉴权函数 ---
function getSessionUser(request) {
    const sessionId = request.cookies['scramjet_session'];
    if (!sessionId) return null;
    const session = db.prepare('SELECT s.username, u.role FROM sessions s JOIN users u ON s.username = u.username WHERE s.id = ? AND s.expires_at > ?').get(sessionId, Date.now());
    if (!session) return null;
    return { user: session.username, role: session.role };
}

// 1. 登录 API 接口
fastify.post("/api/login", async (request, reply) => {
    const { user, pass } = request.body;
    
    // 检查密码
    const userRow = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(user, pass);

    if (userRow) {
        const sessionId = crypto.randomBytes(16).toString('hex');
        const expiresAt = Date.now() + 86400 * 1000; // 24小时

        db.prepare('INSERT INTO sessions (id, username, expires_at) VALUES (?, ?, ?)').run(sessionId, userRow.username, expiresAt);

        reply.setCookie('scramjet_session', sessionId, {
            path: "/",
            httpOnly: true,
            maxAge: 86400
        });
        
        return { success: true };
    }
    return reply.code(401).send({ success: false });
});

// 1.5 注册 API 接口 (仅限管理员)
fastify.post("/api/register", async (request, reply) => {
    const sessionUser = getSessionUser(request);
    if (!sessionUser || sessionUser.role !== 'admin') {
        return reply.code(403).send({ success: false, message: "只有管理员可以添加用户" });
    }

    const { user, pass } = request.body;
    const role = request.body.role || 'user';
    
    if (!user || user.trim() === "" || !pass || pass.trim() === "") {
        return reply.code(400).send({ success: false, message: "用户名和密码不能为空" });
    }

    try {
        db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(user, pass, role);
        return { success: true };
    } catch (err) {
        if (err.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') {
            return reply.code(409).send({ success: false, message: "用户名已存在" });
        }
        return reply.code(500).send({ success: false, message: "内部服务器错误" });
    }
});

// 1.8 登出 API 接口
fastify.post("/api/logout", async (request, reply) => {
    const sessionId = request.cookies['scramjet_session'];
    if (sessionId) {
        db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    }
    
    reply.clearCookie('scramjet_session', { path: "/" });
    
    return { success: true };
});

// 获取当前用户信息
fastify.get("/api/me", async (request, reply) => {
    const sessionUser = getSessionUser(request);
    if (!sessionUser) {
        return reply.code(401).send({ error: "Unauthorized" });
    }
    return { user: sessionUser.user, role: sessionUser.role };
});

// 获取所有用户信息 (仅限管理员)
fastify.get("/api/users", async (request, reply) => {
    const sessionUser = getSessionUser(request);
    if (!sessionUser || sessionUser.role !== 'admin') {
        return reply.code(403).send({ error: "Forbidden: Admins only" });
    }
    const usersList = db.prepare('SELECT username as user, role FROM users').all();
    return { success: true, users: usersList };
});

// 1.9 删除用户 API (仅限管理员)
fastify.delete("/api/users/:username", async (request, reply) => {
    const sessionUser = getSessionUser(request);
    if (!sessionUser || sessionUser.role !== 'admin') {
        return reply.code(403).send({ success: false, message: "只有管理员可以执行此操作" });
    }
    const { username } = request.params;

    if (username === 'admin') {
        return reply.code(403).send({ success: false, message: "内置 admin 账号不能被删除" });
    }
    
    // SQLite's ON DELETE CASCADE will handle deleting sessions if PRAGMA foreign_keys = ON;
    const info = db.prepare('DELETE FROM users WHERE username = ?').run(username);
    if (info.changes === 0) {
        return reply.code(404).send({ success: false, message: "用户未找到" });
    }

    return { success: true };
});

// 1.10 编辑用户 API (仅限管理员)
fastify.put("/api/users/:username", async (request, reply) => {
    const sessionUser = getSessionUser(request);
    if (!sessionUser || sessionUser.role !== 'admin') {
        return reply.code(403).send({ success: false, message: "只有管理员可以执行此操作" });
    }
    const { username } = request.params;
    const { pass, role } = request.body;

    if (username === 'admin' && sessionUser.user !== 'admin') {
        return reply.code(403).send({ success: false, message: "非 admin 账号不能修改 admin 账号信息" });
    }
    
    const userRow = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!userRow) {
        return reply.code(404).send({ success: false, message: "用户未找到" });
    }

    if (pass) {
        db.prepare('UPDATE users SET password = ? WHERE username = ?').run(pass, username);
    }
    if (role) {
        db.prepare('UPDATE users SET role = ? WHERE username = ?').run(role, username);
    }

    return { success: true };
});

// 2. 全局权限拦截钩子
fastify.addHook("preHandler", async (request, reply) => {
    const url = request.url;

    // 白名单：登录页、登录请求、注册请求、静态资源不拦截
    if (url === "/login.html" || url.startsWith("/api/login") || url.startsWith("/api/register") || url.includes("favicon.ico") || url.startsWith("/api/me")) {
        return;
    }

    const sessionUser = getSessionUser(request);
    if (!sessionUser) {
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