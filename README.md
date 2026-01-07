# Test-Alpha

原型工程基于 Vite + React + TypeScript，新增 Cloudflare Workers + Durable Objects + D1 后端，实现“血染大厅（BOTC Day Chat Manager）”多人在线 MVP：

- 多设备可见大厅列表、在线人数、公开聊天实时同步。
- 说书人创建大厅时生成 `storytellerKey`，管理操作需要携带该 key。
- 玩家通过大厅码 + 密码加入，密码使用 PBKDF2 + salt 存储。
- D1 持久化大厅、玩家、消息；Durable Object WebSocket 广播实时消息。
- 大厅列表采用 5 秒轮询（开发模式下 StrictMode 已避免重复 interval）。

产品需求详情见 [docs/BOTC-Day-Chat-Manager-PRD.md](docs/BOTC-Day-Chat-Manager-PRD.md)。

## 项目结构

```
├─ backend
│  ├─ migrations
│  ├─ src
│  ├─ package.json
│  └─ wrangler.toml
├─ public
│  └─ _redirects
├─ src
├─ index.html
├─ package.json
└─ README.md
```

## Cloudflare Pages 构建配置

- Framework：Vite
- Build command：`npm run build`
- Output directory：`dist`
- Root directory：仓库根目录（不是 `backend`）
- Pages 环境变量：`VITE_API_BASE`（填写你的 Workers URL）
  - 生产环境必须配置 `VITE_API_BASE`，否则前端会提示未配置后端。

## 后端（Workers + DO + D1）从 0 启动

1) 进入后端目录并安装依赖：

```bash
cd backend
npm install
```

2) 登录 Cloudflare：

```bash
npx wrangler login
```

3) 创建 D1（示例命名为 `botc_chat`）：

```bash
npx wrangler d1 create botc_chat
```

执行后会输出 `database_id`，把它填到 `backend/wrangler.toml` 的 `database_id`。

4) 初始化表结构：

```bash
# 本地
npx wrangler d1 migrations apply botc_chat --local

# 线上
npx wrangler d1 migrations apply botc_chat --remote
```

5) 配置开发环境变量：

在 `backend` 目录创建 `.dev.vars`（可复制 `backend/.dev.vars.example`），并写入：

```
TOKEN_SECRET=REPLACE_WITH_STRONG_SECRET
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

6) 本地启动 Worker（默认使用本地模式）：

```bash
npx wrangler dev
```

如需强制本地模式可使用：

```bash
npx wrangler dev --local
```

默认地址为 `http://127.0.0.1:8787`。

7) 部署线上：

```bash
# 设置 TOKEN_SECRET（不要写入仓库）
cd backend
npx wrangler secret put TOKEN_SECRET

# 设置 CORS_ORIGINS（允许 Pages 域名 + 本地开发）
# 示例：
# npx wrangler deploy --var CORS_ORIGINS="http://localhost:5173,https://your-pages.pages.dev"

npx wrangler deploy
```

## 前端本地运行

1) 根目录安装依赖：

```bash
npm install
```

2) 配置后端地址：

在根目录新建 `.env`（可参考 `.env.example`）：

```
VITE_API_BASE=http://127.0.0.1:8787
```

未设置 `VITE_API_BASE` 时默认使用 `http://127.0.0.1:8787`。

3) 启动前端：

```bash
npm run dev
```

## CORS 配置说明

- 后端从 `CORS_ORIGINS` 读取允许的 Origin 列表（逗号分隔）。
- 预检 OPTIONS 返回 204 且无 body。
- 所有 JSON API 响应都会附带 CORS headers。

## API 设计（MVP）

- `POST /api/halls` `{name, password}` -> `{hallId, hallCode, storytellerKey}`
- `GET /api/halls` -> 列表（基础字段 + 在线人数）
- `POST /api/halls/:code/join` `{playerName, password}` -> `{playerId, sessionToken, hall}`
- `GET /api/halls/:code` -> `{hall}`
- `GET /api/halls/:code/messages?token=...` -> 最近消息
- `GET /api/halls/:code/roster?token=...` -> 在线玩家列表
- `POST /api/halls/:code/admin/reset-day` `{storytellerKey}` -> `{hall}`
- `POST /api/halls/:code/admin/phase` `{storytellerKey, action}` -> `{hall}`
- `POST /api/halls/:code/private-requests` `{targetName}` -> `{request}`
- `POST /api/halls/:code/private-requests/:id/respond` `{response}` -> `{request, session?}`
- `WS /ws/halls/:code?token=...` 实时通道

## 最短上线清单（Pages + Workers）

1) 后端：
   - `cd backend && npm i`
   - `npx wrangler d1 create botc_chat`（拿到 `database_id` 填入 `backend/wrangler.toml`）
   - `npx wrangler d1 migrations apply botc_chat --remote`
   - `npx wrangler secret put TOKEN_SECRET`
   - `npx wrangler deploy --var CORS_ORIGINS="https://YOUR_PAGES.pages.dev"`
   - 记录 Workers URL（`https://xxx.workers.dev`）

2) 前端（Pages）：
   - 创建 Pages 项目，Root directory 指向仓库根目录
   - 设置环境变量 `VITE_API_BASE=https://xxx.workers.dev`
   - 触发构建，得到 Pages URL

完成后：Pages URL 访问即可连通 Workers。WebSocket 会自动从同一 base 推导。

## 快速自检（两台设备）

1) 设备 A 打开前端，选择“说书人创建大厅”。
2) 记录大厅码与 `storytellerKey`，保持在大厅内。
3) 设备 B 打开前端，通过大厅码加入同一大厅。
4) 双方发送消息，确认实时出现。

## 本地开发命令摘要

```
# 后端
cd backend
npm install
npx wrangler d1 migrations apply botc_chat --local
npx wrangler dev

# 前端
npm install
npm run dev
```
