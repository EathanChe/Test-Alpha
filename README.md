# Test-Alpha

原型工程基于 Vite + React + TypeScript，新增 Cloudflare Workers + Durable Objects + D1 后端，实现“血染大厅（BOTC Day Chat Manager）”多人在线 MVP：

- 多设备可见大厅列表、在线人数、公开聊天实时同步。
- 说书人创建大厅时生成 `storytellerKey`，管理操作需要携带该 key。
- 玩家通过大厅码 + 密码加入，密码使用 PBKDF2 + salt 存储。
- D1 持久化大厅、玩家、消息；Durable Object WebSocket 广播实时消息。

产品需求详情见 [docs/BOTC-Day-Chat-Manager-PRD.md](docs/BOTC-Day-Chat-Manager-PRD.md)。

## 项目结构

```
├─ backend
│  ├─ migrations
│  ├─ src
│  ├─ package.json
│  └─ wrangler.toml
├─ src
├─ index.html
├─ package.json
└─ README.md
```

## Cloudflare 资源准备清单（必须手动完成）

- [ ] 注册/登录 Cloudflare 账号
- [ ] 安装 Wrangler CLI（`npm install -g wrangler` 或使用 `backend` 目录的依赖）
- [ ] 创建 D1 数据库
- [ ] 拿到 D1 `database_id` 并写入 `backend/wrangler.toml`
- [ ] 设置 Worker 变量 `TOKEN_SECRET`
- [ ]（可选）绑定自定义域名

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

3) 创建 D1：

```bash
npx wrangler d1 create botc-day-chat
```

执行后会输出 `database_id`，把它填到 `backend/wrangler.toml` 的 `database_id`。

4) 初始化表结构（本地开发与线上都要）：

```bash
npx wrangler d1 migrations apply botc-day-chat --local
npx wrangler d1 migrations apply botc-day-chat
```

5) 配置开发环境变量：

在 `backend` 目录创建 `.dev.vars`（可复制 `backend/.dev.vars.example`），并写入：

```
TOKEN_SECRET=REPLACE_WITH_STRONG_SECRET
```

6) 本地启动 Worker：

```bash
npx wrangler dev
```

默认地址为 `http://127.0.0.1:8787`。

7) 部署线上：

```bash
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

3) 启动前端：

```bash
npm run dev
```

## API 设计（MVP）

- `POST /api/halls` `{name, password}` -> `{hallId, hallCode, storytellerKey}`
- `GET /api/halls` -> 列表（基础字段 + 在线人数）
- `POST /api/halls/:code/join` `{playerName, password}` -> `{playerId, sessionToken, hall}`
- `GET /api/halls/:code` -> `{hall}`
- `GET /api/halls/:code/messages?token=...` -> 最近消息
- `GET /api/halls/:code/roster?token=...` -> 在线玩家列表
- `POST /api/halls/:code/admin/reset-day` `{storytellerKey}` -> `{hall}`
- `WS /ws/halls/:code?token=...` 实时通道

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
npx wrangler dev

# 前端
npm install
npm run dev
```
