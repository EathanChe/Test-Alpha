# Test-Alpha

原型工程基于 Vite + React + TypeScript，提供“血染大厅（BOTC Day Chat Manager）”的可运行 Web App 雏形：

- 首页仅含两个入口按钮：“我是说书人：创建大厅”“我是玩家：浏览大厅”。
- 说书人可以创建大厅并获得大厅码；玩家可浏览大厅列表并输入密码加入。
- 进入大厅后提供基础聊天区，所有数据保存在浏览器本地存储，便于离线演示。

产品需求详情见 [docs/BOTC-Day-Chat-Manager-PRD.md](docs/BOTC-Day-Chat-Manager-PRD.md)。

## 本地运行

1. 安装依赖：

   ```bash
   npm install
   ```

2. 启动开发服务器：

   ```bash
   npm run dev
   ```

   默认会在终端显示本地访问地址，例如 `http://localhost:5173/`。

3. 构建产物（可选）：

   ```bash
   npm run build
   ```

## 项目结构

```
├─ index.html
├─ package.json
├─ tsconfig.json
├─ vite.config.ts
└─ src
   ├─ App.tsx        # 页面与交互逻辑
   ├─ App.css        # 组件样式
   ├─ index.css      # 全局样式
   └─ main.tsx       # 入口文件
```
