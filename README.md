# Simple-Server——极简Python服务器

> [!WARNING]
> 建设中，未完待续。

> [!NOTE]
> 练手项目，代码质量较差，不喜勿喷。

## 概述

**Simple-Server** 是一个功能丰富且高度可配置的 Web 服务器，使用 **Python** 编写。它提供了多个高级功能，例如自定义错误页面、IP 访问控制、SSL 支持、日志记录等。该服务器旨在灵活并易于扩展，内置工具用于监控、配置热加载和优雅关闭。

### 主要功能：
1. 自定义 404 和 403 错误页面。
2. 使用正则表达式的路由处理（例如：`/user/{username}`）。
3. 基于 IP 的访问控制，支持自定义 403 错误页面。
4. 可配置端口和 SSL 支持。
5. 使用 `RotatingFileHandler` 进行日志记录（`server.log` 和 `client.log`）。
6. 自动启动浏览器（可选）。
7. 服务器运行在单独的线程中，主线程支持交互式的关闭提示。
8. 支持静态文件处理和路由配置。
9. 支持 SSL（可选）。
10. 支持守护进程模式（仅限 UNIX 系统）。
11. 实时监控配置文件变化（使用 `watchdog` 或轮询）。
12. 使用 `uvloop` 优化 `asyncio` 性能。
13. Windows 系统下提升管理员权限，伪装进程。
14. 提供 `/metrics` 接口，返回系统资源信息与运行状态。
15. 优雅关闭与任务清理，确保所有请求完成后退出。
### 文件结构：
```
Simple-Server
├─ admin
│  └─ admin.html
├─ config.json
├─ logs
│  ├─ client.log
│  └─ server.log
├─ metrics
│  └─ (空).txt
├─ server
│  ├─ 403.html
│  ├─ 404.html
│  ├─ index.html
│  └─ static
│     ├─ icon
│     │  ├─ favicon-0.ico
│     │  └─ favicon-1.png
│     └─ js
│        ├─ 404.js
│        └─ stat.js
└─ sever.py
```

## 技术概述

### 依赖项
- `aiohttp`: 用于异步 Web 处理。
- `aiohttp_jinja2`: 用于 Jinja2 模板引擎。
- `psutil`（可选）: 用于系统资源监控。
- `watchdog`（可选）: 用于实时配置文件监控。
- `uvloop`（可选）: 用于提升 `asyncio` 性能。
- `setproctitle`（可选）: 用于修改进程标题。

### 主要组件

#### 日志记录
- 日志分为两类：**服务器日志** 和 **客户端日志**。
- 日志文件存储在 `logs/` 目录下，采用滚动日志机制，每个日志文件大小限制为 5MB。
- 日志内容包括客户端访问信息、错误日志和服务器状态更新。

#### 中间件
1. **日志记录中间件**：记录客户端的请求、响应及处理时间。
2. **IP 拒绝中间件**：根据配置文件中的黑名单，拒绝指定 IP 的访问，并返回自定义的 403 错误页面。

#### 配置
- 服务器配置存储在 `config.json` 文件中。
- 配置项包括端口号、SSL 证书路径、黑名单 IP、缓存设置等。
- 配置可以通过管理员面板修改，或者直接编辑 `config.json` 文件。

#### 路由
- **动态路由示例**：`/user/{username}`，其中 `{username}` 是动态捕获的。
- **管理员面板**：允许修改服务器设置，如黑名单 IP 和缓存超时。
- **/metrics 接口**：暴露系统监控数据，包括 CPU 和内存使用情况。

#### 服务器生命周期
- 服务器运行在后台线程中，主线程通过交互式命令提示符触发优雅关闭。
- 可以选择将服务器运行在前台或者守护进程模式。

### 可选功能
- **SSL**：通过提供证书和密钥文件启用 HTTPS。
- **自动启动浏览器**：服务器启动时可以自动打开浏览器窗口。
- **守护进程模式**：在 UNIX 系统上，服务器可以在守护进程模式下运行。
- **配置监控**：服务器可以使用 `watchdog` 或轮询方式实时监控 `config.json` 文件的变化。

### 错误处理
- 可以定义自定义的 404 和 403 错误页面。
- 加载静态文件、处理请求或读取配置文件时发生的错误都会被记录，并尝试显示自定义错误页面（如果可用）。

---

## 部署指南

### 系统要求
- **Python 3.7+**：确保已安装 Python 3.7 或更高版本。
- **依赖项安装**：使用 `pip` 安装所需的库：

    ```bash
    pip install aiohttp aiohttp_jinja2 psutil watchdog uvloop setproctitle
    ```

    如果使用 SSL，还需要 SSL 证书（`cert.pem` 和 `key.pem`）及相应的配置。

### 配置
1. **编辑配置文件**：
    服务器的配置存储在 `config.json` 文件中。你可以配置以下内容：
    - `port`：服务器监听的端口。
    - `ssl_enabled`：是否启用 SSL（需要证书）。
    - `denied_ips`：黑名单 IP 列表。
    - `cache_max_age`：静态文件的缓存超时时间。
    - `open_browser`：是否在启动时自动打开浏览器。

    如果 `config.json` 文件不存在，服务器会创建默认配置文件。

2. **自定义错误页面**：
    将自定义的 HTML 文件放置在 `server/` 目录下，文件名应为 `404.html` 和 `403.html`。

### 启动服务器
启动服务器，执行以下命令：

```bash
python server.py --port 8080 --ssl --verbose --no-browser --daemon
```

- `--port` 选项指定服务器的监听端口。
- `--ssl` 启用 SSL（需要有效的证书和密钥文件）。
- `--verbose` 启用详细日志记录。
- `--no-browser` 防止自动启动浏览器。
- `--daemon` 以守护进程方式运行（仅限 Mac、Linux系统）。

### 以守护进程模式运行（仅限 Mac、Linux）
在 UNIX 系统上，可以使用 `--daemon` 参数将服务器作为后台进程运行：

```bash
python server.py --daemon --port 8080
```

这将使服务器进程脱离终端，在后台运行。

### 配置文件变化监控
- 如果安装了 `watchdog`，服务器会自动检测 `config.json` 文件的变化并重新加载配置。
- 如果没有安装 `watchdog`，服务器将每 5 秒轮询一次 `config.json` 文件来检查是否有变化。

### 停止服务器
当服务器启动后，可以通过主线程的交互式命令提示符输入 `exit` 来停止服务器。你将看到以下关闭选项：

1. **完全关闭**：完全关闭服务器，确保所有任务完成后退出。
2. **后台运行**：主线程退出，服务器继续在后台运行。
3. **取消**：取消关闭操作，服务器继续运行。

### SSL 配置
启用 SSL 时，在配置文件中提供证书和密钥文件的路径。证书文件必须位于服务器目录中，或者你可以修改配置文件指定其他位置。

### 健康检查
- 服务器提供 `/metrics` 接口，返回系统的监控数据，如 CPU 和内存使用情况，以及客户端访问统计。
- 该接口可以用于实时监控服务器健康状况。

---

## 常见问题

- **SSL 问题**：确保配置文件中 SSL 证书和密钥文件的路径正确。如果 SSL 设置失败，服务器将回退到无 SSL 模式运行。
- **权限问题**：如果在 Windows 上运行，请确保具有管理员权限。服务器可以自动提升权限（如果需要）。
- **配置重新加载**：如果服务器没有检测到配置文件的变化，确保已安装 `watchdog` 或轮询任务正常运行。

