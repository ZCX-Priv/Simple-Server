#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Advanced Python Server
----------------------
主要功能：
    1. 自定义 404 页面（放置在 server/404.html）。
    2. 正则表达式路由示例（例如 /user/{username}）。
    3. 自定义 IP 拒绝访问（返回 server/403.html）。
    4. 支持自定义端口（配置文件与命令行参数）。
    5. 日志记录：使用 RotatingFileHandler 实现日志滚动（server.log 与 client.log）。
    6. 自动打开浏览器（可选）。
    7. 服务器运行在独立线程中，主线程支持 exit 命令弹出关闭提示：
         - 完全关闭：等待所有任务结束后退出。
         - 后台运行：主线程退出，服务器继续后台运行。
         - 取消：取消关闭操作。
    8. 内置复杂路由与静态文件支持（静态资源位于 server 文件夹）。
    9. 支持 SSL（可选）。
   10. 支持后台守护进程模式（--daemon 参数，仅 UNIX）。
   11. 实时监控配置文件变化（使用 watchdog 或轮询）。
   12. 优先使用 uvloop 优化 asyncio 性能。
   13. Windows 下检测管理员权限并提升、伪装进程标题。
   14. 提供 /metrics 接口返回运行状态与系统资源信息（psutil）。
   15. 平滑关闭与任务清理，确保所有请求处理完毕后退出。
   16. 定时健康检查任务，周期性将服务器状态写入日志。
"""

import argparse
import asyncio
import aiohttp
import aiohttp_jinja2
import jinja2
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import ssl
import sys
import threading
import time
import webbrowser
import ipaddress
import socket
from aiohttp import web
from datetime import datetime

# 优先使用 uvloop（若安装）
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# 尝试加载 psutil（用于系统监控）
try:
    import psutil
except ImportError:
    psutil = None

# 尝试加载 watchdog（用于配置热加载）
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
# ===================== 新增中间件定义 =====================

@web.middleware
async def logging_middleware(request, handler):
    """日志记录中间件，记录客户端访问信息。"""
    start_time = time.time()
    try:
        response = await handler(request)
    except web.HTTPException as ex:
        response = ex
    elapsed = (time.time() - start_time) * 1000  # 毫秒
    client_ip = request.remote
    AdvancedServer.client_logger.info(
        f"{client_ip} - \"{request.method} {request.path} "
        f"HTTP/{request.version.major}.{request.version.minor}\" "
        f"{response.status} {elapsed:.1f}ms"
    )
    # 统计访问次数
    AdvancedServer.client_access_count[client_ip] = AdvancedServer.client_access_count.get(client_ip, 0) + 1
    return response

@web.middleware
async def ip_deny_middleware(request, handler):
    """IP拒绝中间件，检查客户端IP是否在黑名单中。"""
    denied_ips = AdvancedServer.config.get("denied_ips", [])
    if request.remote in denied_ips:
        # 返回自定义403页面
        forbidden_path = os.path.join(SERVER_ROOT, "403.html")
        if os.path.exists(forbidden_path):
            try:
                with open(forbidden_path, "r", encoding="utf-8") as f:
                    content = f.read()
                return web.Response(text=content, status=403, content_type="text/html")
            except Exception as ex:
                AdvancedServer.server_logger.error(f"读取403页面失败: {ex}")
        return web.Response(text="403 Forbidden", status=403, content_type="text/plain")
    return await handler(request)
# ===================== 全局常量与配置 =====================

DEFAULT_CONFIG = {
    "port": 8080,
    "ssl_enabled": False,
    "ssl_cert": "cert.pem",
    "ssl_key": "key.pem",
    "denied_ips": [],
    "open_browser": True,
    "cache_max_age": 3600,
}

CONFIG_FILE = "config.json"
LOGS_DIR = "logs"
SERVER_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server")

# ===================== 工具函数 =====================

def check_and_elevate():
    """检查是否具有管理员权限（仅 Windows），否则尝试以管理员权限重启自身。"""
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                params = " ".join(sys.argv)
                DETACHED_PROCESS = 0x00000008
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                sys.exit(0)
        except Exception as ex:
            print(f"[Error] Admin check: {ex}", file=sys.stderr)

def set_process_title(title="svchost.exe"):
    """修改进程标题，需安装 setproctitle 模块。"""
    try:
        from setproctitle import setproctitle
        setproctitle(title)
    except ImportError:
        print("setproctitle not installed.", file=sys.stderr)
    except Exception as ex:
        print(f"[Error] Set process title: {ex}", file=sys.stderr)

def create_rotating_handler(filename, level, fmt):
    """创建 RotatingFileHandler 日志处理器。"""
    handler = RotatingFileHandler(
        os.path.join(LOGS_DIR, filename),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(fmt))
    return handler

def init_logging(verbose=False):
    """初始化日志系统，返回 server 与 client 日志对象。"""
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
    server_log = logging.getLogger("server")
    server_log.setLevel(logging.DEBUG if verbose else logging.INFO)
    server_log.addHandler(create_rotating_handler("server.log", logging.DEBUG,
                                                  "%(asctime)s - %(levelname)s - %(message)s"))
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    server_log.addHandler(console)

    client_log = logging.getLogger("client")
    client_log.setLevel(logging.INFO)
    client_log.addHandler(create_rotating_handler("client.log", logging.INFO,
                                                  "%(asctime)s - %(message)s"))
    return server_log, client_log

def load_config():
    """加载配置文件，若不存在则生成默认配置，同时校验关键参数。"""
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        config = DEFAULT_CONFIG.copy()
    else:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
    # 校验与补全关键参数
    if "port" not in config or not isinstance(config["port"], int):
        config["port"] = DEFAULT_CONFIG["port"]
    if "cache_max_age" not in config or not isinstance(config["cache_max_age"], int):
        config["cache_max_age"] = DEFAULT_CONFIG["cache_max_age"]
    return config

# ===================== 配置热加载 =====================

if WATCHDOG_AVAILABLE:
    class ConfigChangeHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if event.src_path.endswith(CONFIG_FILE):
                AdvancedServer.server_logger.info("Configuration file change detected (watchdog).")
                AdvancedServer.reload_config()
    def start_config_watcher():
        event_handler = ConfigChangeHandler()
        observer = Observer()
        observer.schedule(event_handler, os.path.dirname(os.path.abspath(CONFIG_FILE)), recursive=False)
        observer.daemon = True
        observer.start()
        return observer
else:
    async def config_polling_task(stop_event: threading.Event):
        last_mtime = os.path.getmtime(CONFIG_FILE)
        while not stop_event.is_set():
            try:
                mtime = os.path.getmtime(CONFIG_FILE)
                if mtime != last_mtime:
                    AdvancedServer.server_logger.info("Configuration file change detected (polling).")
                    AdvancedServer.reload_config()
                    last_mtime = mtime
                await asyncio.sleep(5)
            except Exception as ex:
                AdvancedServer.server_logger.exception(f"Error in config polling: {ex}")
                await asyncio.sleep(5)

# ===================== AdvancedServer 类 =====================

class AdvancedServer:
    """
    AdvancedServer 封装了服务器的初始化、启动、配置热加载、健康检查和关闭等功能。
    """
    # 类属性：共享配置与日志对象
    config = load_config()
    server_logger, client_logger = init_logging(verbose=False)
    client_access_count = {}  # 记录各 IP 访问次数
    shutdown_event = threading.Event()  # 用于完全关闭服务器
    config_stop_event = threading.Event()  # 用于停止配置轮询任务

    def __init__(self, port=None, ssl_enabled=False):
        """初始化服务器实例，支持参数覆盖配置。"""
        self.port = port or self.config.get("port", 8000)
        self.ssl_enabled = ssl_enabled or self.config.get("ssl_enabled", False)
        self.observer = None  # 用于watchdog观察者对象

    @classmethod
    def reload_config(cls):
        """重新加载配置文件并更新类属性 config。"""
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                new_config = json.load(f)
            cls.config.update(new_config)
            cls.server_logger.info("Configuration reloaded from file.")
        except Exception as ex:
            cls.server_logger.exception(f"Error reloading configuration: {ex}")

    async def init_app(self):
        """初始化 aiohttp 应用，并配置 jinja2 模板和各路由。"""
        app = web.Application(middlewares=[logging_middleware, ip_deny_middleware])
        templates_path = os.path.join(os.path.dirname(__file__), "templates")
        aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(templates_path))
        self.setup_routes(app)
        return app

    def setup_routes(self, app):
        """配置各路由，包括示例路由、控制面板、/metrics 与静态文件处理。"""
        # 示例路由：/user/{username}
        async def user_handler(request):
            username = request.match_info.get("username", "Anonymous")
            return web.Response(text=f"Hello, {username}!", content_type="text/plain")
        app.router.add_get(r'/user/{username:\w+}', user_handler)

        # 控制面板（admin）：使用 jinja2 模板
        @aiohttp_jinja2.template('admin.html')
        async def admin_panel(request):
            if request.method == "POST":
                try:
                    data = await request.post()
                    denied_ips = data.get("denied_ips", "")
                    cache_max_age = int(data.get("cache_max_age", self.config.get("cache_max_age", 3600)))
                    self.config["denied_ips"] = [ip.strip() for ip in denied_ips.split(",") if ip.strip()]
                    self.config["cache_max_age"] = cache_max_age
                    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(self.config, f, indent=4)
                    self.server_logger.info("Configuration updated via admin panel.")
                    return {"config": self.config, "message": "Configuration updated successfully!"}
                except Exception as ex:
                    self.server_logger.exception("Error updating configuration via admin panel.")
                    return {"config": self.config, "message": f"Error: {ex}"}
            else:
                return {"config": self.config, "message": ""}
        app.router.add_route('*', '/admin', admin_panel)

        # /metrics 接口返回系统监控数据
        async def metrics_handler(request):
            metrics = {
                "timestamp": datetime.utcnow().isoformat(),
                "client_access": self.client_access_count.copy()
            }
            if psutil:
                try:
                    metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
                    metrics["memory"] = psutil.virtual_memory()._asdict()
                except Exception as ex:
                    self.server_logger.exception(f"Error retrieving system metrics: {ex}")
            return web.json_response(metrics)
        app.router.add_get('/metrics', metrics_handler)

       # 静态文件处理
        async def static_handler(request):
            rel_path = request.match_info.get('path', '')
            full_path = os.path.join(SERVER_ROOT, rel_path)
            if os.path.isdir(full_path):
                full_path = os.path.join(full_path, "index.html")
            if os.path.exists(full_path):
                try:
                    with open(full_path, "rb") as f:
                        content = f.read()
                except Exception as ex:
                    self.server_logger.exception(f"Error reading static file {full_path}: {ex}")
                    return web.Response(text="Internal Server Error", status=500)
                if full_path.endswith(".html"):
                    content_type = "text/html"
                elif full_path.endswith(".css"):
                    content_type = "text/css"
                elif full_path.endswith(".js"):
                    content_type = "application/javascript"
                elif full_path.endswith(".png"):
                    content_type = "image/png"
                else:
                    content_type = "application/octet-stream"
                headers = {"Cache-Control": f"max-age={self.config.get('cache_max_age', 3600)}"}
                return web.Response(body=content, content_type=content_type, headers=headers)
            else:
                notfound_path = os.path.join(SERVER_ROOT, "404.html")
                if os.path.exists(notfound_path):
                    try:
                        with open(notfound_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        return web.Response(text=content, status=404, content_type="text/html")
                    except Exception as ex:
                        self.server_logger.exception(f"Error reading 404 page: {ex}")
                return web.Response(text="404 Not Found", status=404)
        app.router.add_get('/{path:.*}', static_handler)

    async def cleanup_tasks(self, app):
        """等待所有 pending 任务结束后再关闭服务器。"""
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        if tasks:
            self.server_logger.info(f"Waiting for {len(tasks)} tasks to finish...")
            await asyncio.gather(*tasks, return_exceptions=True)

    async def shutdown_checker(self, loop):
        """定时检查 shutdown_event，触发后停止事件循环。"""
        while not self.shutdown_event.is_set():
            await asyncio.sleep(1)
        self.server_logger.info("Shutdown event detected. Stopping event loop...")
        loop.stop()

    async def health_check_task(self):
        """定时健康检查任务，每隔 60 秒记录一次服务器状态。"""
        while not self.shutdown_event.is_set():
            try:
                pending = len([t for t in asyncio.all_tasks() if not t.done()])
                msg = f"Health Check: {pending} pending tasks."
                if psutil:
                    cpu = psutil.cpu_percent(interval=0.1)
                    mem = psutil.virtual_memory().percent
                    msg += f" CPU: {cpu}%  Memory: {mem}%"
                self.server_logger.info(msg)
            except Exception as ex:
                self.server_logger.exception(f"Error in health check: {ex}")
            await asyncio.sleep(60)

    async def graceful_shutdown(self, app):
        """平滑关闭：等待所有 pending 任务完成，关闭异步生成器等。"""
        self.server_logger.info("Initiating graceful shutdown...")
        try:
            await app.shutdown()
            await self.cleanup_tasks(app)
            await self.runner.shutdown()
            await self.runner.cleanup()
            await self.loop.shutdown_asyncgens()
        except Exception as ex:
            self.server_logger.exception(f"Error during graceful shutdown: {ex}")

    def run(self):
        """启动服务器：初始化事件循环、配置 SSL、启动站点、启动健康检查与配置监控任务。"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        app = self.loop.run_until_complete(self.init_app())
        self.runner = web.AppRunner(app)
        self.loop.run_until_complete(self.runner.setup())

        # 配置 SSL
        ssl_context = None
        if self.ssl_enabled or self.config.get("ssl_enabled", False):
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                ssl_context.load_cert_chain(self.config.get("ssl_cert"), self.config.get("ssl_key"))
            except Exception as ex:
                self.server_logger.exception("Failed to load SSL certificate. Falling back to non-SSL.")
                ssl_context = None
        site = web.TCPSite(self.runner, "0.0.0.0", self.port, ssl_context=ssl_context)
        self.loop.run_until_complete(site.start())
        self.server_logger.info(f"======= Serving on port {self.port} =======")

        # 启动配置监控：使用 watchdog 或轮询
        if WATCHDOG_AVAILABLE:
            self.observer = start_config_watcher()
            self.server_logger.info("Watchdog config monitor started.")
        else:
            self.loop.create_task(config_polling_task(self.config_stop_event))
            self.server_logger.info("Config polling task started.")

        # 启动健康检查任务
        self.loop.create_task(self.health_check_task())

        # 启动 shutdown 检查任务
        self.loop.create_task(self.shutdown_checker(self.loop))

        try:
            self.loop.run_forever()
        except Exception as ex:
            self.server_logger.exception(f"Exception in event loop: {ex}")
        finally:
            self.server_logger.info("Cleaning up server...")
            self.loop.run_until_complete(self.graceful_shutdown(app))
            self.loop.close()
            self.server_logger.info("Server shutdown complete.")

    def start_in_thread(self):
        """在子线程中启动服务器（服务器线程为非守护线程，支持后台运行）。"""
        thread = threading.Thread(target=self.run, daemon=False)
        thread.start()
        return thread

    def stop(self):
        """通知服务器完全关闭，并退出程序"""
        self.shutdown_event.set()
        self.config_stop_event.set()
        self.server_logger.info("Server is shutting down...")

# ===================== 信号与守护进程支持 =====================

def daemonize():
    """在 UNIX 系统下以守护进程方式运行，需安装 python-daemon。"""
    try:
        import daemon
        context = daemon.DaemonContext(
            working_directory=os.getcwd(),
            umask=0o002,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        context.open()
    except ImportError:
        AdvancedServer.server_logger.error("python-daemon not installed; cannot daemonize.")
    except Exception as ex:
        AdvancedServer.server_logger.exception(f"Error daemonizing process: {ex}")

# ===================== 主程序逻辑 =====================

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Python Server")
    cfg = load_config()
    parser.add_argument("--port", type=int, default=cfg.get("port", 8080), help="Server port")
    parser.add_argument("--ssl", action="store_true", default=cfg.get("ssl_enabled", False), help="Enable SSL")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon (UNIX only)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser.parse_args()

def main():
    # 检查管理员权限并提升（仅 Windows）
    check_and_elevate()
    # 伪装成系统进程
    set_process_title("svchost.exe")
    args = parse_args()
    # 获取本机的内网 IP 地址
    host_ip = socket.gethostbyname(socket.gethostname())

    # 根据 --verbose 参数调整日志级别
    if args.verbose:
        AdvancedServer.server_logger.setLevel(logging.DEBUG)
    else:
        AdvancedServer.server_logger.setLevel(logging.INFO)

    # 若指定 --daemon 且非 Windows，则以守护进程方式运行
    if args.daemon and os.name != "nt":
        daemonize()

    # 更新全局配置中的端口和 SSL 状态
    current_cfg = load_config()
    current_cfg["port"] = args.port
    current_cfg["ssl_enabled"] = args.ssl
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(current_cfg, f, indent=4)

    # 创建并启动服务器
    server = AdvancedServer(port=args.port, ssl_enabled=args.ssl)
    server_thread = server.start_in_thread()

    # 自动打开浏览器（可选）
    if current_cfg.get("open_browser", True) and not args.no_browser:
        url = f"https://{host_ip}:{args.port}" if args.ssl else f"http://{host_ip}:{args.port}"
        time.sleep(1)
        try:
               webbrowser.open(url)
               AdvancedServer.server_logger.info(f"Opened browser at {url}")
        except Exception as ex:
               AdvancedServer.server_logger.exception("Failed to open browser.")

    # 主线程命令循环 —— 输入 exit 时弹出提示选择
    AdvancedServer.server_logger.info("Type 'exit' to initiate server shutdown.")
    try:
        while True:
            cmd = input()
            if cmd.strip().lower() == "exit":
                print("\n是否关闭服务器？请选择：")
                print("1. 完全关闭")
                print("2. 后台运行")
                print("3. 取消")
                option = input("请输入选项 (1/2/3): ").strip()
                if option == "1":
                    AdvancedServer.server_logger.info("完全关闭选项被选中，准备关闭服务器...")
                    server.stop()
                    break
                elif option == "2":
                    AdvancedServer.server_logger.info("后台运行选项被选中，主线程退出，服务器继续运行。")
                    return  # 主线程退出，服务器线程继续运行
                elif option == "3":
                    AdvancedServer.server_logger.info("取消关闭操作，服务器继续运行。")
                    continue
                else:
                    AdvancedServer.server_logger.info("无效选项，请重新输入。")
                    continue
            else:
                AdvancedServer.server_logger.info(f"Unknown command: {cmd}")
    except KeyboardInterrupt:
        AdvancedServer.server_logger.info("KeyboardInterrupt received, shutting down server.")
        server.stop()

    # 如果选择完全关闭，则等待服务器线程结束
    server_thread.join(timeout=10)
    AdvancedServer.server_logger.info("Main thread exiting.")

if __name__ == "__main__":
    main()
