# -*- coding: utf-8 -*-
import subprocess
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
from tkinter import messagebox
import re
import time
import os
import sys
import glob
import wave
import shutil
import signal
import csv  # 新增：CSV 支持
import json  # 新增：JSON 支持（持久化缓存）
import queue
from http.server import BaseHTTPRequestHandler, HTTPServer

import struct  # 新增：音频数据解析

# ==================== 基础路径（必须在最前面定义）====================
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ==================== 自部署到同级文件夹 ====================
def ensure_deployed():
    """如果不在目标文件夹内运行，则在 exe 同级目录自动生成文件夹并跳转，并重命名为预警器.exe"""
    if not getattr(sys, 'frozen', False):
        return

    current_exe = sys.executable
    current_dir = os.path.dirname(current_exe)
    exe_name = os.path.basename(current_exe)
    deploy_name = "LBJ列车预警系统解析"
    deploy_dir = os.path.join(current_dir, deploy_name)

    # 已经在目标文件夹内，正常运行
    if os.path.normcase(os.path.basename(current_dir)) == os.path.normcase(deploy_name):
        # 检查是否需要重命名为预警器.exe
        target_name = "预警器.exe"
        target_path = os.path.join(deploy_dir, target_name)
        if os.path.basename(current_exe).lower() != target_name.lower():
            # 复制并重命名
            shutil.copy2(current_exe, target_path)
            # 启动新文件
            subprocess.Popen([target_path], cwd=deploy_dir, creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
            # 删除旧文件
            try_delete_old(current_exe)
            sys.exit(0)
        return

    # 创建目标文件夹（如果不存在）
    os.makedirs(deploy_dir, exist_ok=True)

    # 复制 exe 自身并重命名为 预警器.exe
    deployed_exe = os.path.join(deploy_dir, "预警器.exe")
    shutil.copy2(current_exe, deployed_exe)

    # 复制 bin 文件夹（从 PyInstaller 临时目录取，或当前目录）
    if hasattr(sys, '_MEIPASS'):
        src_bin = os.path.join(sys._MEIPASS, "bin")
    else:
        src_bin = os.path.join(current_dir, "bin")

    dst_bin = os.path.join(deploy_dir, "bin")
    if os.path.exists(src_bin):
        if os.path.exists(dst_bin):
            pass  # bin已存在，不覆盖（避免删除用户自定义配置）
        else:
            shutil.copytree(src_bin, dst_bin)

    # 复制图标文件
    # 创建 ico 文件夹并处理图标
    ico_dir = os.path.join(deploy_dir, "ico")
    os.makedirs(ico_dir, exist_ok=True)
    # 如果根目录有旧图标，移到 ico/ 文件夹
    old_icon = os.path.join(deploy_dir, "lbj_icon_final.ico")
    if os.path.exists(old_icon):
        try:
            shutil.move(old_icon, os.path.join(ico_dir, "lbj_icon_final.ico"))
        except:
            pass
    # 复制图标到 ico/ 文件夹
    icon_src = os.path.join(sys._MEIPASS if hasattr(sys, '_MEIPASS') else current_dir, "lbj_icon_final.ico")
    icon_dst = os.path.join(ico_dir, "lbj_icon_final.ico")
    if os.path.exists(icon_src) and not os.path.exists(icon_dst):
        shutil.copy2(icon_src, icon_dst)

    # 复制清理脚本
    cleaner_src = os.path.join(sys._MEIPASS if hasattr(sys, '_MEIPASS') else current_dir, "cleaner.exe")
    cleaner_dst = os.path.join(deploy_dir, "cleaner.exe")
    if os.path.exists(cleaner_src) and not os.path.exists(cleaner_dst):
        shutil.copy2(cleaner_src, cleaner_dst)

    # 从新位置启动
    subprocess.Popen([deployed_exe], cwd=deploy_dir, creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)

    # 尝试删除旧 exe（用 bat 脚本延迟删除）
    try_delete_old(current_exe)
    sys.exit(0)


def try_delete_old(old_exe_path):
    """尝试删除旧的 exe 文件，失败则忽略"""
    try:
        bat_path = os.path.join(os.path.dirname(old_exe_path), "_del_old.bat")
        with open(bat_path, 'w', encoding='gbk') as f:
            f.write("@echo off\n")
            f.write("timeout /t 1 /nobreak >nul\n")
            f.write(f'del "{old_exe_path}" >nul 2>&1\n')
            f.write('del "%~f0" >nul 2>&1\n')
        subprocess.Popen([bat_path], creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
    except:
        pass

ensure_deployed()
# ==================== 自部署结束 ====================


def get_resource_path(relative_path):
    """获取资源文件的绝对路径，兼容打包和开发环境"""
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = BASE_DIR
    return os.path.join(base_path, relative_path)


running = False
multimon_process = None
sox_process = None        # 主解码 sox
sox_vu_process = None     # 音量条 sox

# 当前列车信息（用于方向判断）
current_train_info = {
    "train": "",
    "direction": "未知",
    "speed": None,
    "km": ""
}

# ==================== CSV 日志配置 ====================
SCRIPT_NAME = "车次统计"
LOG_DIR = os.path.join(BASE_DIR, SCRIPT_NAME)
os.makedirs(LOG_DIR, exist_ok=True)

# ==================== 全局日志配置 ====================
GLOBAL_LOG_PATH = os.path.join(LOG_DIR, "system_log.txt")
GLOBAL_LOG_LAST_DATE = None  # 记录上次写入的日期

def write_global_log(message, level="INFO"):
    """写入全局日志，每月1号自动清空。level: INFO/WARN/ERROR"""
    global GLOBAL_LOG_LAST_DATE
    try:
        from datetime import datetime
        now = datetime.now()
        month_str = now.strftime("%Y%m")
        time_str = now.strftime("%H:%M:%S")
        # 跨月自动清空：月份变化且不是首次运行
        if GLOBAL_LOG_LAST_DATE is not None and GLOBAL_LOG_LAST_DATE != month_str:
            with open(GLOBAL_LOG_PATH, 'w', encoding='utf-8') as f:
                f.write("[%s] [%s] 日志已按月清空 (%s -> %s)\n" % (time_str, level, GLOBAL_LOG_LAST_DATE, month_str))
                f.flush()
            GLOBAL_LOG_LAST_DATE = month_str
            return
        if GLOBAL_LOG_LAST_DATE is None:
            GLOBAL_LOG_LAST_DATE = month_str
        with open(GLOBAL_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write("[%s] [%s] %s\n" % (time_str, level, message))
            f.flush()
    except:
        pass
CACHE_FILE_PATH = os.path.join(LOG_DIR, "pending_cache.json")
CACHE_MAX_AGE = 3 * 24 * 3600  # 3天 = 259200秒


# ==================== 通知推送配置 ====================
# 方案一：企业微信/钉钉/飞书机器人 Webhook（最推荐，填地址即可）
WEBHOOK_URL = None  # 例: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxx"
WEBHOOK_TYPE = "wechat"  # 可选: wechat / dingtalk / feishu

# 方案三：Lagrange.Core / LLOneBot OneBot HTTP API（需另起QQ机器人）
QQ_BOT_API = None   # 例: "http://127.0.0.1:3000"
QQ_TARGET_GROUP = None  # 群号，发群消息
QQ_TARGET_USER = None   # QQ号，发好友消息（二选一）


# ==================== 通知配置 ====================
NOTIFY_CONFIG_PATH = os.path.join(BASE_DIR, "notify_config.json")
_notify_config = {
    "webhook_url": "", "webhook_type": "wechat",
    "qq_bot_api": "", "qq_target_group": "", "qq_target_user": "",
    "access_token": "",
    "whitelist": "DJ,70,73,74,513,55,58,95,00,F,D,C,50,57,",
    "blacklist": "", "km_interval": 1.0,
    "notify_first": True, "notify_loco": True,
    "use_whitelist": False, "use_blacklist": False,
    "qq_msg_format": "array",
    "msg_template": " 车次: {车次} {方向} K{公里标}\n 速度: {速度}km/h \n 车型: {车型}-{车号}\n 线路: {线路}\n 时间: {时间}",
    "km_ranges": "",     # 公里标区间，如: 179.1-179.3, 182.5
    "use_km_range": False,
    "map_api_port": 8765,     # 地图数据接口端口
    "enable_map_api": True,    # 是否启用地图接口
    "map_api_ip": "127.0.0.1",  # 地图接口IP
}
_notify_state = {}
_notify_raw_text = None
_notify_settings_win = None  # 功能设置窗口引用，防止重复打开
_raw_buffer = []  # 原始流环形缓冲区，最多800条，从解码开始记录
_train_api_state = {}      # 供地图读取的列车实时状态
_api_server = None         # 地图接口服务实例
_api_server_port = None    # 当前实例实际监听的端口
_api_start_error = ""       # 最近一次地图接口启动失败原因
_api_start_port_conflict = False  # 最近一次失败是否为端口冲突
_log_queue = queue.Queue()  # 异步日志队列

# ==================== 历史车次存储 ====================
_history_dir = os.path.join(BASE_DIR, "history")
os.makedirs(_history_dir, exist_ok=True)
_history_cache = []   # 内存缓存当天最近100条
_history_date = None  # 当前缓存对应的日期
# ======================================================

import threading

def _log_writer_thread():
    """后台线程：批量写入日志，不阻塞主线程"""
    while True:
        try:
            msg = _log_queue.get(timeout=2)
            if msg is None:
                break
            with open(GLOBAL_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(msg + '\n')
        except queue.Empty:
            pass
        except:
            pass

threading.Thread(target=_log_writer_thread, daemon=True).start()

# ==================== 地图实时数据接口 ====================
_sse_clients = []  # 挂起的 SSE 客户端列表
_map_log_text = None       # 地图设置里的实时日志框引用
_map_log_sent = set()      # 已记录推送的车次集合（去重）

def _map_log(msg):
    """向地图设置日志框写入一行，线程安全，自动滚动到底部"""
    global _map_log_text
    if _map_log_text is None or not _map_log_text.winfo_exists():
        return
    try:
        from datetime import datetime
        ts = datetime.now().strftime('%H:%M:%S')
        _map_log_text.config(state='normal')
        _map_log_text.insert(tk.END, f'[{ts}] {msg}\n')
        _map_log_text.see(tk.END)
        # 限制行数不超过200行，防止膨胀
        line_count = int(_map_log_text.index(tk.END).split('.')[0])
        if line_count > 200:
            _map_log_text.delete('1.0', f'{line_count-200}.0')
        _map_log_text.config(state='disabled')
    except:
        pass

class _TrainAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 记录API请求日志
        try:
            client_ip = self.client_address[0] if self.client_address else 'unknown'
            _map_log(f'GET {self.path} from {client_ip}')
        except:
            pass

        if self.path == '/api/trains':
            accept = self.headers.get('Accept', '')
            if 'text/event-stream' in accept:
                # SSE 模式：JS EventSource 用这个
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                _sse_clients.append(self)

                # 推送线路数据给新连接的客户端
                try:
                    line_data = {}
                    maplines_dir = os.path.join(BASE_DIR, "maplines")
                    if os.path.exists(maplines_dir):
                        for fname in os.listdir(maplines_dir):
                            if fname.endswith(".json"):
                                fpath = os.path.join(maplines_dir, fname)
                                try:
                                    with open(fpath, 'r', encoding='utf-8') as f:
                                        line_data[fname[:-5]] = json.load(f)
                                except:
                                    pass
                    if line_data:
                        msg = "event: lines\ndata: " + json.dumps(line_data, ensure_ascii=False) + "\n\n"
                        self.wfile.write(msg.encode('utf-8'))
                        self.wfile.flush()
                except:
                    pass

                try:
                    while True:
                        time.sleep(1)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    if self in _sse_clients:
                        _sse_clients.remove(self)
            else:
                # 浏览器直接访问：返回一次性 JSON（兼容测试）
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(_train_api_state, ensure_ascii=False).encode('utf-8'))
        elif self.path.startswith('/api/history'):
            # 解析参数
            query = {}
            if '?' in self.path:
                qs = self.path.split('?', 1)[1]
                for part in qs.split('&'):
                    if '=' in part:
                        k, v = part.split('=', 1)
                        query[k] = v
            date_str = query.get('date')
            line_filter = query.get('line', '')
            train_filter = query.get('train', '')
            try:
                limit = int(query.get('limit', '100'))
            except:
                limit = 100
            if limit > 500:
                limit = 500
            # 确保内存缓存有数据
            global _history_cache, _history_date
            from datetime import datetime
            today = datetime.now().strftime('%Y-%m-%d')
            target_date = date_str if date_str else today
            if _history_date != target_date:
                load_history_cache(target_date)
            # 筛选并返回（倒序，最新在前）
            result = []
            for item in reversed(_history_cache):
                if line_filter and item.get('line') != line_filter:
                    continue
                if train_filter and item.get('train_no') != train_filter:
                    continue
                result.append(item)
                if len(result) >= limit:
                    break
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode('utf-8'))
            return

        elif self.path == '/api/refresh_lines':
            # JS主动请求：刷新线路数据
            line_data = {}
            maplines_dir = os.path.join(BASE_DIR, "maplines")
            if os.path.exists(maplines_dir):
                for fname in os.listdir(maplines_dir):
                    if fname.endswith(".json"):
                        fpath = os.path.join(maplines_dir, fname)
                        try:
                            with open(fpath, 'r', encoding='utf-8') as f:
                                line_data[fname[:-5]] = json.load(f)
                        except:
                            pass
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(line_data, ensure_ascii=False).encode('utf-8'))
            return

        elif self.path == '/' or self.path == '/map.html':
            # 静态文件服务：返回 map.html
            map_path = os.path.join(BASE_DIR, "map.html")
            if os.path.exists(map_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                with open(map_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(f"<html><body><h2>map.html 未找到</h2><p>期望路径: {map_path}</p></body></html>".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, format, *args):
        pass  # 静默，不刷屏

def _start_train_api(port=8765):
    """检查端口并启动地图接口；冲突时安全失败，绝不终止占用者。"""
    global _api_server, _api_server_port, _api_start_error, _api_start_port_conflict
    _api_start_error = ""
    _api_start_port_conflict = False
    srv = None
    try:
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError(f"端口号无效: {port}")

        if _api_server is not None:
            if _api_server_port == port:
                return True
            _api_start_error = (
                f"当前程序的地图接口已在端口 {_api_server_port} 运行，无法切换到端口 {port}"
            )
            write_global_log(_api_start_error, "ERROR")
            return False

        # 先检查是否已经有监听者。真实 bind 仍会再检查一次，处理检查与绑定之间的竞争。
        import socket
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.35)
        try:
            probe_result = probe.connect_ex(("127.0.0.1", port))
        finally:
            probe.close()

        if probe_result == 0:
            _api_start_port_conflict = True
            _api_start_error = f"地图接口端口冲突：127.0.0.1:{port} 已有程序在监听。"
            write_global_log(_api_start_error, "ERROR")
            return False

        write_global_log(f"检查地图接口端口：127.0.0.1:{port}，未发现现有监听者，尝试启动。")

        from socketserver import ThreadingMixIn

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            # 不设置 SO_REUSEADDR，避免多个实例复用同一监听端口。
            allow_reuse_address = False
            pass

        # 以实际创建服务器时的 bind 结果为准；若有程序抢先占用，会在此处失败。
        srv = ThreadedHTTPServer(("127.0.0.1", port), _TrainAPIHandler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        try:
            thread.start()
        except Exception:
            srv.server_close()
            raise

        _api_server = srv
        _api_server_port = port
        write_global_log(
            f"地图SSE接口已启动: http://127.0.0.1:{port}/api/trains "
            f"(JS连接: http://{_notify_config.get('map_api_ip', '127.0.0.1')}:{port}/api/trains)"
        )
        return True
    except OSError as e:
        if srv is not None:
            try:
                srv.server_close()
            except Exception:
                pass

        error_text = str(e)
        winerror = getattr(e, "winerror", None)
        error_no = getattr(e, "errno", None)
        is_conflict = (
            winerror == 10048
            or error_no in (98, 10048)
            or "address already in use" in error_text.lower()
            or "10048" in error_text
            or "通常每个套接字地址" in error_text
            or "通常只允许每个套接字地址" in error_text
        )
        _api_start_port_conflict = is_conflict
        if is_conflict:
            _api_start_error = f"地图接口端口冲突：127.0.0.1:{port} 已被占用。详情：{e}"
        else:
            _api_start_error = f"地图接口启动失败（端口 {port}）：{e}"
        write_global_log(_api_start_error, "ERROR")
        return False
    except Exception as e:
        if srv is not None:
            try:
                srv.server_close()
            except Exception:
                pass
        _api_start_error = f"地图接口启动失败（端口 {port if 'port' in locals() else '未知'}）：{type(e).__name__}: {e}"
        write_global_log(_api_start_error, "ERROR")
        return False

def _stop_train_api():
    global _api_server, _api_server_port
    if _api_server:
        srv = _api_server
        _api_server = None  # 先清引用，防止重复调用
        _api_server_port = None
        try:
            # 关闭所有SSE连接，让serve_forever有机会退出
            global _sse_clients
            dead = list(_sse_clients)
            _sse_clients = []
            for client in dead:
                try:
                    client.connection.close()
                except:
                    pass
            # shutdown阻塞等serve_forever退出
            srv.shutdown()
            srv.server_close()
        except Exception as e:
            write_global_log(f"地图接口关闭异常: {e}", "WARN")

def _push_map_data(train_no, train_type, line, direction, km, speed, lon, lat, loco_type, loco_num):
    """SSE 主动推送地图数据，有客户端连接才发"""
    data = {
        "train_no": train_no,
        "type": train_type if train_type and train_type != "未知" else "",
        "line": line if line and line not in ("****", "***") else "",
        "direction": direction,
        "km": float(km) if km else None,
        "speed": speed if speed is not None else 0,
        "lon": lon if lon else None,
        "lat": lat if lat else None,
        "loco_type": loco_type if loco_type and loco_type not in ("****", "***") else "",
        "loco_num": loco_num if loco_num and loco_num not in ("****", "***") else "",
        "last_update": time.time(),
    }
    # 日志：每个车次只记录一次推送
    global _map_log_sent
    if train_no and train_no not in _map_log_sent:
        _map_log_sent.add(train_no)
        _map_log(f'推送 {train_no} 到 {len(_sse_clients)} 个客户端')
        # 集合超过50个时清空，避免无限增长
        if len(_map_log_sent) > 50:
            _map_log_sent.clear()

    if not _notify_config.get("enable_map_api", True):
        return
    dead = []
    for client in list(_sse_clients):  # 复制列表避免遍历时并发修改
        try:
            msg = "data: " + json.dumps(data, ensure_ascii=False) + chr(10) + chr(10)
            client.wfile.write(msg.encode('utf-8'))
            client.wfile.flush()
        except:
            dead.append(client)
    for d in dead:
        if d in _sse_clients:
            _sse_clients.remove(d)

# ==================== 通知配置加载 ====================

def get_history_path(date_str=None):
    """获取指定日期的历史文件路径"""
    from datetime import datetime
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(_history_dir, f"{date_str}.jsonl")

def append_history(record):
    """追加单条历史记录到文件和内存缓存"""
    global _history_cache, _history_date
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%d")
    # 跨天清空缓存
    if _history_date != today:
        _history_cache = []
        _history_date = today
    # 构造历史记录
    raw_lonlat = record.get("经度 纬度", "")
    lonlat_parts = raw_lonlat.split() if raw_lonlat else []
    hist = {
        "train_no": record.get("车次", ""),
        "type": record.get("列车类型", ""),
        "line": record.get("线路", ""),
        "direction": record.get("方向", ""),
        "km": float(record.get("公里标", 0)) if record.get("公里标") else None,
        "speed": int(record.get("速度", 0)) if record.get("速度") else None,
        "lon": lonlat_parts[0] if len(lonlat_parts) >= 1 else None,
        "lat": lonlat_parts[1] if len(lonlat_parts) >= 2 else None,
        "loco_type": record.get("车型", ""),
        "loco_num": record.get("车号", ""),
        "time": record.get("时间", "")[11:19] if record.get("时间") and len(record.get("时间", "")) >= 19 else record.get("时间", ""),
    }
    _history_cache.append(hist)
    if len(_history_cache) > 100:
        _history_cache.pop(0)
    # 追加到文件
    try:
        path = get_history_path(today)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(hist, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        write_global_log(f"历史记录写入失败: {e}", "WARN")

def load_history_cache(date_str=None):
    """从文件加载指定日期的历史记录到内存缓存"""
    global _history_cache, _history_date
    from datetime import datetime
    if date_str is None:
        date_str = datetime.now().strftime("%Y-%m-%d")
    _history_date = date_str
    _history_cache = []
    path = get_history_path(date_str)
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    _history_cache.append(json.loads(line))
                except:
                    pass
        # 只保留最近100条
        if len(_history_cache) > 100:
            _history_cache = _history_cache[-100:]
    except Exception as e:
        write_global_log(f"历史记录加载失败: {e}", "WARN")

def cleanup_history_files():
    """清理历史文件，只保留当天"""
    try:
        from datetime import datetime
        today = datetime.now().strftime("%Y-%m-%d")
        for fname in os.listdir(_history_dir):
            if fname.endswith(".jsonl"):
                fdate = fname.replace(".jsonl", "")
                if fdate != today:
                    try:
                        os.remove(os.path.join(_history_dir, fname))
                    except:
                        pass
    except:
        pass
def _load_notify_config():
    global _notify_config
    try:
        if os.path.exists(NOTIFY_CONFIG_PATH):
            with open(NOTIFY_CONFIG_PATH, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                for k, v in loaded.items():
                    if k in _notify_config: _notify_config[k] = v
            write_global_log("通知配置已加载")
    except Exception as e:
        write_global_log(f"通知配置加载失败: {e}", "WARN")

def _save_notify_config():
    try:
        with open(NOTIFY_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(_notify_config, f, ensure_ascii=False, indent=2)
            f.flush(); os.fsync(f.fileno())
    except Exception as e:
        write_global_log(f"通知配置保存失败: {e}", "ERROR")

def _parse_ranges(text):
    """解析区间文本，返回 (min, max) 元组列表。支持 575-579, 182.5 格式"""
    ranges = []
    if not text: return ranges
    for part in text.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ranges.append((float(a.strip()), float(b.strip())))
            except: pass
        else:
            try:
                v = float(part)
                ranges.append((v, v))
            except: pass
    return ranges

def _in_range(value, ranges):
    """检查数值是否在任一区间内"""
    if not ranges: return True
    if value is None: return False
    try:
        v = float(value)
        return any(lo <= v <= hi for lo, hi in ranges)
    except: return False

def _parse_filter_item(item):
    """解析过滤项，返回 (类型, 值)。类型: 'train'/'loco_type'/'loco_num'"""
    item = item.strip()
    if not item: return None, None
    if item.startswith('车次:'):
        return 'train', item[3:].strip()
    elif item.startswith('车型:'):
        return 'loco_type', item[3:].strip()
    elif item.startswith('车号:'):
        return 'loco_num', item[3:].strip()
    else:
        return 'train', item  # 默认按车次匹配

def _match_filter(train_no, loco_type, loco_num, filter_text):
    """通用匹配：支持车次/车型/车号前缀，任一命中返回True"""
    if not filter_text: return False
    for item in filter_text.split(","):
        ftype, fval = _parse_filter_item(item)
        if not fval: continue
        if ftype == 'train':
            # 区间匹配: 575-579
            if "-" in fval and fval.replace("-", "").replace(".", "").isdigit():
                try:
                    train_num = float(re.sub(r'[^0-9.]', '', train_no) or "0")
                    ranges = _parse_ranges(fval)
                    if ranges and _in_range(train_num, ranges):
                        return True
                except: pass
            else:
                # 前缀匹配
                if train_no.upper().startswith(fval.upper()):
                    return True
        elif ftype == 'loco_type':
            if loco_type and loco_type != "****" and loco_type != "***" and loco_type.upper().startswith(fval.upper()):
                return True
        elif ftype == 'loco_num':
            if loco_num and loco_num != "****" and loco_num != "***" and loco_num == fval:
                return True
    return False

def _should_notify(train_no, lt, ln, km_str):
    global _notify_config, _notify_state
    if not train_no: return False, "无车次"
    # 优先级1: 黑名单 + 白名单（可同时使用）
    use_bl = _notify_config.get("use_blacklist", False)
    use_wl = _notify_config.get("use_whitelist", False)
    bl = _notify_config.get("blacklist", "").strip()
    wl = _notify_config.get("whitelist", "").strip()
    if use_bl and bl:
        if _match_filter(train_no, lt, ln, bl):
            return False, "黑名单命中"
    if use_wl and wl:
        if not _match_filter(train_no, lt, ln, wl):
            return False, "不在白名单"
    # 优先级2: 首次通知 / 车型补充通知
    kmf = None
    if km_str:
        try: kmf = float(km_str)
        except: pass
    st = _notify_state.get(train_no, {"first_sent": False, "loco_sent": False, "last_km": None})
    if not st.get("first_sent"):
        st["first_sent"] = True; st["last_km"] = kmf; _notify_state[train_no] = st
        nf = _notify_config.get("notify_first", True)
        return (nf, "首次通知") if nf else (False, "首次通知已关闭")
    if lt and lt != "****" and lt != "" and not st.get("loco_sent"):
        st["loco_sent"] = True; _notify_state[train_no] = st
        nl = _notify_config.get("notify_loco", True)
        return (nl, "车型补充通知") if nl else (False, "车型补充通知已关闭")
    # 优先级3: 公里标区间过滤（最后检查）
    use_kmr = _notify_config.get("use_km_range", False)
    kmr_text = _notify_config.get("km_ranges", "").strip()
    if use_kmr and kmr_text:
        km_ranges = _parse_ranges(kmr_text)
        if km_ranges and not _in_range(km_str, km_ranges):
            return False, "不在公里标区间"
    # 优先级4: 公里标变化
    kmi = 1.0
    try: kmi = float(_notify_config.get("km_interval", 1.0))
    except: pass
    if kmf is not None and st.get("last_km") is not None and abs(kmf - st["last_km"]) >= kmi:
        st["last_km"] = kmf; _notify_state[train_no] = st
        return True, "公里标变化"
    # 兜底：无限制模式（黑白名单/公里标区间都关闭时，每次来车都发位置更新）
    _notify_state[train_no] = st
    return True, "位置更新"

_load_notify_config()

import urllib.request
import ssl

def _send_qq_notification(api, payload, token, ssl_ctx):
    """内部函数：发送QQ通知，超时2秒，失败才写日志"""
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f"Bearer {token}"
    req = urllib.request.Request(api, data=data, headers=headers, method='POST')
    resp = urllib.request.urlopen(req, timeout=5, context=ssl_ctx)
    resp_body = resp.read().decode('utf-8', errors='replace')[:500]
    try:
        resp_json = json.loads(resp_body)
        if resp_json.get("retcode", 0) != 0:
            write_global_log(f"QQ通知返回错误: retcode={resp_json.get('retcode')} msg={resp_json.get('wording','')}", "WARN")
            return False, resp_json.get('wording','')
        return True, ""
    except:
        return True, ""

def _send_notification_thread(message):
    """后台线程：发送通知，失败才写日志"""
    try:
        wurl = _notify_config.get("webhook_url") or WEBHOOK_URL
        qapi = _notify_config.get("qq_bot_api") or QQ_BOT_API
        qgrp = _notify_config.get("qq_target_group") or QQ_TARGET_GROUP
        qusr = _notify_config.get("qq_target_user") or QQ_TARGET_USER
        token = _notify_config.get("access_token", "")
        # 本地https自签名证书处理
        ssl_ctx = None
        if qapi and ("127.0.0.1" in qapi or "localhost" in qapi):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        if wurl:
            wt = _notify_config.get("webhook_type", "wechat")
            if wt == "wechat": payload = {"msgtype": "text", "text": {"content": message}}
            elif wt == "dingtalk": payload = {"msgtype": "text", "text": {"content": message}}
            elif wt == "feishu": payload = {"msg_type": "text", "content": {"text": message}}
            else: payload = {"msgtype": "text", "text": {"content": message}}
            data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            req = urllib.request.Request(wurl, data=data, headers={'Content-Type': 'application/json'}, method='POST')
            urllib.request.urlopen(req, timeout=5, context=ssl_ctx)
            return
        if qapi and (qgrp or qusr):
            fmt = _notify_config.get("qq_msg_format", "array")
            if qgrp:
                api = f"{qapi.rstrip('/')}/send_group_msg"
                try: gid = int(qgrp)
                except: gid = str(qgrp)
                if fmt == "array":
                    payload = {"group_id": gid, "message": [{"type": "text", "data": {"text": message}}]}
                else:
                    payload = {"group_id": gid, "message": message}
            else:
                api = f"{qapi.rstrip('/')}/send_private_msg"
                try: uid = int(qusr)
                except: uid = str(qusr)
                if fmt == "array":
                    payload = {"user_id": uid, "message": [{"type": "text", "data": {"text": message}}]}
                else:
                    payload = {"user_id": uid, "message": message}
            ok, err = _send_qq_notification(api, payload, token, ssl_ctx)
            if not ok and "message" in str(err).lower():
                if qgrp:
                    payload = {"group_id": gid, "message": message}
                else:
                    payload = {"user_id": uid, "message": message}
                ok2, err2 = _send_qq_notification(api, payload, token, ssl_ctx)
                if not ok2:
                    write_global_log(f"通知发送失败: {err2}", "WARN")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='replace')[:500] if e.fp else ""
        write_global_log(f"通知发送失败[HTTPError {e.code}]: {e.reason} body={err_body}", "WARN")
    except Exception as e:
        write_global_log(f"通知发送失败[{type(e).__name__}]: {e}", "WARN")

def send_notification(message):
    """发送通知到Webhook或QQ机器人，后台线程执行不阻塞主程序"""
    if not message: return
    threading.Thread(target=_send_notification_thread, args=(message,), daemon=True).start()


def _load_pending_cache():
    """从文件加载持久化缓存，丢弃超过3天的记录"""
    global _csv_pending_records
    try:
        if os.path.exists(CACHE_FILE_PATH):
            with open(CACHE_FILE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            now = time.time()
            valid_records = []
            for item in data.get("records", []):
                if now - item.get("timestamp", 0) < CACHE_MAX_AGE:
                    valid_records.append(item["record"])
            _csv_pending_records = valid_records
    except:
        _csv_pending_records = []
_SAVE_LOGGED_HOUR = set()  # 当前小时内已记录保存成功的车次，去重日志
_LOCO_TYPE_LOADED_TODAY = None  # 车型库最后加载日期，同一天不重复日志

def _save_pending_cache():
    """将当前缓存保存到文件"""
    try:
        data = {
            "records": [
                {"record": r, "timestamp": time.time()}
                for r in _csv_pending_records
            ]
        }
        with open(CACHE_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
    except:
        pass

def cleanup_old_logs():
    pass

def get_log_file_path():
    """获取当天 CSV 路径，每次都重新计算日期，绝不缓存。"""
    from datetime import datetime
    today = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"{today}.csv")
CSV_HEADER = ["时间", "车次", "方向", "速度", "车型", "车号", "线路", "公里标", "列车类型", "经度 纬度"]

def init_csv():
    """如果 CSV 不存在，写入 UTF-8-BOM 表头。"""
    log_path = get_log_file_path()
    if not os.path.exists(log_path):
        try:
            with open(log_path, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            write_global_log(f"CSV表头写入失败: {e}", "ERROR")
def save_to_csv(record):
    """保存单条解析记录到 CSV。主文件被占用时，自动写入备用文件。"""
    global _csv_pending_records, _SAVE_LOGGED_HOUR
    def _wr(w, r):
        w.writerow([str(r.get(k, "")).strip() for k in CSV_HEADER])
    def _ws(r, p):
        try:
            init_csv()
            with open(p, 'a', newline='', encoding='utf-8-sig') as f:
                _wr(csv.writer(f), r); f.flush(); os.fsync(f.fileno())
            return True
        except PermissionError: return "CSV文件被其他程序占用"
        except OSError as e: return "磁盘空间不足" if "space" in str(e).lower() else f"磁盘错误: {e}"
        except Exception as e: return f"写入异常: {e}"
    def _wb(r, d):
        bp = os.path.join(LOG_DIR, f"{d}_备用.csv")
        try:
            if not os.path.exists(bp):
                with open(bp, 'w', newline='', encoding='utf-8-sig') as f:
                    csv.writer(f).writerow(CSV_HEADER); f.flush(); os.fsync(f.fileno())
            with open(bp, 'a', newline='', encoding='utf-8-sig') as f:
                _wr(csv.writer(f), r); f.flush(); os.fsync(f.fileno())
            return True
        except: return False
    def _gd(r):
        t = r.get("时间", "")
        return t[:10] if t and len(t) >= 10 else __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    tn = record.get('车次', 'unknown'); td = _gd(record); th = __import__('datetime').datetime.now().strftime("%H")
    tp = os.path.join(LOG_DIR, f"{td}.csv")
    res = _ws(record, tp)
    if res is True:
        lk = f"{td}:{th}:{tn}"
        if lk not in _SAVE_LOGGED_HOUR:
            _SAVE_LOGGED_HOUR.add(lk)
            write_global_log(f"车次保存成功: {tn} -> {os.path.basename(tp)}")
    else:
        if not _wb(record, td):
            _csv_pending_records.append(record); _save_pending_cache()
        write_global_log(f"车次保存失败[{res}]: {tn}, 已缓存", "ERROR")
        return
    if _csv_pending_records:
        ft, fr = 0, []
        from collections import defaultdict
        bd = defaultdict(list)
        for p in _csv_pending_records: bd[_gd(p)].append(p)
        for ds, rs in bd.items():
            dp = os.path.join(LOG_DIR, f"{ds}.csv")
            for rc in rs:
                r2 = _ws(rc, dp)
                if r2 is True: ft += 1
                elif not _wb(rc, ds): fr.append(rc)
        _csv_pending_records = fr; _save_pending_cache()
        if ft > 0: write_global_log(f"缓存刷新成功: {ft}条, 剩余失败={len(fr)}")

def get_audio_devices():
    """获取可用音频输入设备列表"""
    devices = ["CABLE Output (VB-Audio Virtual Cable)"]
    return devices
DEFAULT_TYPES_TXT = """
# ==================== 铁路机车车型库 ====================
# 格式: 注册号=车型名称
# 例: 237=HXD1C
# 以 # 开头的行为注释，会被忽略
# 修改后点击开始/停止/查找按钮重新加载，或重启程序
# ======================================================
100=解放    101=DF    102=DF2    103=DF3    104=DF4
105=DF4K    106=DF4C    107=DF4D    108=DF5（口）    109=DF6
110=DF7    111=DF8    112=DF9    113=DF10    114=DFH1
115=DFH2    116=DFH3    117=DFH5    118=BJ    119=BJ（口）
120=ND2    121=ND3    122=ND4    123=ND5    124=NY5
125=NY6    126=NY7    127=QY    128=DFH21    129=DF7B
130=DF5（口）    131=DF5S    132=DF7S    133=GK1    134=GK1F
135=DF4E    136=DF7D    137=GK1A    138=DF11    139=DF11A
140=DF10F    141=DF4D    142=DF8B    143=DF12    144=DF7E
145=NYJ2    146=NZJ1    147=NZJ2    148=DF4DJ    149=NDJ1
150=NDJ2    151=NJ2    152=DF7G    153=NDJ3    156=DF11Z
157=FXN3D    158=DF11G    160=HXN3    161=HXN5    162=HXN3B
163=HXN5B    167=FXN3B    170=FXN5C    171=FXN3-J    201=8G
202=8K    203=6G    204=6K    205=SS1    206=SS3
207=SS4    208=SS5    209=SS6    210=SS3B    211=SS7
212=SS8    213=SS7B    214=SS7C    215=SS6B    216=SS9
217=SS7D    218=DJ    219=DJ1    220=DJ2    221=DJF1
222=DJJ1    223=DJF2    224=SS7E    225=SS4B    226=SS3C
227=SSJ3    228=天梭    229=HX    230=KTT    231=HXD1
232=HXD2    233=HXD3    234=HXD1B    235=HXD2B    236=HXD3B
237=HXD1C    238=HXD2C    239=HXD3C    240=HXD1D    241=HXD2D
242=HXD3D    243=FXD1B    244=FXD2B    245=FXD1    246=FXD3
247=FXD1-J    248=FXD3-J    249=KZ25TA    251=KZ25TB    252=HXD1D-J
253=FXD1H    257=FXD1D-J    299=雪域神州    300=CRH1    301=CRH1A
302=CRH2A    304=CRH380AL    305=CRH5A    306=CRH3C    307=CRH380BG
308=CRH380A    309=CRH380D    310=CRH380B    311=CRH380BL    312=CR300AF
313=CRH2B    314=CRH2C    315=CRH2E    319=CRH1B    329=CJ1
330=CJ2    331=CJ3    332=CJ4    333=CJ5    334=CJ6
361=JW-4G接触网作业车    400=GC-270重型轨道车    403=GX-160综合巡检车    410=DWL-48k捣固稳定车    411=DCL-32k型连续式捣固车
    413=SPZ-350型双向配砟整形车    415=GMC-96B型钢轨打磨车
415=GMC-96B型钢轨打磨车    422=GTC-80J钢轨探伤车    500=建设    550=蓝箭控车    600=KD7
801=NS1600    810=DF21

"""

LOCOMOTIVE_TYPE_MAP = {}

def load_locomotive_types():
    """加载外置车型库。运行时只认外置车型库.txt，没有则自动生成默认的。
    编码兼容：先尝试 UTF-8，失败自动 fallback 到 GBK（兼容 Windows 记事本默认 ANSI）。
    同一天只记录一次加载成功日志。"""
    global LOCOMOTIVE_TYPE_MAP, _LOCO_TYPE_LOADED_TODAY
    map_path = os.path.join(BASE_DIR, "车型库.txt")
    from datetime import datetime
    today_str = datetime.now().strftime("%Y%m%d")
    loaded = False
    if os.path.exists(map_path):
        # 先尝试 UTF-8
        try:
            result = {}
            with open(map_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    for segment in line.split():
                        if '=' in segment:
                            key, val = segment.split('=', 1)
                            result[key.strip()] = val.strip()
            if result:
                LOCOMOTIVE_TYPE_MAP = result
                loaded = True
            else:
                write_global_log(f"车型库文件为空或格式错误: {map_path}", "WARN")
        except Exception as e:
            write_global_log(f"车型库加载失败(UTF-8): {e}", "WARN")
        # fallback GBK
        if not loaded:
            try:
                result = {}
                with open(map_path, 'r', encoding='gbk') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        for segment in line.split():
                            if '=' in segment:
                                key, val = segment.split('=', 1)
                                result[key.strip()] = val.strip()
                if result:
                    LOCOMOTIVE_TYPE_MAP = result
                    loaded = True
                else:
                    write_global_log(f"车型库文件为空或格式错误(GBK): {map_path}", "WARN")
            except Exception as e:
                write_global_log(f"车型库加载失败(GBK): {e}", "ERROR")
    # 没有外置文件或加载失败：用默认文本生成一份
    if not loaded:
        try:
            with open(map_path, 'w', encoding='utf-8') as f:
                f.write(DEFAULT_TYPES_TXT)
        except Exception as e:
            write_global_log(f"车型库生成失败: {e}", "ERROR")
        result = {}
        for line in DEFAULT_TYPES_TXT.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            for segment in line.split():
                if '=' in segment:
                    key, val = segment.split('=', 1)
                    result[key.strip()] = val.strip()
        LOCOMOTIVE_TYPE_MAP = result
    # 同一天只记录一次加载成功日志
    if loaded:
        if _LOCO_TYPE_LOADED_TODAY != today_str:
            _LOCO_TYPE_LOADED_TODAY = today_str
            write_global_log(f"车型库加载成功: {map_path}, 共{len(LOCOMOTIVE_TYPE_MAP)}条")
load_locomotive_types()


# ==================== BCD 映射 ====================
NIBBLE_MAP = {
    '0': 0x0, '1': 0x1, '2': 0x2, '3': 0x3, '4': 0x4,
    '5': 0x5, '6': 0x6, '7': 0x7, '8': 0x8, '9': 0x9,
    '.': 0xA, 'U': 0xB, ' ': 0xC, '-': 0xD, ')': 0xE, '[': 0xF,
    ']': 0xE, 'E': 0xE, 'C': 0xC, 'A': 0xA, 'D': 0xD,
}

ANSI_RE = re.compile(r'\x1B\[[0-9;]*[mK]')


def filter_ansi(s):
    return ANSI_RE.sub('', s)


def parse_nibbles(numeric_str):
    clean_str = filter_ansi(numeric_str)
    return [NIBBLE_MAP.get(c, int(c) if c.isdigit() else None) for c in clean_str
            if c in NIBBLE_MAP or c.isdigit()]


# ==================== 车次类型识别 ====================
SPECIAL_TYPES = {
    "客运单机", "货车单机", "小运转单机", "补机",
    "试运行列车", "轨道车/小型工程车", "路用列车", "救援列车"
}

def identify_train_type(train_no):
    """根据车次号自动识别列车类型（客运/非客运）"""
    if not train_no:
        return "未知"

    # ===== 新增：处理特殊前缀 =====
    # F = 折返列车（如 FK1184、FT1234、FG21）
    # 0 = 回送列车（如 0K1184、0G21）
    upper_no = train_no.upper()
    if upper_no.startswith('F'):
        base_type = identify_train_type(train_no[1:])
        return base_type + "(折返)" if base_type != "未知" else "折返列车"
    if upper_no.startswith('0'):
        base_type = identify_train_type(train_no[1:])
        return base_type + "(回送)" if base_type != "未知" else "回送列车"
    # ===== 新增结束 =====

    # ===== 新增：DJ 动车组检测/确认列车 =====
    if upper_no.startswith('DJ'):
        num_part = train_no[2:]
        try:
            num = int(num_part)
            if 11 <= num <= 1998: return "动车组检测列车"
            if 5001 <= num <= 8998: return "动车组确认列车"
        except:
            pass
        return "动车组检测/确认列车"
    # ===== 新增结束 =====

    prefix = ''
    num_part = train_no
    for p in ['C', 'Z', 'T', 'K', 'L', 'Y', 'X', 'D', 'G', 'N', 'S']:
        if train_no.upper().startswith(p):
            prefix = p.upper()
            num_part = train_no[len(p):]
            break

    try:
        num = int(num_part)
        num_len = len(num_part)
    except:
        return "未知"

    if prefix == 'C': return "城际动车组"
    if prefix == 'Z': return "直达特快"
    if prefix == 'T': return "特快旅客列车"
    if prefix == 'K': return "快速旅客列车"
    if prefix == 'L': return "临时旅客列车"
    if prefix == 'Y': return "旅游列车"
    if prefix == 'D': return "动车组"
    if prefix == 'G': return "高速动车组"
    if prefix == 'N': return "管内快速"
    if prefix == 'S': return "市郊列车"

    if prefix == 'X':
        if 1 <= num <= 198: return "行邮特快专列"
        if 201 <= num <= 398: return "行包快运专列"
        if 401 <= num <= 2990: return "普通行包列车"
        if 3001 <= num <= 3998: return "特需货物列车"
        if 8001 <= num <= 8998: return "中欧中亚班列(120km/h)"
        if 9001 <= num <= 9498: return "中欧中亚班列(80km/h)"
        if 9501 <= num <= 9998: return "铁水联运班列"
        return "行包/货运专列"

    if num_len <= 5:
        if 1 <= num <= 100: return "动车组有火回送"
        if 101 <= num <= 198: return "动车组无火跨局回送"
        if 201 <= num <= 298: return "动车组无火管内回送"
        if 301 <= num <= 398: return "跨局回送客车"
        if 401 <= num <= 498: return "管内回送客车"
        if 1001 <= num <= 3998: return "普通快车"
        if 4001 <= num <= 5998: return "普通快车(管内)"
        if 6001 <= num <= 6198: return "普通慢车"
        if 6201 <= num <= 7598: return "普通慢车(管内)"
        if 7601 <= num <= 8998: return "通勤列车"
        if 10001 <= num <= 19998: return "货运列车(技术直达)"
        if 20001 <= num <= 29998: return "货运列车(直通)"
        if 30001 <= num <= 39998: return "货运列车(区段)"
        if 40001 <= num <= 44998: return "摘挂列车"
        if 45001 <= num <= 49998: return "小运转列车"
        if 50001 <= num <= 50998: return "客运单机"
        if 51001 <= num <= 51998: return "货车单机"
        if 52001 <= num <= 52998: return "小运转单机"
        if 53001 <= num <= 54998: return "补机"
        if 55001 <= num <= 55998: return "试运行列车"
        if 56001 <= num <= 56998: return "轨道车/小型工程车"
        if 57001 <= num <= 57998: return "路用列车"
        if 58101 <= num <= 58998: return "救援列车"
        if 60001 <= num <= 69998: return "工厂自备车"
        if 70001 <= num <= 70998: return "超限货运列车"
        if 71001 <= num <= 72998: return "万吨货物列车"
        if 73001 <= num <= 74998: return "冷藏列车"
        if 75001 <= num <= 75998: return "货运列车(集装箱)"
        if 77001 <= num <= 77998: return "货运列车(石油直达)"
        if 78001 <= num <= 78998: return "货运列车(煤炭直达)"
        if 79001 <= num <= 79998: return "快运货物列车"
        if 80001 <= num <= 81748: return "货运列车(直达、五定)"
        if 81749 <= num <= 81998: return "货运列车(快运直达)"
        if 82001 <= num <= 84998: return "货运列车(煤炭直达)"
        if 85001 <= num <= 85998: return "货运列车(石油直达)"
        if 86001 <= num <= 86998: return "货运列车(始发直达)"
        if 87001 <= num <= 87998: return "货运列车(空车直达)"
        if 88001 <= num <= 88998: return "货运列车(汽运)"
        if 90001 <= num <= 91998: return "特殊超限"
        if 93001 <= num <= 94998: return "特殊超限"
        if 95001 <= num <= 97998: return "抢险救灾列车"
        if 98001 <= num <= 99998: return "特种列车"

    return "未知"


def decode_1234002(numeric_str):
    try:
        nibbles = parse_nibbles(numeric_str)
        nibble_count = len(nibbles)

        # 车号部分(nibble 4-11)必须是纯BCD数字(0-9)，含[ ]U.等非数字说明误码，直接丢弃
        if nibble_count >= 12:
            if any(n > 9 for n in nibbles[4:12]):
                return "", "****", "****", "未知", None, None, None, 0

        prefix = ""
        loco_type = "****"
        loco_num = "****"
        end_position = "未知"
        route_name = None
        lon_str = None
        lat_str = None

        # 1. 字头解析 (ASCII, nibble 0-3)
        if nibble_count >= 4:
            try:
                c1 = chr((nibbles[0] << 4) | nibbles[1])
                c2 = chr((nibbles[2] << 4) | nibbles[3])
                prefix = "".join(c for c in (c1 + c2) if c.isalnum()).upper()
            except:
                pass

        # 2. 车号解析 (BCD, nibble 4-11, 8位数字: 3位注册号+5位车号)
        if nibble_count >= 12:
            loco_num_full = ''.join(str(n) for n in nibbles[4:12])
            # 注册号统一取前3位
            loco_prefix = loco_num_full[:3]
            loco_type = LOCOMOTIVE_TYPE_MAP.get(loco_prefix)
            if loco_type:
                if loco_type.startswith("CRH"):
                    # CRH 车号特殊取法: 注册号后取4位
                    loco_num = loco_num_full[3:7]
                else:
                    # 其他车取后5位（含前导零）
                    loco_num = loco_num_full[-5:]
            else:
                loco_type = f"未知({loco_prefix})"
                loco_num = loco_num_full[-5:]

        # 3. 端位解析 (nibble 12-13)
        if nibble_count >= 14:
            try:
                end_code = ''.join(str(n) for n in nibbles[12:14])
                end_map = {"31": "A端", "32": "B端", "30": "未知端位"}
                end_position = end_map.get(end_code, f"端位{end_code}")
            except:
                pass

        # 4. 线路解析 (GB2312, nibble 14-29)
        if nibble_count >= 30:
            route_bytes = bytearray()
            for i in range(14, 30, 2):
                route_bytes.append((nibbles[i] << 4) | nibbles[i+1])
            try:
                decoded = route_bytes.decode('gb18030', errors='ignore').strip()
                route_name = ''.join(c for c in decoded if c.isprintable() and c != '\x00')
                if not route_name or len(route_name) < 2:
                    route_name = None
            except:
                pass

        # 5. 经度解析 (nibble 30-38, 9个数字: DDDMM.MMMM)
        if nibble_count >= 39:
            try:
                lon_digits = ''.join(str(n) for n in nibbles[30:39])
                if len(lon_digits) == 9:
                    lon_str = f"{lon_digits[:3]}°{lon_digits[3:5]}.{lon_digits[5:]}′E"
            except:
                pass

        # 6. 纬度解析 (nibble 39-46, 8个数字: DDMM.MMMM)
        if nibble_count >= 47:
            try:
                lat_digits = ''.join(str(n) for n in nibbles[39:47])
                if len(lat_digits) == 8:
                    lat_str = f"{lat_digits[:2]}°{lat_digits[2:4]}.{lat_digits[4:]}′N"
            except:
                pass

        return prefix, loco_type, loco_num, end_position, route_name, lon_str, lat_str, nibble_count
    except Exception as e:
        write_global_log(f"decode_1234002 解析异常: {e}, raw={numeric_str[:50]}", "ERROR")
        return "", "****", "****", "未知", None, None, None, 0
direction_cache = {}
DIRECTION_CACHE_TTL = 3600  # 1小时
TRAIN_BIND_CACHE_TTL = 3600  # 1小时未收到1234000则清理该车次的机车绑定状态

def get_direction(train_no, km, func_hint=None):
    """
    方向判断：优先公里标比较，无公里标时用Function Code辅助。
    func_hint: Function Code 辅助方向，3='上行', 1='下行', None=无。
    Function判定的方向同样受1小时TTL限制，过期后重新判断。
    """
    try:
        cached = direction_cache.get(train_no)
        now = time.time()

        # 无缓存 或 缓存超过1小时过期 → 视为新车次
        if cached is None or (now - cached[2]) > DIRECTION_CACHE_TTL:
            # 第一次来车：如果有Function hint，直接用Function判定
            if func_hint is not None:
                direction_cache[train_no] = (func_hint, km, now)
                return func_hint
            # 无Function hint，返回检测中（等第二次来车）
            direction_cache[train_no] = ("检测中", km, now)
            return "检测中"

        last_dir, last_km, _ = cached
        # 有公里标且上次也有公里标 → 用公里标计算（优先于Function）
        if km is not None and last_km is not None and abs(km - last_km) < 0.001:
            direction_cache[train_no] = (last_dir, last_km, now)
            return last_dir

        if km is not None and last_km is not None:
            new_dir = "上行" if km < last_km else "下行"
            direction_cache[train_no] = (new_dir, km, now)
            # 只记录方向反转（上行↔下行）
            # 方向反转日志已关闭
            return new_dir

        # 无公里标或上次无公里标，保持原方向（如果有效）
        if last_dir not in ("检测中",):
            direction_cache[train_no] = (last_dir, km if km is not None else last_km, now)
            return last_dir

        # 无有效方向，尝试Function hint（无公里标但有Function的情况）
        if func_hint is not None:
            direction_cache[train_no] = (func_hint, km, now)
            return func_hint

        return "检测中"
    except Exception as e:
        write_global_log(f"方向异常[{type(e).__name__}]: {e}, train_no={train_no}, km={km}", "ERROR")
        return "检测中"

def reset_direction_cache(train_no):
    if train_no in direction_cache:
        del direction_cache[train_no]


# ==================== 双向时间窗口匹配绑定（解决多车错判）====================
# 结构: {train_no: {"prefix": ..., "type": ..., "num": ..., "route": ..., "lon": ..., "lat": ..., "time": ...}}
loco_cache_by_train = {}
train_last_seen_time = {}  # 按原始车次号记录最近一次收到1234000的时间

# 全局最新缓存（仅用于 1234002 自身显示，不再用于 1234000 绑定）
current_loco = {
    "prefix": "",
    "type": "****",
    "num": "****",
    "route": "****",
    "lon": None,
    "lat": None,
    "time": 0
}

# 双向 pending 队列（时间窗口匹配）
# 单次信号持续1200ms，用multimon-ng毫秒时间戳精确判断
SIGNAL_DURATION_MS = 900   # 单次信号持续900ms
TRAIN_WINDOW = 2   # 兼容旧逻辑，实际用毫秒时间戳判断
LOCO_WINDOW = 2    # 同上

pending_loco = None   # 最近收到的 1234002 信息：{"prefix", "type", "num", "route", "lon", "lat", "time"}
pending_trains = []  # 最近收到的 1234000 车次列表（支持多车同时来）
_raw_count = {}  # 每个车次原始流显示次数计数

last_loco_display_time = {}

# 延迟显示队列：收到1234000后等待1.5秒，期间若1234002到达并绑定，则一起显示
pending_display = {}  # {train_no: {"after_id": int, "data": dict}}

def _direction_cache_keys_for_train(train_no):
    """返回同一原始车次可能使用的方向缓存键（带字头和不带字头）。"""
    single_prefixes = ["C", "Z", "T", "K", "L", "Y", "X", "D", "G", "N", "S"]
    prefixes = ["", "DJ", "F", "0"] + single_prefixes
    prefixes.extend("F" + p for p in single_prefixes)
    prefixes.extend("0" + p for p in single_prefixes)
    return {prefix + train_no for prefix in prefixes}


def _cleanup_expired_train_binding_cache(now=None):
    """清理超过1小时没有收到1234000的车次绑定缓存及相关方向状态。"""
    if now is None:
        now = time.time()

    for train_no, last_seen in list(train_last_seen_time.items()):
        if now - last_seen <= TRAIN_BIND_CACHE_TTL:
            continue

        train_last_seen_time.pop(train_no, None)
        old_binding = loco_cache_by_train.pop(train_no, None)
        removed_direction = False
        for cache_key in _direction_cache_keys_for_train(train_no):
            if cache_key in direction_cache:
                direction_cache.pop(cache_key, None)
                removed_direction = True

        if old_binding or removed_direction:
            write_global_log(
                f"车次缓存清理：{train_no} 超过1小时未收到1234000，已清除机车绑定及相关方向状态"
            )


def _periodic_train_binding_cache_cleanup():
    """每分钟检查一次长期未出现的车次；每次收到车次报文时也会立即检查。"""
    try:
        _cleanup_expired_train_binding_cache()
    except Exception as e:
        write_global_log(f"车次缓存定时清理异常：{e}", "ERROR")
    try:
        root.after(60000, _periodic_train_binding_cache_cleanup)
    except Exception:
        pass



def update_loco(prefix, loco_type, loco_num, route_name, lon_str, lat_str, train_no=None, nibble_count=0):
    """更新位置缓存。如果提供了车次号，同时按车次缓存（带绑定次数和完整度）"""
    global current_loco, loco_cache_by_train
    try:
        current_loco["prefix"] = prefix
        current_loco["type"] = loco_type
        current_loco["num"] = loco_num
        current_loco["route"] = route_name if route_name else "****"
        current_loco["lon"] = lon_str
        current_loco["lat"] = lat_str
        current_loco["time"] = time.time()

        if train_no:
            old = loco_cache_by_train.get(train_no, {})
            old_count = old.get("bind_count", 0)
            loco_cache_by_train[train_no] = {
                "prefix": prefix,
                "type": loco_type,
                "num": loco_num,
                "route": route_name if route_name else "****",
                "lon": lon_str,
                "lat": lat_str,
                "time": time.time(),
                "bind_count": old_count,
                "nibble_count": nibble_count if nibble_count > 0 else old.get("nibble_count", 0),
            }
    except Exception as e:
        write_global_log(f"update_loco 异常: {e}, train_no={train_no}", "ERROR")

def get_loco_info(train_no=None):
    """获取位置信息。严格按车次缓存，不再回退到全局 current_loco（避免多车串号）。"""
    try:
        if train_no:
            cached = loco_cache_by_train.get(train_no)
            if cached and time.time() - cached["time"] < 780:
                return (cached["prefix"], cached["type"], cached["num"],
                        cached["route"], cached["lon"], cached["lat"])
        # 无缓存或超时，返回空，不再回退 current_loco
        return "", "****", "****", "****", None, None
    except Exception as e:
        write_global_log(f"get_loco_info 异常: {e}, train_no={train_no}", "ERROR")
        return "", "****", "****", "****", None, None




def _should_override_cache(train_no, new_nibble_count, time_diff_ms, new_type=None, new_num=None):
    """覆盖决策：绑定次数越多，越不容易被误码覆盖。新数据必须'明显更好'才覆盖。"""
    cached = loco_cache_by_train.get(train_no)
    if not cached:
        return True
    old_type = cached.get("type", "****")
    old_num = cached.get("num", "****")
    old_count = cached.get("bind_count", 0)
    # 相同车型直接刷新（数据一样，无风险，只更新经纬度时间戳）
    if new_type and new_num and old_type == new_type and old_num == new_num and old_type not in ("****", "***", "", "未知"):
        return "refresh"
    # 旧车型是未知/截断/空 → 直接覆盖
    if old_type in ("****", "***", "", "未知") or not old_type:
        return True
    # 绑定次数为0 → 可以覆盖
    if old_count == 0:
        return True
    # 绑定1次 → 正常间隔内允许覆盖（纠正首次误码）
    if old_count == 1 and time_diff_ms < 500:
        return True
    # 绑定2次+ → 需要明显更好
    if old_count >= 2:
        if new_nibble_count > cached.get("nibble_count", 0) + 5:
            return True
        if time_diff_ms < 200:
            return True
        return False
    return False

def try_bind_pending_loco(prefix, loco_type, loco_num, route_name, lon_str, lat_str, nibble_count=0, line=None):
    """
    收到 1234002 时尝试绑定：
    1. 找 320ms 内时间差最小的 pending_train 绑定（防串车）
    2. 绑定后从 pending_trains 移除，防止后续车型再匹配
    3. 覆盖决策：绑定次数越多越难被覆盖，降低误码影响
    4. 总是更新 current_loco（全局最新）
    """
    global pending_loco, pending_trains
    try:
        cutoff = time.time() - 5
        pending_trains[:] = [t for t in pending_trains if t["time"] > cutoff]

        msg_time = _extract_msg_time(line) if line else time.time()

        pending_loco = {
            "prefix": prefix, "type": loco_type, "num": loco_num,
            "route": route_name if route_name else "****",
            "lon": lon_str, "lat": lat_str,
            "time": time.time(), "msg_time": msg_time,
            "nibble_count": nibble_count
        }

        update_loco(prefix, loco_type, loco_num, route_name, lon_str, lat_str, nibble_count=nibble_count)

        # 诊断日志：1234002当前匹配快照
        _map_log(f"1234002匹配开始: msg_time={msg_time:.3f}, pending={[(t['train_no'], round(t.get('msg_time', t['time']), 3)) for t in pending_trains]}")

        # 找时间差最小的车次（不是第一个）
        best_train = None
        best_diff = float('inf')
        for t in pending_trains:
            time_diff_ms = abs(msg_time - t.get("msg_time", t["time"])) * 1000
            # 诊断日志：逐个候选及时间差
            _map_log(f"1234002候选: train={t['train_no']}, diff={time_diff_ms:.0f}ms")
            if time_diff_ms > SIGNAL_DURATION_MS:
                continue
            if time_diff_ms < best_diff:
                best_diff = time_diff_ms
                best_train = t

        # 诊断日志：最佳候选
        _map_log(f"1234002最佳候选: best={best_train['train_no'] if best_train else 'None'}, best_diff={best_diff:.0f}ms, pending={len(pending_trains)}")

        if best_train:
            cached = loco_cache_by_train.get(best_train["train_no"], {})
            override = _should_override_cache(best_train["train_no"], nibble_count, best_diff, loco_type, loco_num)
            # 诊断日志：覆盖判断及旧缓存
            _map_log(f"1234002覆盖判断: train={best_train['train_no']}, old_type={cached.get('type', '****')}, old_num={cached.get('num', '****')}, old_bind_count={cached.get('bind_count', 0)}, new_type={loco_type}, new_num={loco_num}, override={override}")
            if override == "refresh":
                # 相同车型：只刷新经纬度/线路/时间戳，不增加bind_count
                cached = loco_cache_by_train.get(best_train["train_no"])
                if cached:
                    cached["lon"] = lon_str
                    cached["lat"] = lat_str
                    cached["route"] = route_name if route_name else cached.get("route", "****")
                    cached["time"] = time.time()
            elif override:
                update_loco(
                    prefix, loco_type, loco_num, route_name, lon_str, lat_str,
                    train_no=best_train["train_no"], nibble_count=nibble_count
                )
                cached = loco_cache_by_train.get(best_train["train_no"])
                if cached:
                    cached["bind_count"] = cached.get("bind_count", 0) + 1
            # 覆盖/刷新成功才移除，拒绝时保留给下一个1234002
            if override:
                pending_trains.remove(best_train)
            # 这条1234002已被消费，清空pending_loco防止后续车次误绑
            pending_loco = None
            _map_log(f"1234002绑定: best={best_train['train_no']}, diff={best_diff:.0f}ms, override={override}, clients={len(_sse_clients)}")
            return True
            _map_log(f"1234002无匹配: pending={len(pending_trains)}, best_diff={best_diff}")
        _map_log(f"1234002无匹配(实际返回): pending={len(pending_trains)}, best_diff={best_diff:.0f}ms, msg_time={msg_time:.3f}")
        return False
    except Exception as e:
        write_global_log(f"绑定异常[{type(e).__name__}]: {e}", "ERROR")
        return False

def try_bind_pending_train(train_no, line=None):
    """
    收到 1234000 时：只查缓存 + 加入 pending_trains，不消费 pending_loco。
    车型绑定只由 try_bind_pending_loco（1234002）负责，避免截胡。
    返回 (prefix, loco_type, loco_num, route_name, lon_str, lat_str, bound)
    """
    global pending_trains
    try:
        # 清理5秒前的旧队列
        cutoff = time.time() - 5
        pending_trains[:] = [t for t in pending_trains if t["time"] > cutoff]

        msg_time = _extract_msg_time(line) if line else time.time()

        # 加入待绑队列
        pending_trains.append({
            "train_no": train_no,
            "time": time.time(),
            "msg_time": msg_time
        })
        # 诊断日志：1234000入队后的完整队列
        _map_log(f"1234000入队: train={train_no}, msg_time={msg_time:.3f}, pending={[t['train_no'] for t in pending_trains]}")

        # 查缓存
        cached = get_loco_info(train_no)
        if cached[1] != "****":
            return (*cached, True)
        return ("", "****", "****", "****", None, None, False)
    except Exception as e:
        write_global_log(f"绑定异常[{type(e).__name__}]: {e}, train_no={train_no}", "ERROR")
        return ("", "****", "****", "****", None, None, False)

# ==================== 音量监控 ====================
import queue

volume_queue = queue.Queue(maxsize=5)  # 只保留最新5个值，防止堆积

def volume_reader_thread(sox_vu_proc):
    """独立线程：死循环读 sox 音量，丢到队列"""
    history = []
    while running and sox_vu_proc and sox_vu_proc.poll() is None:
        try:
            data = sox_vu_proc.stdout.read(512)
            if data and len(data) >= 2:
                import struct
                samples = struct.unpack(f'<{len(data)//2}h', data[:len(data)//2*2])
                sum_sq = sum(s * s for s in samples)
                rms = int((sum_sq / len(samples)) ** 0.5) if samples else 0
                vol = min(100, int((rms / 32767) * 100 * 4))

                history.append(vol)
                if len(history) > 3:
                    history.pop(0)
                avg = sum(history) // len(history)

                # 丢到队列，满了就覆盖旧的
                if volume_queue.full():
                    try:
                        volume_queue.get_nowait()
                    except:
                        pass
                volume_queue.put_nowait(avg)
        except:
            pass
        time.sleep(0.01)  # 10ms 采样

def update_volume_bar(volume_var, volume_label, root):
    """主线程：50ms 从队列取一次值，更新 GUI"""
    if not running:
        volume_var.set(0)
        volume_label.config(text="0%")
        return

    # 取最新值（非阻塞）
    latest = None
    while not volume_queue.empty():
        try:
            latest = volume_queue.get_nowait()
        except:
            break

    if latest is not None:
        volume_var.set(latest)
        volume_label.config(text=f"{latest}%")

    # 主界面刷新率：50ms，完全不卡
    root.after(50, lambda: update_volume_bar(volume_var, volume_label, root))


# ==================== ETA 显示更新 ====================



# ==================== 解码启动/停止 ====================
selected_device = None

def start_decoder():
    global running, sox_process, sox_vu_process, multimon_process
    if running:
        return

    # 地图接口启用时，先绑定端口；失败则显示在主输出、写系统日志并取消解码启动
    if _notify_config.get("enable_map_api", True):
        map_port = _notify_config.get("map_api_port", 8765)
        write_global_log(f"开始前检查地图接口端口：127.0.0.1:{map_port}")
        if not _start_train_api(map_port):
            error_message = _api_start_error or f"地图接口端口 {map_port} 无法启动"
            full_error = f"解码启动取消：{error_message}"
            write_global_log(full_error, "ERROR")
            try:
                output.insert(tk.END, "\n" + full_error + "\n本次解码未启动。\n")
                output.see(tk.END)
            except Exception:
                pass
            dialog_title = "地图接口端口冲突" if _api_start_port_conflict else "地图接口启动失败"
            if _api_start_port_conflict:
                dialog_message = (
                    f"{error_message}\n\n本次解码未启动。请关闭占用端口的程序，"
                    "或修改地图接口端口后重试。"
                )
            else:
                dialog_message = f"{error_message}\n\n本次解码未启动。请检查地图接口设置后重试。"
            messagebox.showerror(dialog_title, dialog_message, parent=root)
            return

    cleanup_history_files()  # 只有确认可以启动后才清理历史文件
    load_locomotive_types()  # 重新加载车型库
    write_global_log("开始解码")
    write_global_log("当前版本: 10.22.22")
    # 开始解码前尝试写入之前缓存的CSV记录（仅当有缓存时）
    if _csv_pending_records:
        _flush_csv_pending()
    running = True

    device_name = device_var.get()

    def run():
        global sox_process, multimon_process
        sox_exe = os.path.join(BASE_DIR, "bin", "sox.exe")
        multimon_exe = os.path.join(BASE_DIR, "bin", "multimon-ng.exe")
        sox_process = subprocess.Popen([
            sox_exe, "-q",
            "-t", "waveaudio", device_name,
            "-r", "22050", "-c", "1", "-b", "16",
            "-e", "signed-integer", "-t", "raw", "-"
        ], stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)

        multimon_process = subprocess.Popen(
            [multimon_exe, "-a", "POCSAG1200", "-f", "numeric", "-t", "raw", "-"],
            stdin=sox_process.stdout, stdout=subprocess.PIPE,
            text=True, encoding='utf-8', errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        try:
            for line in multimon_process.stdout:
                if not running:
                    break
                root.after(0, parse_and_display, line)
        except Exception as e:
            write_global_log(f"multimon读取异常[{type(e).__name__}]: {e}", "ERROR")

    threading.Thread(target=run, daemon=True).start()

    # 独立音量 sox
    sox_exe = os.path.join(BASE_DIR, "bin", "sox.exe")
    sox_vu_process = subprocess.Popen([
        sox_exe, "-q",
        "-t", "waveaudio", device_name,
        "-r", "22050", "-c", "1", "-b", "16",
        "-e", "signed-integer", "-t", "raw", "-"
    ], stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)

    # 启动音量读取线程（10ms 高频采样）
    threading.Thread(target=volume_reader_thread, args=(sox_vu_process,), daemon=True).start()

    # GUI 更新（50ms 低频刷新，不卡主界面）
    root.after(50, lambda: update_volume_bar(volume_var, volume_label, root))
def stop_decoder():
    global running, sox_process, sox_vu_process, multimon_process
    load_locomotive_types()  # 重新加载车型库
    write_global_log("停止解码")
    running = False
    _train_api_state.clear()
    threading.Thread(target=_stop_train_api, daemon=True).start()

    # CSV缓存刷新放到后台线程，不阻塞主线程
    if _csv_pending_records:
        threading.Thread(target=_flush_csv_pending, daemon=True).start()

    # 子进程终止放到后台线程，taskkill杀进程树更彻底
    def _kill_procs():
        for proc_name in ["sox.exe", "multimon-ng.exe"]:
            try:
                subprocess.Popen(
                    f'taskkill /F /T /IM {proc_name}',
                    shell=True, creationflags=subprocess.CREATE_NO_WINDOW
                )
            except:
                pass
        time.sleep(0.3)
        for proc in [sox_process, sox_vu_process, multimon_process]:
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                except:
                    pass

    threading.Thread(target=_kill_procs, daemon=True).start()

    sox_process = None
    sox_vu_process = None
    multimon_process = None
def schedule_train_display(train_no, display_data):
    """延迟1.5秒显示车次信息，等待可能的1234002绑定"""
    # 如果已有该车的定时器，取消旧的（防重复）
    if train_no in pending_display and pending_display[train_no].get("after_id"):
        try:
            root.after_cancel(pending_display[train_no]["after_id"])
        except:
            pass

    after_id = root.after(1300, lambda tn=train_no: display_train_delayed(tn))
    pending_display[train_no] = {
        "after_id": after_id,
        "data": display_data
    }

def display_train_delayed(train_no):
    """1.5秒后执行：重新查询绑定状态并显示"""
    if train_no not in pending_display:
        return

    info = pending_display[train_no]["data"]

    # 重新查询绑定状态（1.5秒内1234002可能已到并绑定）
    prefix, lt, ln, lr, lon, lat = get_loco_info(train_no)

    # 如果有新绑定，更新显示数据
    if lt != "****" and lt != "":
        info["lt"] = lt
        info["ln"] = ln
        info["lr"] = lr
        info["lon"] = lon
        info["lat"] = lat
        if prefix:
            info["prefix"] = prefix
            info["full_train_no"] = prefix + info["train_raw"]
            # 重新识别类型（因为加了字头可能不同）
            info["train_type"] = identify_train_type(info["full_train_no"])

    # 执行显示和CSV保存
    _do_train_display(info)

    del pending_display[train_no]

def _do_train_display(info):
    """实际显示和保存CSV"""
    full_train_no = info["full_train_no"]
    lt = info["lt"]
    ln = info["ln"]
    lr = info["lr"]
    direction = info["direction"]
    speed_val = info["speed_val"]
    km_str = info["km_str"]
    train_type = info["train_type"]
    now_str = info["now_str"]
    lon = info["lon"]
    lat = info["lat"]

    # GUI 显示（保持原有带符号排版）
    display_text = "-" * 50 + "\n"
    display_text += f"🚂 车型: {lt} | 车号: {ln} | 🛤️ 线路: {lr}\n"
    display_text += f"🚆 车次: {full_train_no} | 方向: {direction}\n"

    speed_display = f"{speed_val}" if speed_val is not None else "--"
    km_display = km_str if km_str else "--"
    display_text += f"📊 速度: {speed_display} km/h | 公里标: {km_display}\n"

    display_text += f"🚃 类型: {train_type}\n"

    lon_display = lon if lon else "--"
    lat_display = lat if lat else "--"
    display_text += f"🌐 经纬度: {lon_display}  {lat_display}\n"

    display_text += f"⏰ 时间: {now_str}\n"
    display_text += "-" * 50 + "\n"

    output.insert(tk.END, display_text)
    output.see(tk.END)

    # 保存到 CSV（纯文本无符号，与模板格式一致）
    record = {
        "时间": now_str,
        "车次": full_train_no,
        "方向": direction,
        "速度": str(speed_val) if speed_val is not None else "",
        "车型": lt,
        "车号": ln,
        "线路": lr,
        "公里标": km_str if km_str else "",
        "列车类型": train_type,
        "经度 纬度": f"{lon_display} {lat_display}" if lon and lat else "",
    }
    threading.Thread(target=save_to_csv, args=(record,), daemon=True).start()

    # 推送通知（非阻塞，失败不影响主程序）
    should_send, reason = _should_notify(full_train_no, lt, ln, km_str)
    if should_send:
        tmpl = _notify_config.get("msg_template", "")
        if not tmpl:
            tmpl = "型：{车型}-{车号}\n车次：{车次} {方向}\n速-标：{速度}km/h  K{公里标}\n{时间}\n经纬：{经度}  {纬度}"
        # 时间去掉年份
        time_no_year = now_str[5:] if len(now_str) >= 10 else now_str
        notify_msg = tmpl.format(
            车型=lt if lt and lt != "****" else "***",
            车号=ln if ln and ln != "****" else "***",
            车次=full_train_no,
            方向=direction,
            速度=str(speed_val) if speed_val is not None else "***",
            公里标=km_str if km_str else "***",
            时间=time_no_year,
            经度=lon if lon else "***",
            纬度=lat if lat else "***",
            线路=lr if lr and lr != "****" else "***",
        )
        # 只在首次和车型补充时记录日志，公里标变化不记录避免刷屏
        if reason in ("首次通知", "车型补充通知"):
            write_global_log(f"通知触发[{reason}]: {full_train_no}")
        send_notification(notify_msg)
    # 通知跳过不记录日志，避免日志膨胀

    # === 地图实时数据推送 ===
    try:
        _push_map_data(
            full_train_no,
            train_type,
            lr if lr and lr not in ("****", "***") else "",
            direction,
            km_str,
            speed_val,
            lon if lon else None,
            lat if lat else None,
            lt if lt and lt not in ("****", "***") else "",
            ln if ln and ln not in ("****", "***") else ""
        )
    except Exception:
        pass
    # === 地图数据推送结束 ===

    # === 历史车次存储 ===
    append_history(record)
    # === 历史存储结束 ===

def _extract_msg_time(line):
    """从 multimon-ng 输出中提取精确毫秒时间戳 [HH:MM:SS.mmm]，返回秒级浮点数"""
    try:
        ts_match = re.search(r"(?:\[|^|\s)(\d{2}:\d{2}:\d{2}\.\d{3})(?:\]|\s|$|:)", line)
        if ts_match:
            ts_str = ts_match.group(1)
            h, m, s = ts_str.split(':')
            return int(h) * 3600 + int(m) * 60 + float(s)
        return time.time()
    except Exception as e:
        write_global_log(f"_extract_msg_time 异常: {e}, line={line[:100]}", "ERROR")
        return time.time()


def parse_and_display(line):
    global pending_loco, pending_trains, _raw_buffer
    # 原始流：始终保存到环形缓冲区（800条上限），不管通知窗口是否打开
    _raw_buffer.append(line)
    if len(_raw_buffer) > 800:
        _raw_buffer.pop(0)
    # 如果通知窗口已打开，实时追加
    try:
        if _notify_raw_text and _notify_raw_text.winfo_exists():
            _notify_raw_text.config(state="normal")
            _notify_raw_text.insert(tk.END, line)
            _notify_raw_text.see(tk.END)
            _notify_raw_text.config(state="disabled")
    except Exception:
        pass

    # ================== 1234002 位置/机车信息 ==================
    if "1234002" in line:
        match = re.search(r'Numeric:\s*(.+)', line)
        if not match:
            return

        raw_data = match.group(1).strip()
        prefix, loco_type, loco_num, end_pos, route_name, lon_str, lat_str, nibble_count = decode_1234002(raw_data)

        # 车字头校验：合法字头 C,Z,T,K,L,Y,X,D,G,N,S,DJ,F,0 及折返组合(F+单字)
        if prefix:
            _valid_single = {'C','Z','T','K','L','Y','X','D','G','N','S','F','0'}
            _is_valid_prefix = False
            if prefix in _valid_single or prefix == 'DJ':
                _is_valid_prefix = True
            elif prefix.startswith('F') and len(prefix) == 2 and prefix[1] in _valid_single:
                _is_valid_prefix = True
            elif prefix.startswith('0') and len(prefix) == 2 and prefix[1] in _valid_single:
                _is_valid_prefix = True  # 0+单字: 回送列车
            if not _is_valid_prefix:
                return  # 无效字头，丢弃这帧数据

        # 检测数据截断
        is_truncated = nibble_count < 13  # 正常应 >= 47 nibbles，但13位已含字头+车号+端位

        # 修复：即使数据截断，只要解析出车号就更新缓存和绑定（前13位已含车型车号）
        if loco_num != "****":
            update_loco(prefix, loco_type, loco_num, route_name, lon_str, lat_str, nibble_count=nibble_count)
            bound = try_bind_pending_loco(prefix, loco_type, loco_num, route_name, lon_str, lat_str, nibble_count=nibble_count, line=line)
            now = time.time()
            last_loco_display_time[loco_num] = now

        # 原始流：新车次前5次全部输出，后面40%随机显示（不影响绑定）
        import random
        show_raw = False
        raw_key = loco_num if loco_num != "****" else "unknown"
        if raw_key not in _raw_count:
            _raw_count[raw_key] = 0
        if _raw_count[raw_key] < 5:
            show_raw = True
            _raw_count[raw_key] += 1
        elif random.random() < 0.5:
            show_raw = True
        if show_raw:
            display_text = "-" * 50 + "\n"
            display_text += f"🗺️[原始流]: {line.strip()}\n"
            display_text += "-" * 50 + "\n"
            output.insert(tk.END, display_text)
            output.see(tk.END)
        # 原始流只显示，不保存到 CSV

        return

    # ================== 1234000 运行状态 ==================
    if "1234000" in line and "Numeric:" in line:
        match = re.search(r'Numeric:\s*(.+)', line)
        if not match:
            return

        numeric_part = match.group(1).strip()
        clean_numeric = re.sub(r'[^\d\s]', '', numeric_part)
        parts = clean_numeric.split()

        if len(parts) < 1:
            return

        train_raw = parts[0]
        if len(train_raw) < 1 or len(train_raw) > 5:
            return

        # 每次收到有效车次状态帧，都刷新该车活动时间；超时记录先清理，再将本次视为新车次
        _cleanup_expired_train_binding_cache()
        train_last_seen_time[train_raw] = time.time()

        # 解析速度（可选）
        speed_val = None
        if len(parts) >= 2:
            try:
                s = int(parts[1])
                if 0 <= s <= 400:
                    speed_val = s
            except ValueError:
                pass

        # 解析公里标（可选）
        # LBJ 格式：最后一位是小数位，前面是整数位
        # 2位: 87 -> 8.7 | 3位: 107 -> 10.7 | 4位: 1846 -> 184.6 | 5位: 18465 -> 1846.5
        km_str = None
        if len(parts) >= 3:
            try:
                k = int(parts[2])
                s = str(k)
                if 1 < len(s) <= 5:  # 至少2位（1位整数+1位小数），最多5位
                    km_str = f"{s[:-1]}.{s[-1]}"
            except ValueError:
                pass

        # 组合完整车次
        full_train_no = train_raw  # 先假设没有字头

        # 尝试双向绑定：获取位置信息
        prefix, lt, ln, lr, lon, lat, bound = try_bind_pending_train(full_train_no, line)

        # 如果绑定成功，full_train_no 可能需要加上字头
        if prefix:
            # 修复：继承无前缀车次的方向缓存，避免 1234002 补充信息后重置方向/线路等
            if train_raw in direction_cache and (prefix + train_raw) not in direction_cache:
                direction_cache[prefix + train_raw] = direction_cache[train_raw]
            full_train_no = prefix + train_raw

        # 识别列车类型
        train_type = identify_train_type(full_train_no)
        is_special = train_type in SPECIAL_TYPES

        # 刷新规则：
        # 1. 特殊类型（单机/补机/工程车等）有车次就显示
        # 2. 普通列车：必须有速度或公里标才显示，防误码
        # 3. 但如果 multimon-ng 原始输出明确显示为 "-- ---"（即确实没有速度公里标），也显示
        has_explicit_dash = re.search(r'Numeric:\s+\S+\s+[-—]+\s+[-—]+', line) is not None
        if speed_val is None and km_str is None and not is_special and not has_explicit_dash:
            return

        # 从multimon-ng输出行提取Function Code（辅助方向判断）
        func_direction = None
        func_match = re.search(r'Function:\s*(\d+)', line)
        if func_match:
            func_code = int(func_match.group(1))
            if func_code == 3:
                func_direction = "上行"
            elif func_code == 1:
                func_direction = "下行"

        # 方向判断（修复：不同车次严格隔离缓存）
        # 优先公里标比较，无公里标/无缓存时用Function Code辅助
        direction = "检测中"
        if km_str:
            km_float = float(km_str)
            direction = get_direction(full_train_no, km_float, func_hint=func_direction)
        else:
            # 无公里标时，尝试使用上次的方向缓存（1小时内有效）
            cached = direction_cache.get(full_train_no)
            if cached and (time.time() - cached[2]) <= DIRECTION_CACHE_TTL:
                direction = cached[0]
            else:
                # 无缓存且无公里标，尝试Function辅助（第一次来车或无公里标车辆）
                direction = get_direction(full_train_no, None, func_hint=func_direction)

        # 更新当前列车信息（用于方向判断）
        current_train_info.update({
            "train": full_train_no,
            "direction": direction,
            "speed": speed_val,
            "km": km_str
        })

        # 时间
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # 收集显示数据，延迟1.5秒显示，等待可能的1234002绑定
        display_data = {
            "train_raw": train_raw,
            "full_train_no": full_train_no,
            "prefix": prefix,
            "lt": lt,
            "ln": ln,
            "lr": lr,
            "lon": lon,
            "lat": lat,
            "direction": direction,
            "speed_val": speed_val,
            "km_str": km_str,
            "train_type": train_type,
            "now_str": now_str,
        }
        schedule_train_display(full_train_no, display_data)

        return

def open_map_window(event=None):
    """Ctrl+Shift+M 打开地图（浏览器访问本地SSE服务）"""
    ip = _notify_config.get("map_api_ip", "127.0.0.1")
    port = _notify_config.get("map_api_port", 8765)
    url = f"http://{ip}:{port}/"
    # 自动启动SSE服务（如果还没启动）
    if _api_server is None and _notify_config.get("enable_map_api", True):
        _start_train_api(port)
        pass  # time.sleep已移除
    # 用浏览器打开
    try:
        import webbrowser
        webbrowser.open(url, new=2, autoraise=True)
    except Exception:
        try:
            import subprocess
            subprocess.Popen(['start', url], shell=True)
        except Exception:
            write_global_log(f"地图浏览器打开失败: {url}", "WARN")

def open_notification_settings(event=None):
    """Ctrl+Shift+N 打开通知设置窗口"""
    global _notify_config, _notify_raw_text, _notify_settings_win
    if _notify_settings_win is not None and _notify_settings_win.winfo_exists():
        _notify_settings_win.lift()
        _notify_settings_win.focus_force()
        return
    win = tk.Toplevel(root)
    _notify_settings_win = win
    win.title("功能设置")
    win.geometry("650x550")
    win.resizable(True, True)
    win.transient(root)
    try:
        ip = get_resource_path(os.path.join("ico", "lbj_icon_final.ico"))
        if os.path.exists(ip): win.iconbitmap(ip)
    except: pass
    nb = ttk.Notebook(win)
    nb.pack(fill="both", expand=True, padx=10, pady=10)
    # 选项卡1：原输出
    tr = tk.Frame(nb); nb.add(tr, text="原输出")
    rt = ScrolledText(tr, font=("Consolas", 10), wrap=tk.WORD, height=22, bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
    rt.pack(fill="both", expand=True, padx=5, pady=5)
    if _raw_buffer:
        rt.insert("1.0", "".join(_raw_buffer))
    else:
        rt.insert("1.0", "等待原始流数据...\n")
    rt.config(state="disabled")
    rt.see(tk.END)  # 默认滚动到底部，显示最新原始流
    _notify_raw_text = rt
    # 选项卡2：通知设置（带滚动条）
    ts_outer = tk.Frame(nb); nb.add(ts_outer, text="通知设置")
    # 选项卡3：地图设置
    map_frame = tk.Frame(nb)
    nb.add(map_frame, text="地图设置")

    # 启用开关
    map_enable_var = tk.BooleanVar(value=_notify_config.get("enable_map_api", True))
    tk.Checkbutton(map_frame, text="启用地图接口", variable=map_enable_var, font=("Microsoft YaHei", 10)).pack(anchor="w", padx=20, pady=(15, 5))

    # IP输入
    map_ip_lbl = tk.Label(map_frame, text="地图接口IP:", font=("Microsoft YaHei", 10))
    map_ip_lbl.pack(anchor="w", padx=20, pady=(10, 2))
    map_ip = tk.Entry(map_frame, font=("Microsoft YaHei", 10), width=30)
    map_ip.pack(anchor="w", padx=20, pady=2)
    map_ip.insert(0, _notify_config.get("map_api_ip", "127.0.0.1"))
    win._map_ip_entry = map_ip

    # 端口输入
    map_port_lbl = tk.Label(map_frame, text="地图接口端口:", font=("Microsoft YaHei", 10))
    map_port_lbl.pack(anchor="w", padx=20, pady=(10, 2))
    map_port = tk.Entry(map_frame, font=("Microsoft YaHei", 10), width=30)
    map_port.pack(anchor="w", padx=20, pady=2)
    map_port.insert(0, str(_notify_config.get("map_api_port", 8765)))
    win._map_port_entry = map_port

    # 动态 API URL 显示
    map_url_var = tk.StringVar(value=f"API地址: http://127.0.0.1:{_notify_config.get('map_api_port', 8765)}/api/trains")
    map_url_lbl = tk.Label(map_frame, textvariable=map_url_var, font=("Consolas", 9), fg="#666")
    map_url_lbl.pack(anchor="w", padx=20, pady=(5, 15))

    def _update_map_url(*args):
        ip = map_ip.get().strip() or "127.0.0.1"
        try:
            p = int(map_port.get().strip())
            map_url_var.set(f"API地址: http://{ip}:{p}/api/trains")
        except:
            map_url_var.set(f"API地址: http://{ip}:端口无效")
    map_ip.bind("<KeyRelease>", _update_map_url)
    map_port.bind("<KeyRelease>", _update_map_url)

    # 保存按钮
    def _sv_map():
        _notify_config["enable_map_api"] = map_enable_var.get()
        _notify_config["map_api_ip"] = map_ip.get().strip() or "127.0.0.1"
        try: _notify_config["map_api_port"] = int(map_port.get().strip())
        except: _notify_config["map_api_port"] = 8765
        _save_notify_config()
        write_global_log("地图配置已保存")
        saved_lbl = tk.Label(map_frame, text="✓ 保存成功", font=("Microsoft YaHei", 10), fg="#28a745")
        saved_lbl.pack(anchor="w", padx=20, pady=5)
        win.after(2000, saved_lbl.destroy)
    tk.Button(map_frame, text="保存", command=_sv_map, bg="#28a745", fg="white", font=("Microsoft YaHei", 11), width=10).pack(anchor="w", padx=20, pady=(10, 0))

    # 实时日志输出框（黑底白字，不保存）
    tk.Label(map_frame, text='接口日志:', font=('Microsoft YaHei', 10)).pack(anchor='w', padx=20, pady=(15, 2))
    map_log = ScrolledText(map_frame, font=('Consolas', 9), wrap=tk.WORD, height=8, width=60,
                           bg='#1e1e1e', fg='#d4d4d4', insertbackground='white', state='disabled')
    map_log.pack(fill='both', expand=True, padx=20, pady=(0, 10))
    global _map_log_text
    _map_log_text = map_log

    canvas = tk.Canvas(ts_outer, highlightthickness=0)
    scrollbar = tk.Scrollbar(ts_outer, orient="vertical", command=canvas.yview)
    ts = tk.Frame(canvas)
    ts.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=ts, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    # 鼠标滚轮支持（只在 canvas 区域内生效）
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    canvas.bind("<MouseWheel>", _on_mousewheel)

    # 递归绑定滚轮到canvas内所有子控件
    def _bind_wheel_recursive(widget):
        widget.bind('<MouseWheel>', _on_mousewheel)
        for child in widget.winfo_children():
            _bind_wheel_recursive(child)
    _bind_wheel_recursive(canvas)
    # 控件
    r = 0
    tk.Label(ts, text="Webhook URL:", font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    we = tk.Entry(ts, font=("Microsoft YaHei", 10), width=30)
    we.grid(row=r, column=1, sticky="w", padx=5, pady=3)
    we.insert(0, _notify_config.get("webhook_url", ""))
    r += 1
    tk.Label(ts, text="QQ Bot API:", font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    qe = tk.Entry(ts, font=("Microsoft YaHei", 10), width=30)
    qe.grid(row=r, column=1, sticky="w", padx=5, pady=3)
    qe.insert(0, _notify_config.get("qq_bot_api", ""))
    r += 1
    tk.Label(ts, text="Access Token:", font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    at = tk.Entry(ts, font=("Microsoft YaHei", 10), width=30, show="*")
    at.grid(row=r, column=1, sticky="w", padx=5, pady=3)
    at.insert(0, _notify_config.get("access_token", ""))
    r += 1
    tk.Label(ts, text="QQ群号:", font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    qg = tk.Entry(ts, font=("Microsoft YaHei", 10), width=30)
    qg.grid(row=r, column=1, sticky="w", padx=5, pady=3)
    qg.insert(0, _notify_config.get("qq_target_group", ""))
    r += 1
    tk.Label(ts, text="消息格式:", font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    mf_var = tk.StringVar(value=_notify_config.get("qq_msg_format", "array"))
    mf_combo = ttk.Combobox(ts, textvariable=mf_var, values=["array", "string"], font=("Microsoft YaHei", 10), width=15, state="readonly")
    mf_combo.grid(row=r, column=1, sticky="w", padx=5, pady=3)
    r += 1
    tk.Label(ts, text="公里标间隔(km):", font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    ke = tk.Entry(ts, font=("Microsoft YaHei", 10), width=30)
    ke.grid(row=r, column=1, sticky="w", padx=5, pady=3)
    ke.insert(0, str(_notify_config.get("km_interval", 1.0)))
    r += 1
    fv = tk.BooleanVar(value=_notify_config.get("notify_first", True))
    lv = tk.BooleanVar(value=_notify_config.get("notify_loco", True))
    tk.Checkbutton(ts, text="首次出现发通知", variable=fv, font=("Microsoft YaHei", 10)).grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=2)
    r += 1
    tk.Checkbutton(ts, text="有车型车次后再发一次", variable=lv, font=("Microsoft YaHei", 10)).grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=2)
    r += 1
    # 白名单
    wl_var = tk.BooleanVar(value=_notify_config.get("use_whitelist", False))
    tk.Checkbutton(ts, text="启用白名单", variable=wl_var, font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    r += 1
    wl = ScrolledText(ts, font=("Microsoft YaHei", 10), wrap=tk.WORD, height=3, width=50)
    wl.grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=3)
    wl.insert("1.0", _notify_config.get("whitelist", "DJ,70,73,74,513,55,58,95,00,F,D,C,50"))
    if not wl_var.get():
        wl.config(state="disabled", bg="#e0e0e0")
    r += 1
    # 黑名单
    bl_var = tk.BooleanVar(value=_notify_config.get("use_blacklist", False))
    tk.Checkbutton(ts, text="启用黑名单", variable=bl_var, font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    r += 1
    bl = ScrolledText(ts, font=("Microsoft YaHei", 10), wrap=tk.WORD, height=3, width=50)
    bl.grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=3)
    bl.insert("1.0", _notify_config.get("blacklist", ""))
    if not bl_var.get():
        bl.config(state="disabled", bg="#e0e0e0")
    r += 1
    # 黑白名单开关联动
    def _toggle_wl(*args):
        if wl_var.get():
            wl.config(state="normal", bg="white")
        else:
            wl.config(state="disabled", bg="#e0e0e0")
    def _toggle_bl(*args):
        if bl_var.get():
            bl.config(state="normal", bg="white")
        else:
            bl.config(state="disabled", bg="#e0e0e0")
    wl_var.trace_add("write", _toggle_wl)
    bl_var.trace_add("write", _toggle_bl)
    # 公里标区间
    kmr_var = tk.BooleanVar(value=_notify_config.get("use_km_range", False))
    tk.Checkbutton(ts, text="启用公里标区间", variable=kmr_var, font=("Microsoft YaHei", 10)).grid(row=r, column=0, sticky="w", padx=10, pady=3)
    r += 1
    kmg = ScrolledText(ts, font=("Microsoft YaHei", 10), wrap=tk.WORD, height=2, width=50)
    kmg.grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=3)
    kmg.insert("1.0", _notify_config.get("km_ranges", ""))
    if not kmr_var.get():
        kmg.config(state="disabled", bg="#e0e0e0")
    r += 1
    def _toggle_kmr(*args):
        if kmr_var.get():
            kmg.config(state="normal", bg="white")
        else:
            kmg.config(state="disabled", bg="#e0e0e0")
    kmr_var.trace_add("write", _toggle_kmr)
    r += 1
    # 消息模板
    tk.Label(ts, text="消息模板(变量:{车型}{车号}{车次}{方向}{速度}{公里标}{时间}{经度}{纬度}{线路}):", font=("Microsoft YaHei", 10)).grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=3)
    r += 1
    mt = ScrolledText(ts, font=("Microsoft YaHei", 10), wrap=tk.WORD, height=5, width=50)
    mt.grid(row=r, column=0, columnspan=2, sticky="w", padx=10, pady=3)
    mt.insert("1.0", _notify_config.get("msg_template", "型：{车型}-{车号}\n车次：{车次} {方向}\n速-标：{速度}km/h  K{公里标}\n {时间}\n经纬：{经度}  {纬度}"))
    r += 1
    # 保存按钮（不关闭窗口）
    def sv():
        global WEBHOOK_URL, QQ_BOT_API, QQ_TARGET_GROUP
        _notify_config["webhook_url"] = we.get().strip()
        _notify_config["qq_bot_api"] = qe.get().strip()
        _notify_config["access_token"] = at.get().strip()
        _notify_config["qq_target_group"] = qg.get().strip()
        _notify_config["whitelist"] = wl.get("1.0", tk.END).strip()
        _notify_config["blacklist"] = bl.get("1.0", tk.END).strip()
        _notify_config["use_whitelist"] = wl_var.get()
        _notify_config["use_blacklist"] = bl_var.get()
        try: _notify_config["km_interval"] = float(ke.get().strip())
        except: _notify_config["km_interval"] = 1.0
        _notify_config["notify_first"] = fv.get()
        _notify_config["notify_loco"] = lv.get()
        _notify_config["qq_msg_format"] = mf_var.get()
        _notify_config["msg_template"] = mt.get("1.0", tk.END).rstrip("\n")
        _notify_config["km_ranges"] = kmg.get("1.0", tk.END).strip()
        _notify_config["use_km_range"] = kmr_var.get()
        try: _notify_config["map_api_port"] = int(win._map_port_entry.get().strip())
        except: _notify_config["map_api_port"] = 8765
        try: _notify_config["map_api_ip"] = win._map_ip_entry.get().strip() or "127.0.0.1"
        except: _notify_config["map_api_ip"] = "127.0.0.1"
        if _notify_config["webhook_url"]: WEBHOOK_URL = _notify_config["webhook_url"]
        if _notify_config["qq_bot_api"]: QQ_BOT_API = _notify_config["qq_bot_api"]
        if _notify_config["qq_target_group"]: QQ_TARGET_GROUP = _notify_config["qq_target_group"]
        _save_notify_config()
        write_global_log("通知配置已保存")
        # 保存成功提示，不关闭窗口
        saved_lbl = tk.Label(ts, text="✓ 保存成功", font=("Microsoft YaHei", 10), fg="#28a745")
        saved_lbl.grid(row=r, column=0, columnspan=2, pady=5)
        win.after(2000, saved_lbl.destroy)
    tk.Button(ts, text="保存", command=sv, bg="#28a745", fg="white", font=("Microsoft YaHei", 11), width=10).grid(row=r, column=0, columnspan=2, pady=10)
    def _on_settings_close():
        global _notify_settings_win
        canvas.unbind("<MouseWheel>")
        win.destroy()
        _notify_settings_win = None
    win.protocol("WM_DELETE_WINDOW", _on_settings_close)
def _set_window_icon(root):
    """设置窗口图标（任务栏+左上角）"""
    try:
        icon_path = get_resource_path(os.path.join("ico", "lbj_icon_final.ico"))
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
            # Windows任务栏图标
            if sys.platform == 'win32':
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("LBJ.Warning.System")
    except Exception:
        pass


# ==================== GUI ====================
root = tk.Tk()
root.title("LBJ列车预警系统解析")
root.geometry("850x800")
_set_window_icon(root)



# 顶部控制区
top_frame = tk.Frame(root)
top_frame.pack(pady=5, fill=tk.X, padx=10)

# 音频设备选择
tk.Label(top_frame, text="🎙️ 音频输入:", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)
device_var = tk.StringVar(value="CABLE Output (VB-Audio Virtual Cable)")
device_combo = ttk.Combobox(top_frame, textvariable=device_var, width=35, font=("Microsoft YaHei", 9))
device_combo['values'] = get_audio_devices()
device_combo.pack(side=tk.LEFT, padx=5)

# 音量条
volume_frame = tk.Frame(top_frame)
volume_frame.pack(side=tk.RIGHT, padx=10)

# 音量条子frame（水平排列）
vol_sub_frame = tk.Frame(volume_frame)
vol_sub_frame.pack(side=tk.TOP)
tk.Label(vol_sub_frame, text="🔊 音量:", font=("Microsoft YaHei", 10)).pack(side=tk.LEFT)
volume_var = tk.IntVar(value=0)
volume_bar = ttk.Progressbar(vol_sub_frame, variable=volume_var, maximum=100, length=120, mode='determinate')
volume_bar.pack(side=tk.LEFT, padx=5)
volume_label = tk.Label(vol_sub_frame, text="0%", font=("Microsoft YaHei", 9), width=4)
volume_label.pack(side=tk.LEFT)

# 查找按钮 - 放在音量条下方，灰色背景，小按钮
# 按钮行：查找+地图，水平排列
btn_row = tk.Frame(volume_frame)
btn_row.pack(side=tk.TOP, pady=(5, 0))

search_btn = tk.Button(btn_row, text="查找", command=lambda: open_search_window(),
                       bg="#d9d9d9", fg="#333333", font=("Microsoft YaHei", 9), width=6, height=1)
search_btn.pack(side=tk.LEFT, padx=(20, 5))

map_btn = tk.Button(btn_row, text="地图", command=lambda: open_map_window(),
                    bg="#d9d9d9", fg="#333333", font=("Microsoft YaHei", 9), width=6, height=1)
map_btn.pack(side=tk.LEFT, padx=(0, 0))



# 按钮区（保持原样）
btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

btn_start = tk.Button(btn_frame, text="▶ 开始解码", command=start_decoder,
                      bg="#28a745", fg="white", font=("Microsoft YaHei", 11), width=12)
btn_start.pack(side=tk.LEFT, padx=5)

btn_stop = tk.Button(btn_frame, text="⏹ 停止解码", command=stop_decoder,
                     bg="#dc3545", fg="white", font=("Microsoft YaHei", 11), width=12)
btn_stop.pack(side=tk.LEFT, padx=5)



# 输出区
output = ScrolledText(root, font=("Consolas", 11), wrap=tk.WORD)
output.pack(expand=True, fill="both", padx=10, pady=5)

# ==================== 查找功能 ====================
search_window = None
search_matches = []
search_current_idx = -1
search_entry_global = None
search_type_var_global = None
_csv_pending_records = []  # CSV写入失败时的缓存队列
_load_pending_cache()  # 启动时加载持久化缓存

SEARCH_PATTERNS = {
    "车次": r'车次:\s*(\S+)',
    "车型": r'车型:\s*([^|]+)',
    "车号": r'车号:\s*([^|]+)',
    "线路": r'线路:\s*([^\n]+)',
    "方向": r'方向:\s*(\S+)',
    "类型": r'类型:\s*([^\n]+)',
    "时间": r'时间:\s*([^\n]+)',
    "公里标": r'公里标:\s*([^\n]+)',
}

SEARCH_HINTS = {
    "车次": "请输入车次  如：Y752",
    "车型": "请输入车型  如：HXD1C",
    "车号": "请输入车号  如：0053",
    "线路": "请输入线路  如：南昆线",
    "方向": "请输入方向  上行或下行",
    "类型": "请输入类型  如：快速旅客列车",
    "时间": "请输入时间  如：2026年6月27日",
    "公里标": "请输入公里标  如：185.1",
}

def do_search_all():
    """模块级查找函数：查找窗口开着时自动刷新高亮"""
    global search_matches, search_current_idx, search_window, search_entry_global, search_type_var_global

    # 如果没有查找窗口或没有保存的引用，直接返回
    if search_window is None or not search_window.winfo_exists():
        return
    if search_entry_global is None or search_type_var_global is None:
        return

    output.tag_remove("search_highlight", "1.0", tk.END)
    output.tag_remove("search_current", "1.0", tk.END)
    search_matches = []
    search_current_idx = -1

    keyword = search_entry_global.get().strip()
    if not keyword:
        return

    search_type = search_type_var_global.get()

    prefix_map = {
        "车次": "车次: ",
        "车型": "车型: ",
        "车号": "车号: ",
        "线路": "线路: ",
        "方向": "方向: ",
        "类型": "类型: ",
        "时间": "时间: ",
        "公里标": "公里标: ",
    }
    search_prefix = prefix_map.get(search_type, "")

    start_pos = "1.0"
    while True:
        pos = output.search(search_prefix, start_pos, tk.END)
        if not pos:
            break

        line_start = f"{pos.split('.')[0]}.0"
        line_end = f"{pos.split('.')[0]}.end"
        line_text = output.get(line_start, line_end)

        if search_prefix in line_text:
            # 使用Text widget的search方法配合count选项获取准确匹配长度
            # 避免手动计算索引导致的emoji偏移问题
            line_num = pos.split('.')[0]
            prefix_start_col = int(pos.split('.')[1])
            prefix_end_col = prefix_start_col + len(search_prefix)

            # 在值文本中搜索关键字
            value_text = line_text[line_text.find(search_prefix) + len(search_prefix):]

            # 时间类型：支持多种格式匹配（如2026年6月27日、2026.6.27也能匹配2026-06-27）
            if search_type == "时间":
                import re
                # 将用户输入的关键字标准化为YYYY-MM-DD格式用于匹配
                def normalize_date(text):
                    # 匹配 2026年6月27日 或 2026.6.27 或 2026-06-27 等格式
                    patterns = [
                        r'(\d{4})[年\-/](\d{1,2})[月\-/](\d{1,2})[日]?',
                        r'(\d{4})\.(\d{1,2})\.(\d{1,2})',
                    ]
                    for p in patterns:
                        m = re.match(p, text.strip())
                        if m:
                            return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
                    return text

                normalized_kw = normalize_date(keyword)
                # 在值文本中查找标准化后的日期
                search_offset = 0
                while True:
                    # 先尝试直接匹配
                    kw_pos = value_text.find(keyword, search_offset)
                    if kw_pos == -1:
                        # 直接匹配失败，尝试标准化后匹配
                        kw_pos = value_text.find(normalized_kw, search_offset)
                        if kw_pos == -1:
                            break
                        match_len = len(normalized_kw)
                    else:
                        match_len = len(keyword)
                    # 基于Text内部列号计算关键字位置
                    kw_start_col = prefix_end_col + kw_pos
                    kw_end_col = kw_start_col + match_len
                    match_start = f"{line_num}.{kw_start_col}"
                    match_end = f"{line_num}.{kw_end_col}"
                    search_matches.append((match_start, match_end))
                    output.tag_add("search_highlight", match_start, match_end)
                    search_offset = kw_pos + match_len
            else:
                search_offset = 0
                # 车次类型：不区分大小写匹配
                if search_type == "车次":
                    search_kw = keyword.lower()
                    search_text = value_text.lower()
                else:
                    search_kw = keyword
                    search_text = value_text
                while True:
                    kw_pos = search_text.find(search_kw, search_offset)
                    if kw_pos == -1:
                        break
                    # 基于Text内部列号计算关键字位置（用原始文本长度）
                    kw_start_col = prefix_end_col + kw_pos
                    kw_end_col = kw_start_col + len(keyword)
                    match_start = f"{line_num}.{kw_start_col}"
                    match_end = f"{line_num}.{kw_end_col}"
                    search_matches.append((match_start, match_end))
                    output.tag_add("search_highlight", match_start, match_end)
                    search_offset = kw_pos + len(search_kw)

        start_pos = f"{int(pos.split('.')[0]) + 1}.0"

    output.tag_config("search_highlight", background="#ffff00", foreground="#000000")
    output.tag_config("search_current", background="#ff6600", foreground="#ffffff")

    if search_matches:
        search_current_idx = 0
        start, end = search_matches[0]
        output.tag_add("search_current", start, end)
        output.see(start)
        search_window.title(f"查找 - 找到 {len(search_matches)} 个结果")
    else:
        search_window.title("查找 - 未找到结果")


def open_search_window():
    global search_window
    load_locomotive_types()  # 重新加载车型库

    if search_window is not None and search_window.winfo_exists():
        search_window.lift()
        search_window.focus_force()
        return

    search_window = tk.Toplevel(root)
    search_window.title("查找")
    search_window.geometry("400x190")
    search_window.resizable(False, False)
    search_window.transient(root)
    # 设置查找窗口图标（避免显示默认Python图标）
    try:
        icon_path = get_resource_path(os.path.join("ico", "lbj_icon_final.ico"))
        if os.path.exists(icon_path):
            search_window.iconbitmap(icon_path)
    except:
        pass

    # 让第1列可以扩展，保持输入框和类型选择框对齐
    search_window.grid_columnconfigure(1, weight=1)

    tk.Label(search_window, text="查找内容:", font=("Microsoft YaHei", 10)).grid(row=0, column=0, padx=10, pady=10, sticky="w")

    search_entry = tk.Entry(search_window, font=("Microsoft YaHei", 13), width=25)
    search_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

    hint_label = tk.Label(search_window, text="请输入车次  如：Y752", font=("Microsoft YaHei", 10), fg="#999")
    hint_label.place(in_=search_entry, x=5, y=0)

    tk.Label(search_window, text="查找类型:", font=("Microsoft YaHei", 10)).grid(row=1, column=0, padx=10, pady=5, sticky="w")

    search_type_var = tk.StringVar(value="车次")

    # 保存全局引用，用于新数据到达时自动刷新查找
    global search_entry_global, search_type_var_global
    search_entry_global = search_entry
    search_type_var_global = search_type_var

    type_combo = ttk.Combobox(search_window, textvariable=search_type_var,
                               values=["车次", "车型", "车号", "线路", "方向", "类型", "时间", "公里标"],
                               font=("Microsoft YaHei", 10), width=15, state="readonly")
    type_combo.grid(row=1, column=1, padx=5, pady=5, sticky="w")

    # === 列车类型下拉框（仅在查找类型为"类型"时启用）===
    TRAIN_TYPES = [
        "直达特快", "特快旅客列车", "快速旅客列车", "临时旅客列车", "旅游列车",
        "普通快车", "普通快车(管内)", "管内快速", "普通慢车", "普通慢车(管内)",
        "通勤列车", "动车组", "城际动车组", "高速动车组", "市郊列车",
        "摘挂列车", "小运转列车", "货运列车(技术直达)", "货运列车(直通)", "货运列车(区段)",
        "货运列车(直达、五定)", "货运列车(快运直达)", "货运列车(煤炭直达)", "货运列车(石油直达)",
        "货运列车(始发直达)", "货运列车(空车直达)", "货运列车(汽运)", "货运列车(集装箱)",
        "中欧中亚班列(120km/h)", "中欧中亚班列(80km/h)", "铁水联运班列",
        "行包快运专列", "快运货物列车", "行邮特快专列", "特需货物列车", "冷藏列车",
        "普通行包列车", "特殊超限", "超限货运列车", "万吨货物列车",
        "路用列车", "货车单机", "客运单机", "小运转单机", "补机", "试运行列车",
        "轨道车/小型工程车", "救援列车", "工厂自备车",
        "折返", "回送","动车组有火回送", "动车组无火跨局回送", "动车组无火管内回送",
        "跨局回送客车", "管内回送客车", 
        "动车组检测列车", "动车组确认列车", "抢险救灾列车", "特种列车", "未知"
    ]

    train_type_var = tk.StringVar()
    train_type_label = tk.Label(search_window, text="列车类型:", font=("Microsoft YaHei", 10))
    train_type_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
    train_type_combo = ttk.Combobox(search_window, textvariable=train_type_var,
                                       values=TRAIN_TYPES, font=("Microsoft YaHei", 10), width=23, state="disabled")
    train_type_combo.grid(row=2, column=1, padx=5, pady=5, sticky="w")

    def on_train_type_select(event):
        selected = train_type_var.get()
        if selected:
            search_entry.delete(0, tk.END)
            search_entry.insert(0, selected)
            hint_label.place_forget()
            do_search_all()

    train_type_combo.bind("<<ComboboxSelected>>", on_train_type_select)
    # === 列车类型下拉框结束 ===

    def update_hint(*args):
        selected = search_type_var.get()
        hint = SEARCH_HINTS.get(selected, "请输入")
        hint_label.config(text=hint)
        if not search_entry.get():
            hint_label.place(in_=search_entry, x=5, y=0)
        else:
            hint_label.place_forget()
        # 列车类型下拉框控制：仅"类型"时启用并显示，否则禁用隐藏并清空
        if selected == "类型":
            train_type_combo.config(state="readonly")
            train_type_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
            train_type_combo.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        else:
            train_type_combo.config(state="disabled")
            train_type_var.set("")
            train_type_label.grid_remove()
            train_type_combo.grid_remove()
        # 查找类型切换时，自动重新执行查找
        if search_entry.get().strip():
            do_search_all()

    search_type_var.trace_add("write", update_hint)

    def on_entry_focus_in(event):
        hint_label.place_forget()

    def on_entry_focus_out(event):
        if not search_entry.get():
            hint_label.place(in_=search_entry, x=5, y=0)

    search_entry.bind("<FocusIn>", on_entry_focus_in)
    search_entry.bind("<FocusOut>", on_entry_focus_out)

    def on_entry_type(event):
        if search_entry.get():
            hint_label.place_forget()
        else:
            hint_label.place(in_=search_entry, x=5, y=0)

    search_entry.bind("<KeyRelease>", on_entry_type)

    btn_frame_search = tk.Frame(search_window)
    btn_frame_search.grid(row=3, column=0, columnspan=2, pady=15)

    def do_search_next():
        global search_current_idx

        if not search_matches:
            do_search_all()
            return

        if search_current_idx >= 0 and search_current_idx < len(search_matches):
            start, end = search_matches[search_current_idx]
            output.tag_remove("search_current", start, end)

        search_current_idx = (search_current_idx + 1) % len(search_matches)
        start, end = search_matches[search_current_idx]
        output.tag_add("search_current", start, end)
        output.see(start)

        search_window.title(f"查找 - {search_current_idx + 1}/{len(search_matches)}")

    btn_find_all = tk.Button(btn_frame_search, text="查找全部", command=do_search_all,
                              font=("Microsoft YaHei", 9), width=12)
    btn_find_all.pack(side=tk.LEFT, padx=5)

    btn_find_next = tk.Button(btn_frame_search, text="查找下一个", command=do_search_next,
                               font=("Microsoft YaHei", 9), width=12)
    btn_find_next.pack(side=tk.LEFT, padx=5)

    def do_search_prev():
        global search_current_idx

        if not search_matches:
            do_search_all()
            return

        if search_current_idx >= 0 and search_current_idx < len(search_matches):
            start, end = search_matches[search_current_idx]
            output.tag_remove("search_current", start, end)

        search_current_idx = (search_current_idx - 1) % len(search_matches)
        start, end = search_matches[search_current_idx]
        output.tag_add("search_current", start, end)
        output.see(start)

        search_window.title(f"查找 - {search_current_idx + 1}/{len(search_matches)}")

    btn_find_prev = tk.Button(btn_frame_search, text="查找上一个", command=do_search_prev,
                               font=("Microsoft YaHei", 9), width=12)
    btn_find_prev.pack(side=tk.LEFT, padx=5)

    search_entry.bind("<Return>", lambda e: do_search_next())

    def on_search_close():
        global search_window, search_entry_global, search_type_var_global, search_matches, search_current_idx
        output.tag_remove("search_highlight", "1.0", tk.END)
        output.tag_remove("search_current", "1.0", tk.END)
        search_matches = []
        search_current_idx = -1
        search_window.destroy()
        search_window = None
        search_entry_global = None
        search_type_var_global = None

    btn_close = tk.Button(btn_frame_search, text="关闭", command=on_search_close,
                           font=("Microsoft YaHei", 9), width=8)
    btn_close.pack(side=tk.LEFT, padx=5)

    search_window.protocol("WM_DELETE_WINDOW", on_search_close)

    update_hint()
    search_entry.focus_set()


# 底部信息 - 分开两个Label，独立控制样式
bottom_frame = tk.Frame(root)
bottom_frame.pack(pady=5)

# 🐏咩师傅特供 - 大字体，彩色
tk.Label(bottom_frame, text="🐏", font=("Microsoft YaHei", 15), fg="#1A3D7C").pack(side=tk.LEFT)
tk.Label(bottom_frame, text="咩师傅特供", font=("Microsoft YaHei", 12, "bold"), fg="#F2B807").pack(side=tk.LEFT, padx=(0, 15))

# 其他信息 - 小字体，灰色
info = f"""🛤️全局信息缓存780秒 
💾    车次保存: {LOG_DIR} """
tk.Label(bottom_frame, text=info, justify=tk.LEFT, fg="#666", font=("Microsoft YaHei", 9)).pack(side=tk.LEFT)


# ==================== 窗口关闭清理 ====================
def _flush_csv_pending():
    """将缓存按日期分组写入对应文件。主文件被占时写备用文件。"""
    global _csv_pending_records
    if not _csv_pending_records: return True
    def _gd(r):
        t = r.get("时间", "")
        return t[:10] if t and len(t) >= 10 else __import__('datetime').datetime.now().strftime("%Y-%m-%d")
    def _ws(r, p):
        try:
            init_csv()
            with open(p, 'a', newline='', encoding='utf-8-sig') as f:
                w = csv.writer(f)
                w.writerow([str(r.get(k, "")).strip() for k in CSV_HEADER])
                f.flush(); os.fsync(f.fileno())
            return True
        except: return False
    def _wb(r, d):
        bp = os.path.join(LOG_DIR, f"{d}_备用.csv")
        try:
            if not os.path.exists(bp):
                with open(bp, 'w', newline='', encoding='utf-8-sig') as f:
                    csv.writer(f).writerow(CSV_HEADER); f.flush(); os.fsync(f.fileno())
            with open(bp, 'a', newline='', encoding='utf-8-sig') as f:
                w = csv.writer(f)
                w.writerow([str(r.get(k, "")).strip() for k in CSV_HEADER])
                f.flush(); os.fsync(f.fileno())
            return True
        except: return False
    from collections import defaultdict
    bd = defaultdict(list)
    for p in _csv_pending_records: bd[_gd(p)].append(p)
    failed, ft = [], 0
    for ds, rs in bd.items():
        dp = os.path.join(LOG_DIR, f"{ds}.csv")
        for rc in rs:
            if _ws(rc, dp): ft += 1
            elif not _wb(rc, ds): failed.append(rc)
    _csv_pending_records = failed; _save_pending_cache()
    if ft > 0: write_global_log(f"缓存刷新成功: {ft}条, 剩余失败={len(failed)}")
    return len(failed) == 0

def on_closing():
    # 保留系统原生确认框样式，只修改标题和提示文字，并临时置顶避免被程序窗口遮挡
    try:
        previous_topmost = root.attributes("-topmost")
    except tk.TclError:
        previous_topmost = False
    try:
        root.attributes("-topmost", True)
        root.lift()
        root.focus_force()
        root.update_idletasks()
        confirmed = messagebox.askyesno(
            "是否确认",
            "确定要关闭程序吗",
            parent=root,
            icon="warning"
        )
    finally:
        try:
            root.attributes("-topmost", previous_topmost)
        except tk.TclError:
            pass
    if not confirmed:
        return

    """窗口关闭时彻底清理所有子进程，Windows下防卡死"""
    global running, sox_process, sox_vu_process, multimon_process

    # 立刻停止主循环标志，所有循环线程看到就会退出
    running = False

    # 取消所有tkinter延迟定时器，防止root.quit()后还在跑
    for tn in list(pending_display.keys()):
        try:
            root.after_cancel(pending_display[tn]["after_id"])
        except:
            pass
    pending_display.clear()

    # 用taskkill强制杀进程树（/T杀子进程，/F强制），比proc.kill()彻底
    for proc_name in ["sox.exe", "multimon-ng.exe"]:
        try:
            subprocess.Popen(
                f'taskkill /F /T /IM {proc_name}',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except:
            pass

    # 同时杀直接持有的进程句柄（兜底）
    for proc in [multimon_process, sox_process, sox_vu_process]:
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except:
                pass

    # 停止API服务
    threading.Thread(target=_stop_train_api, daemon=True).start()  # 后台关闭，不阻塞

    # 通知日志线程退出
    try:
        _log_queue.put(None, block=False)
    except:
        pass

    # 快速保存CSV缓存（后台线程，不阻塞）
    if _csv_pending_records:
        threading.Thread(target=_flush_csv_pending, daemon=True).start()

    # 启动独立清理进程（杀残留）
    try:
        cleaner_path = os.path.join(BASE_DIR, "cleaner.exe")
        if os.path.exists(cleaner_path):
            subprocess.Popen(
                [cleaner_path, str(os.getpid())],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
    except:
        pass

    # 尝试删除旧文件名
    try:
        old_exe = os.path.join(BASE_DIR, os.path.basename(sys.executable))
        if os.path.exists(old_exe) and os.path.basename(old_exe).lower() != "预警器.exe":
            try_delete_old(old_exe)
    except:
        pass

    write_global_log("程序关闭完成")

    # 用quit()停止mainloop，不destroy()（destroy会等所有after完成，可能阻塞）
    root.quit()

    # 给quit()一点时间，然后强制退出，确保daemon线程和残留句柄不卡cmd
    import time
    pass  # time.sleep已移除
    os._exit(0)
root.protocol("WM_DELETE_WINDOW", on_closing)
root.after(60000, _periodic_train_binding_cache_cleanup)
# 快捷键：Ctrl+Shift+N 打开通知设置
root.bind("<Control-Shift-N>", open_notification_settings)
root.bind("<Control-Shift-M>", open_map_window)
# ==================== 窗口关闭清理结束 ====================


root.mainloop()

# 注释：当前版本10.22.22
# 注释：请智能体在小改动时，如bug修复之类的自动增加当前版本小数点，在大改动时，如添加新功能之类的增加01.0（注意：是修改上一行的版本号，不是修改你输出的文件名）