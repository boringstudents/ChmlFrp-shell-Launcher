import ipaddress
import json
import logging
import os
import random
import re
import smtplib
import socket
import subprocess
import sys
import threading
import time
import traceback
import glob
import argparse
import getpass
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Tuple, Optional
import html

import psutil
import requests
import urllib3

urllib3.disable_warnings()

# 日志器 - 全局定义
logger = None

# ------------------------------以下为程序信息--------------------
APP_NAME = "CUL-CLI"  # 程序名称
APP_VERSION = "1.6.7"  # 程序版本
PY_VERSION = "3.13.*"  # Python 版本
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Python/{PY_VERSION})"  # 生成统一的 User-Agent


# ------------------------------更新的镜像地址--------------------

def get_mirrors():
    """获取可用的GitHub镜像站点列表"""
    DEFAULT_MIRRORS = [
        "github.tbedu.top",
        "gitproxy.click",
        "github.moeyy.xyz",
        "ghproxy.net",
        "gh.llkk.cc"
    ]
    try:
        response = requests.get("https://api.akams.cn/github")
        response.raise_for_status()
        data = response.json()
        if data.get("code") == 200:
            mirrors = data.get("data", [])
            valid_mirrors = [
                mirror for mirror in mirrors
                if mirror.get("speed", 0) > 1 and ":" not in mirror.get("ip", "")
            ]
            MIRROR_PREFIXES = [
                mirror["url"].replace("https://", "").replace("http://", "").strip()
                for mirror in valid_mirrors
            ]
            return MIRROR_PREFIXES
        else:
            return DEFAULT_MIRRORS
    except:
        return DEFAULT_MIRRORS


def get_absolute_path(relative_path):
    """获取相对于程序目录的绝对路径"""
    return os.path.abspath(os.path.join(os.path.split(sys.argv[0])[0], relative_path))


def get_headers(request_json=False):
    """生成统一的请求头"""
    headers = {'User-Agent': USER_AGENT}
    if request_json:
        headers['Content-Type'] = 'application/json'
    return headers


class CredentialManager:
    @staticmethod
    def save_credentials(username="", password="", token=""):
        """保存凭证到文件"""
        credentials_path = get_absolute_path("credentials.json")
        try:
            credentials = {
                "username": username,
                "password": password,
                "token": token
            }
            with open(credentials_path, 'w') as f:
                json.dump(credentials, f)
        except Exception as e:
            if logger:
                logger.error(f"保存凭证失败: {str(e)}")
            else:
                print(f"保存凭证失败: {str(e)}")

    @staticmethod
    def load_credentials():
        """从文件加载凭证"""
        credentials_path = get_absolute_path("credentials.json")
        try:
            if os.path.exists(credentials_path):
                with open(credentials_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            if logger:
                logger.error(f"加载凭证失败: {str(e)}")
            else:
                print(f"加载凭证失败: {str(e)}")
        return {"username": "", "password": "", "token": ""}


class MessagePush:
    CONFIG_MAP = {
        'qq.com': ('smtp.qq.com', 465),
        '163.com': ('smtp.163.com', 465),
        'aliyun.com': ('smtp.aliyun.com', 465),
        '126.com': ('smtp.126.com', 465),
        'foxmail.com': ('smtp.exmail.qq.com', 465),
        'sina.com': ('smtp.sina.com', 465),
        'sohu.com': ('smtp.sohu.com', 465),
        'yeah.net': ('smtp.yeah.net', 465),
        '21cn.com': ('smtp.21cn.com', 465),
        'vip.qq.com': ('smtp.vip.qq.com', 465),
        '263.net': ('smtp.263.net', 465),
        'exmail.qq.com': ('smtp.exmail.qq.com', 465)
    }

    def __init__(self, sender_email: str, password: str, receiver_email: str,
                 smtp_server: Optional[str] = None, port: Optional[int] = None):
        self.sender_email = sender_email
        self.password = password
        self.receiver_email = receiver_email

        if smtp_server is None or port is None:
            self.smtp_server, self.port = self.auto_detect_config()
        else:
            self.smtp_server = smtp_server
            self.port = port

    @staticmethod
    def get_computer_name() -> str:
        """获取计算机名"""
        return socket.gethostname()

    @staticmethod
    def get_current_time(format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
        """获取当前时间"""
        return datetime.now().strftime(format_str)

    def auto_detect_config(self) -> Tuple[str, int]:
        """根据邮箱地址自动检测SMTP配置"""
        domain = self.sender_email.split('@')[-1].lower()
        for key, value in self.CONFIG_MAP.items():
            if domain.endswith(key):
                return value
        raise ValueError(f"不支持的邮箱服务商: {domain}，请手动配置SMTP信息")

    def send(self, subject: str, body: str) -> Tuple[bool, str]:
        """发送邮件"""
        message = MIMEMultipart()
        message["From"] = self.sender_email
        message["To"] = self.receiver_email
        message["Subject"] = subject

        clean_body = html.unescape(body)
        message.attach(MIMEText(clean_body, "plain", "utf-8"))

        try:
            server = smtplib.SMTP_SSL(self.smtp_server, 465, timeout=15)
            server.login(self.sender_email, self.password)
            server.sendmail(self.sender_email, self.receiver_email, message.as_string())
            server.quit()
            return True, "邮件发送成功"
        except Exception as e465:
            try:
                server = smtplib.SMTP(self.smtp_server, 587, timeout=15)
                server.starttls()
                server.login(self.sender_email, self.password)
                server.sendmail(self.sender_email, self.receiver_email, message.as_string())
                server.quit()
                return True, "邮件发送成功（使用端口 587）"
            except Exception as e:
                return False, f"发送邮件失败: {str(e)}"


class EnterInspector:
    @staticmethod
    def validate_port(port, tyen):
        """端口检查"""
        try:
            port_num = int(port)
            if tyen:
                return 0 < port_num <= 65535
            elif not tyen:
                return 10000 < port_num <= 65535
        except ValueError:
            return False

    @staticmethod
    def remove_http_https(url):
        """去除 http 和 https 头"""
        return re.sub(r'^https?://', '', url)

    @staticmethod
    def parse_srv_target(target):
        """srv解析操作"""
        parts = target.split()
        if len(parts) == 4:
            return parts[0], parts[1], parts[2], parts[3]
        return None, None, None, target

    @staticmethod
    def is_valid_ipv6(ip):
        """IPV6检测"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_valid_domain(domain):
        """域名检测"""
        pattern = re.compile(
            r'^(?!-)[A-Za-z0-9-\u0080-\uffff]{1,63}(?<!-)(\.[A-Za-z\u0080-\uffff]{2,})+$',
            re.UNICODE
        )
        return bool(pattern.match(domain))

    @staticmethod
    def is_valid_ipv4(ip):
        """IPV4检测"""
        pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
        return bool(pattern.match(ip))


class API:
    @classmethod
    def login(cls, username, password):
        """用户登录"""
        if logger:
            logger.info(f"尝试登录用户: {username}")
        url = f"https://cf-v2.uapis.cn/login"
        params = {
            "username": username,
            "password": password
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            response_data = response.json()
            return response_data
        except Exception as content:
            if logger:
                logger.exception("登录API发生错误")
                logger.exception(content)
            return None

    @classmethod
    def get_nodes(cls, max_retries=3, retry_delay=1):
        """获取节点数据"""
        url = "https://cf-v2.uapis.cn/node"
        headers = get_headers()

        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers)
                response.raise_for_status()
                data = response.json()
                if data['code'] == 200:
                    return data['data']
                else:
                    if logger:
                        logger.error(f"获取节点数据失败: {data['msg']}")
                    return []
            except requests.RequestException as content:
                if logger:
                    logger.warning(f"获取节点数据时发生网络错误 (尝试 {attempt + 1}/{max_retries}): {str(content)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    if logger:
                        logger.error("获取节点数据失败，已达到最大重试次数")
                    return []
            except Exception:
                if logger:
                    logger.exception("获取节点数据时发生未知错误")
                return []

    @classmethod
    def is_node_online(cls, node_name=None, tyen=None):
        url = "https://cf-v2.uapis.cn/node_stats"
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()

                if tyen == "online":
                    if stats and 'data' in stats:
                        for node in stats['data']:
                            if node['node_name'] == node_name:
                                return node['state'] == "online"
                elif tyen == "all":
                    if node_name is not None:
                        raise ValueError("当tyen为'all'时，不能传入node_name参数")
                    return stats

            return False
        except Exception:
            if logger:
                logger.exception("检查节点在线状态时发生错误")
            return False

    @classmethod
    def get_user_tunnels(cls, user_token):
        """获取用户隧道列表"""
        url = f"https://cf-v2.uapis.cn/tunnel"
        params = {
            "token": user_token
        }
        headers = get_headers()
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            if data['code'] == 200:
                tunnels = data.get("data", [])
                return tunnels
            else:
                if logger:
                    logger.error(f"{data.get('msg')}")
                return []
        except requests.RequestException:
            if logger:
                logger.exception("获取隧道列表时发生网络错误")
            return []
        except Exception:
            if logger:
                logger.exception("获取隧道列表时发生未知错误")
            return []

    @classmethod
    def userinfo(cls, user_token):
        """用户信息"""
        url = f"https://cf-v2.uapis.cn/userinfo"
        headers = get_headers()
        params = {
            "token": user_token
        }
        try:
            data = requests.get(url, params=params, headers=headers).json()
            return data
        except Exception as content:
            if logger:
                logger.exception("用户信息API发生错误")
                logger.exception(content)
            return None


class TunnelManager:
    def __init__(self, token):
        self.token = token
        self.tunnel_processes = {}
        self.process_lock = threading.Lock()

    def start_tunnel(self, tunnel_info):
        """启动隧道"""
        try:
            if not API.is_node_online(tunnel_info['node'], tyen="online"):
                print(f"警告: 节点 {tunnel_info['node']} 当前不在线")
                return False

            with self.process_lock:
                if tunnel_info['name'] in self.tunnel_processes:
                    if logger:
                        logger.warning(f"隧道 {tunnel_info['name']} 已在运行")
                    return False

                frpc_path = get_absolute_path("frpc.exe")
                cmd = [
                    frpc_path,
                    "-u", self.token,
                    "-p", str(tunnel_info['id'])
                ]

                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )

                self.tunnel_processes[tunnel_info['name']] = process
                if logger:
                    logger.info(f"隧道 {tunnel_info['name']} 启动成功")

                # 启动一个线程来监控隧道输出
                threading.Thread(target=self._monitor_tunnel_output, args=(tunnel_info['name'], process),
                                 daemon=True).start()

                return True

        except Exception as e:
            if logger:
                logger.error(f"启动隧道失败: {str(e)}")
            return False

    def _monitor_tunnel_output(self, tunnel_name, process):
        """监控隧道输出"""
        try:
            for line in iter(process.stdout.readline, b''):
                decoded_line = line.decode('utf-8', errors='replace').rstrip()
                if logger:
                    logger.info(f"[{tunnel_name}] {decoded_line}")

            return_code = process.wait()
            if logger:
                logger.info(f"隧道 {tunnel_name} 已停止, 退出代码: {return_code}")

            with self.process_lock:
                if tunnel_name in self.tunnel_processes:
                    del self.tunnel_processes[tunnel_name]
        except Exception as e:
            if logger:
                logger.error(f"监控隧道输出时发生错误: {str(e)}")

    def stop_tunnel(self, tunnel_name):
        """停止隧道"""
        with self.process_lock:
            try:
                process = self.tunnel_processes.get(tunnel_name)
                if process:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

                    del self.tunnel_processes[tunnel_name]
                    if logger:
                        logger.info(f"隧道 {tunnel_name} 已停止")
                    return True
                else:
                    if logger:
                        logger.warning(f"未找到隧道 {tunnel_name} 的运行进程")
                    return False

            except Exception as e:
                if logger:
                    logger.error(f"停止隧道时发生错误: {str(e)}")
                return False

    def list_running_tunnels(self):
        """列出正在运行的隧道"""
        with self.process_lock:
            return list(self.tunnel_processes.keys())


class CLIApp:
    def __init__(self):
        self.token = None
        self.tunnel_manager = None
        self.mail_notifier = None
        self.load_mail_config()

    def load_mail_config(self):
        """加载邮件配置"""
        settings_path = get_absolute_path("settings.json")
        if os.path.exists(settings_path):
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                mail_config = settings.get('mail', {})
                if mail_config.get('sender_email') and mail_config.get('password'):
                    self.mail_notifier = MessagePush(
                        sender_email=mail_config['sender_email'],
                        password=mail_config['password'],
                        receiver_email=mail_config['sender_email'],
                        smtp_server=mail_config.get('smtp_server'),
                        port=mail_config.get('smtp_port')
                    )

    def send_notification(self, event_type, message, node_name):
        """发送通知"""
        if not self.mail_notifier:
            return

        computer_name = MessagePush.get_computer_name()
        current_time = MessagePush.get_current_time()

        subject_map = {
            "node_online": f"节点上线通知",
            "node_offline": f"节点离线通知",
            "node_added": f"节点上架通知",
            "node_removed": f"节点下架通知",
            "tunnel_offline": f"{node_name}隧道离线通知",
            "tunnel_start": f"{node_name}隧道启动通知"
        }

        subject = f"{APP_NAME} {subject_map.get(event_type, f'系统通知 - {event_type}')}"

        body = f"""
        通知类型：{subject_map.get(event_type, event_type)}
        发生时间：{current_time}
        计算机名称：{computer_name}

        详细信息：
        {message}

        此邮件由 {APP_NAME} v{APP_VERSION} 自动发送
        """

        # 在后台线程中发送邮件
        threading.Thread(
            target=self.mail_notifier.send,
            args=(subject, body),
            daemon=True
        ).start()

    def login(self, username=None, password=None, token=None):
        """登录"""
        if token:
            try:
                data = API.userinfo(token)
                if data['code'] == 200:
                    self.token = token
                    CredentialManager.save_credentials(token=token)
                    print("Token登录成功")
                    return True
                else:
                    print(f"Token登录失败: {data.get('msg', '未知错误')}")
                    return False
            except Exception as e:
                print(f"Token验证失败: {str(e)}")
                return False
        else:
            try:
                data = API.login(username, password)
                if data['code'] == 200:
                    self.token = data['data']['usertoken']
                    CredentialManager.save_credentials(username, password, self.token)
                    print("登录成功")
                    return True
                else:
                    print(f"登录失败: {data.get('msg', '未知错误')}")
                    return False
            except Exception as e:
                print(f"登录请求失败: {str(e)}")
                return False

    def interactive_login(self):
        """交互式登录"""
        print("请选择登录方式:")
        print("1. 用户名密码登录")
        print("2. Token登录")
        choice = input("选择 (1/2): ").strip()

        if choice == "1":
            username = input("用户名/邮箱: ").strip()
            password = getpass.getpass("密码: ")
            return self.login(username=username, password=password)
        elif choice == "2":
            token = input("Token: ").strip()
            return self.login(token=token)
        else:
            print("无效的选择")
            return False

    def display_user_info(self):
        """显示用户信息"""
        if not self.token:
            print("未登录")
            return

        try:
            user_info = API.userinfo(self.token)
            if user_info and user_info['code'] == 200:
                data = user_info['data']
                if data['term'] >= "9999-09-09":
                    data['term'] = "永久有效"

                print(f"\n=== 用户信息 ===")
                print(f"ID: {data['id']}")
                print(f"用户名: {data['username']}")
                print(f"注册时间: {data['regtime']}")
                print(f"邮箱: {data['email']}")
                print(f"实名状态: {data['realname']}")
                print(f"用户组: {data['usergroup']}")
                print(f"国内带宽: {data['bandwidth']} Mbps")
                print(f"国外带宽: {int(data['bandwidth']) * 4} Mbps")
                print(f"隧道数量: {data['tunnelCount']} / {data['tunnel']}")
                print(f"积分: {data['integral']}")
                print(f"到期时间: {data['term']}")
                print(f"上传数据: {data['total_upload'] / 1024 / 1024:.2f}MB")
                print(f"下载数据: {data['total_download'] / 1024 / 1024:.2f}MB")
            else:
                print("无法获取用户信息")
        except Exception as e:
            print(f"获取用户信息失败: {str(e)}")

    def list_tunnels(self):
        """列出所有隧道"""
        if not self.token:
            print("未登录")
            return

        tunnels = API.get_user_tunnels(self.token)
        if not tunnels:
            print("没有隧道")
            return

        print(f"\n=== 隧道列表 ===")
        for i, tunnel in enumerate(tunnels, 1):
            tunnel_type = tunnel.get('type', 'Unknown')
            if tunnel_type in ['http', 'https']:
                remote_info = f"域名: {tunnel.get('dorp', '未绑定')}"
            else:
                remote_info = f"远程端口: {tunnel.get('dorp', 'Unknown')}"

            print(f"{i}. {tunnel['name']}")
            print(f"   类型: {tunnel_type}")
            print(f"   本地: {tunnel['localip']}:{tunnel['nport']}")
            print(f"   {remote_info}")
            print(f"   节点: {tunnel['node']}")
            print(f"   状态: {'运行中' if tunnel['name'] in self.tunnel_manager.list_running_tunnels() else '未启动'}")
            print()

    def start_tunnel_interactive(self):
        """交互式启动隧道"""
        if not self.token:
            print("未登录")
            return

        tunnels = API.get_user_tunnels(self.token)
        if not tunnels:
            print("没有隧道")
            return

        self.list_tunnels()

        try:
            choice = int(input("选择要启动的隧道编号: ")) - 1
            if 0 <= choice < len(tunnels):
                tunnel = tunnels[choice]
                if self.tunnel_manager.start_tunnel(tunnel):
                    print(f"隧道 {tunnel['name']} 启动成功")
                else:
                    print(f"隧道 {tunnel['name']} 启动失败")
            else:
                print("无效的选择")
        except ValueError:
            print("请输入有效的数字")

    def stop_tunnel_interactive(self):
        """交互式停止隧道"""
        if not self.token:
            print("未登录")
            return

        running_tunnels = self.tunnel_manager.list_running_tunnels()
        if not running_tunnels:
            print("没有正在运行的隧道")
            return

        print("\n=== 正在运行的隧道 ===")
        for i, tunnel_name in enumerate(running_tunnels, 1):
            print(f"{i}. {tunnel_name}")

        try:
            choice = int(input("选择要停止的隧道编号: ")) - 1
            if 0 <= choice < len(running_tunnels):
                tunnel_name = running_tunnels[choice]
                if self.tunnel_manager.stop_tunnel(tunnel_name):
                    print(f"隧道 {tunnel_name} 已停止")
                else:
                    print(f"停止隧道 {tunnel_name} 失败")
            else:
                print("无效的选择")
        except ValueError:
            print("请输入有效的数字")

    def create_tunnel_interactive(self):
        """交互式创建隧道"""
        if not self.token:
            print("未登录")
            return

        print("\n=== 创建隧道 ===")
        tunnel_name = input("隧道名称 (留空则随机): ").strip() or ''.join(
            random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8))

        nodes = API.get_nodes()
        if not nodes:
            print("无法获取节点列表")
            return

        print("\n可用节点:")
        for i, node in enumerate(nodes, 1):
            print(f"{i}. {node['name']} - {node['area']}")

        try:
            node_choice = int(input("选择节点编号: ")) - 1
            if not 0 <= node_choice < len(nodes):
                print("无效的选择")
                return
            selected_node = nodes[node_choice]['name']
        except ValueError:
            print("请输入有效的数字")
            return

        print("\n隧道类型:")
        types = ["tcp", "udp", "http", "https"]
        for i, t in enumerate(types, 1):
            print(f"{i}. {t}")

        try:
            type_choice = int(input("选择类型编号: ")) - 1
            if not 0 <= type_choice < len(types):
                print("无效的选择")
                return
            tunnel_type = types[type_choice]
        except ValueError:
            print("请输入有效的数字")
            return

        local_ip = input("本地IP/主机名 (默认: 127.0.0.1): ").strip() or "127.0.0.1"
        local_port = input("本地端口: ").strip()

        if not EnterInspector.validate_port(local_port, True):
            print("无效的端口号")
            return

        if tunnel_type in ["tcp", "udp"]:
            remote_port = input("远程端口 (留空则随机): ").strip() or str(random.randint(10000, 65535))
            if not EnterInspector.validate_port(remote_port, False):
                print("远程端口必须是10000-65535之间的整数")
                return
        else:
            banddomain = input("绑定域名: ").strip()
            if not banddomain:
                print("绑定域名是必须的")
                return

        encryption = input("开启加密? (y/n): ").strip().lower() == 'y'
        compression = input("开启压缩? (y/n): ").strip().lower() == 'y'

        try:
            payload = {
                "token": self.token,
                "tunnelname": tunnel_name,
                "node": selected_node,
                "localip": local_ip,
                "porttype": tunnel_type,
                "localport": int(local_port),
                "encryption": encryption,
                "compression": compression,
                "extraparams": ""
            }

            if tunnel_type in ["tcp", "udp"]:
                payload["remoteport"] = int(remote_port)
            else:
                payload["banddomain"] = banddomain

            headers = get_headers(request_json=True)
            url = "http://cf-v2.uapis.cn/create_tunnel"
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()

            if response_data['code'] == 200:
                print("隧道创建成功!")
            else:
                print(f"隧道创建失败: {response_data.get('msg', '未知错误')}")

        except Exception as e:
            print(f"创建隧道失败: {str(e)}")

    def edit_tunnel_interactive(self):
        """交互式编辑隧道"""
        if not self.token:
            print("未登录")
            return

        tunnels = API.get_user_tunnels(self.token)
        if not tunnels:
            print("没有隧道")
            return

        self.list_tunnels()

        try:
            choice = int(input("选择要编辑的隧道编号: ")) - 1
            if not 0 <= choice < len(tunnels):
                print("无效的选择")
                return

            tunnel = tunnels[choice]
            print(f"\n=== 编辑隧道 '{tunnel['name']}' ===")

            # API版本选择
            print("\nAPI版本选择:")
            print("1. V2 API")
            print("2. V1 API（部分参数可能无法修改）")
            api_choice = input("选择API版本 (1/2): ").strip()
            use_v1_api = (api_choice == "2")

            # 强制修改选项
            force_update = False
            if input("强制修改（删除后重建）？这会导致隧道ID变更 (y/n): ").strip().lower() == 'y':
                force_update = True

            # 基本信息修改
            new_name = input(f"新名称 (留空保持原值 '{tunnel['name']}'): ").strip() or tunnel['name']

            # 节点选择
            nodes = API.get_nodes()
            print("\n可用节点:")
            for i, node in enumerate(nodes, 1):
                print(f"{i}. {node['name']} - {node['area']}")

            try:
                node_choice = input(f"选择新节点编号 (留空保持原值 '{tunnel['node']}'): ").strip()
                if node_choice:
                    node_index = int(node_choice) - 1
                    if 0 <= node_index < len(nodes):
                        new_node = nodes[node_index]['name']
                    else:
                        print("无效的节点选择，保持原值")
                        new_node = tunnel['node']
                else:
                    new_node = tunnel['node']
            except ValueError:
                print("无效的输入，保持原节点")
                new_node = tunnel['node']

            # 其他参数修改
            new_local_ip = input(f"新本地IP (留空保持原值 '{tunnel['localip']}'): ").strip() or tunnel['localip']
            new_local_port = input(f"新本地端口 (留空保持原值 '{tunnel['nport']}'): ").strip() or tunnel['nport']

            if not EnterInspector.validate_port(new_local_port, True):
                print("无效的端口号，保持原值")
                new_local_port = tunnel['nport']

            # 根据隧道类型处理远程端口或域名
            if tunnel['type'] in ['tcp', 'udp']:
                print(f"注意：TCP/UDP隧道的远程端口在批量编辑中将保持原值: {tunnel['dorp']}")
                remote_param = tunnel['dorp']  # 保持原值
            else:
                print(f"注意：HTTP/HTTPS隧道的绑定域名在批量编辑中将保持原值: {tunnel['dorp']}")
                remote_param = tunnel['dorp']  # 保持原值

            # 加密和压缩选项
            encryption = tunnel.get('encryption', False)
            compression = tunnel.get('compression', False)

            if input("修改加密设置? (y/n): ").strip().lower() == 'y':
                encryption = input("开启加密? (y/n): ").strip().lower() == 'y'

            if input("修改压缩设置? (y/n): ").strip().lower() == 'y':
                compression = input("开启压缩? (y/n): ").strip().lower() == 'y'

            # 执行更新
            if force_update:
                # 强制更新：删除后重建
                if use_v1_api:
                    # V1 API删除
                    user_info = API.userinfo(self.token)
                    if user_info and user_info['code'] == 200:
                        user_id = user_info['data']['id']
                        user_token = user_info['data']['usertoken']

                        url = f"http://cf-v1.uapis.cn/api/deletetl.php"
                        params = {
                            "token": user_token,
                            "userid": user_id,
                            "nodeid": tunnel['id'],
                        }
                        headers = get_headers()
                        response = requests.get(url, params=params, headers=headers)
                else:
                    # V2 API删除
                    url = f"http://cf-v2.uapis.cn/deletetunnel"
                    params = {"token": self.token, "tunnelid": tunnel['id']}
                    headers = get_headers()
                    response = requests.post(url, headers=headers, params=params)

                # 创建新隧道
                time.sleep(1)  # 等待删除完成
                payload = {
                    "token": self.token,
                    "tunnelname": new_name,
                    "node": new_node,
                    "localip": new_local_ip,
                    "porttype": tunnel['type'],
                    "localport": int(new_local_port),
                    "encryption": encryption,
                    "compression": compression,
                    "extraparams": tunnel.get('ap', '')
                }

                if tunnel['type'] in ['tcp', 'udp']:
                    payload["remoteport"] = int(remote_param)
                else:
                    payload["banddomain"] = remote_param

                headers = get_headers(request_json=True)
                url = "http://cf-v2.uapis.cn/create_tunnel"
                response = requests.post(url, headers=headers, json=payload)
                response_data = response.json()

                if response_data['code'] == 200:
                    print("隧道强制更新成功（新隧道已创建）")
                else:
                    print(f"强制更新失败: {response_data.get('msg', '未知错误')}")
            else:
                # 普通更新
                if use_v1_api:
                    # V1 API更新
                    user_info = API.userinfo(self.token)
                    if user_info and user_info['code'] == 200:
                        user_id = user_info['data']['id']
                        user_token = user_info['data']['usertoken']

                        url = f"http://cf-v1.uapis.cn/api/cztunnel.php"
                        params = {
                            "usertoken": user_token,
                            "userid": user_id,
                            "tunnelid": tunnel['id'],
                            "type": tunnel['type'],
                            "node": new_node,
                            "name": new_name,
                            "ap": tunnel.get('ap', ''),
                            "dorp": str(remote_param),
                            "localip": new_local_ip,
                            "encryption": encryption,
                            "compression": compression,
                            "nport": str(new_local_port)
                        }
                        headers = get_headers()
                        response = requests.get(url, params=params, headers=headers)
                        response_content = response.text

                        if "success" in response_content.lower():
                            print("隧道更新成功")
                        else:
                            print(f"更新失败: {response_content}")
                else:
                    # V2 API更新
                    payload = {
                        "token": self.token,
                        "tunnelid": tunnel['id'],
                        "tunnelname": new_name,
                        "node": new_node,
                        "localip": new_local_ip,
                        "porttype": tunnel['type'],
                        "localport": int(new_local_port),
                        "encryption": encryption,
                        "compression": compression
                    }

                    if tunnel['type'] in ['tcp', 'udp']:
                        payload["remoteport"] = int(remote_param)
                    else:
                        payload["banddomain"] = remote_param

                    headers = get_headers(request_json=True)
                    url = "http://cf-v2.uapis.cn/update_tunnel"
                    response = requests.post(url, headers=headers, json=payload)
                    response_data = response.json()

                    if response_data['code'] == 200:
                        print("隧道更新成功")
                    else:
                        print(f"更新失败: {response_data.get('msg', '未知错误')}")

        except Exception as e:
            print(f"编辑隧道时发生错误: {str(e)}")

    def batch_edit_tunnels(self):
        """批量编辑隧道"""
        if not self.token:
            print("未登录")
            return

        tunnels = API.get_user_tunnels(self.token)
        if not tunnels:
            print("没有隧道可以编辑")
            return

        self.list_tunnels()

        try:
            selected_tunnels = []
            while True:
                choice = input("选择要编辑的隧道编号（用空格分隔，0表示完成选择）: ").strip()
                if choice == "0":
                    break

                try:
                    indices = [int(i) - 1 for i in choice.split()]
                    for idx in indices:
                        if 0 <= idx < len(tunnels) and tunnels[idx] not in selected_tunnels:
                            selected_tunnels.append(tunnels[idx])
                except ValueError:
                    print("请输入有效的数字")

            if not selected_tunnels:
                print("没有选择任何隧道")
                return

            print(f"\n已选择 {len(selected_tunnels)} 个隧道进行批量编辑")

            # API版本选择
            print("\nAPI版本选择:")
            print("1. V2 API")
            print("2. V1 API（部分参数可能无法修改）")
            api_choice = input("选择API版本 (1/2): ").strip()
            use_v1_api = (api_choice == "2")

            # 强制修改选项
            force_update = False
            if input("强制修改（删除后重建）？这会导致隧道ID变更 (y/n): ").strip().lower() == 'y':
                force_update = True

            # 批量修改选项
            print("\n批量修改选项（留空表示不修改）:")

            # 节点选择
            nodes = API.get_nodes()
            print("\n可用节点:")
            for i, node in enumerate(nodes, 1):
                print(f"{i}. {node['name']} - {node['area']}")

            new_node = None
            node_choice = input("选择新节点编号（留空表示不修改）: ").strip()
            if node_choice:
                try:
                    node_index = int(node_choice) - 1
                    if 0 <= node_index < len(nodes):
                        new_node = nodes[node_index]['name']
                except ValueError:
                    print("无效的节点选择，将保持原值")

            # 其他参数
            new_local_ip = input("新本地IP（留空表示不修改）: ").strip()
            new_local_port = input("新本地端口（留空表示不修改）: ").strip()

            # 加密和压缩选项
            encrypt_choice = input("修改加密设置？1=开启 2=关闭 其他=不修改: ").strip()
            new_encryption = None
            if encrypt_choice == "1":
                new_encryption = True
            elif encrypt_choice == "2":
                new_encryption = False

            compress_choice = input("修改压缩设置？1=开启 2=关闭 其他=不修改: ").strip()
            new_compression = None
            if compress_choice == "1":
                new_compression = True
            elif compress_choice == "2":
                new_compression = False

            # 确认修改
            print("\n即将进行以下修改:")
            if new_node:
                print(f"- 节点: {new_node}")
            if new_local_ip:
                print(f"- 本地IP: {new_local_ip}")
            if new_local_port:
                print(f"- 本地端口: {new_local_port}")
            if new_encryption is not None:
                print(f"- 加密: {'开启' if new_encryption else '关闭'}")
            if new_compression is not None:
                print(f"- 压缩: {'开启' if new_compression else '关闭'}")

            if not any(
                    [new_node, new_local_ip, new_local_port, new_encryption is not None, new_compression is not None]):
                print("没有任何修改")
                return

            if input("确认修改? (y/n): ").strip().lower() != 'y':
                print("取消批量编辑")
                return

            # 执行批量修改
            success_count = 0
            fail_count = 0

            for tunnel in selected_tunnels:
                try:
                    if force_update:
                        # 强制更新逻辑（删除后重建）
                        # 首先删除隧道
                        delete_success = False
                        if use_v1_api:
                            # V1 API删除
                            user_info = API.userinfo(self.token)
                            if user_info and user_info['code'] == 200:
                                user_id = user_info['data']['id']
                                user_token = user_info['data']['usertoken']

                                url = f"http://cf-v1.uapis.cn/api/deletetl.php"
                                params = {
                                    "token": user_token,
                                    "userid": user_id,
                                    "nodeid": tunnel['id'],
                                }
                                headers = get_headers()
                                response = requests.get(url, params=params, headers=headers)
                                delete_success = (response.status_code == 200)
                        else:
                            # V2 API删除
                            url = f"http://cf-v2.uapis.cn/deletetunnel"
                            params = {"token": self.token, "tunnelid": tunnel['id']}
                            headers = get_headers()
                            response = requests.post(url, headers=headers, params=params)
                            delete_success = (response.status_code == 200)

                        if not delete_success:
                            print(f"删除隧道 '{tunnel['name']}' 失败")
                            fail_count += 1
                            continue

                        # 创建新隧道
                        time.sleep(1)  # 等待删除完成
                        payload = {
                            "token": self.token,
                            "tunnelname": tunnel['name'],
                            "node": new_node or tunnel['node'],
                            "localip": new_local_ip or tunnel['localip'],
                            "porttype": tunnel['type'],
                            "localport": int(new_local_port) if new_local_port else tunnel['nport'],
                            "encryption": new_encryption if new_encryption is not None else tunnel.get('encryption',
                                                                                                       False),
                            "compression": new_compression if new_compression is not None else tunnel.get('compression',
                                                                                                          False),
                            "extraparams": tunnel.get('ap', '')
                        }

                        if tunnel['type'] in ['tcp', 'udp']:
                            payload["remoteport"] = int(tunnel['dorp'])
                        else:
                            payload["banddomain"] = tunnel['dorp']

                        headers = get_headers(request_json=True)
                        url = "http://cf-v2.uapis.cn/create_tunnel"
                        response = requests.post(url, headers=headers, json=payload)
                        response_data = response.json()

                        if response_data['code'] == 200:
                            print(f"隧道 '{tunnel['name']}' 强制更新成功")
                            success_count += 1
                        else:
                            print(f"隧道 '{tunnel['name']}' 强制更新失败: {response_data.get('msg', '未知错误')}")
                            fail_count += 1
                    else:
                        # 普通更新
                        if use_v1_api:
                            # V1 API更新
                            user_info = API.userinfo(self.token)
                            if user_info and user_info['code'] == 200:
                                user_id = user_info['data']['id']
                                user_token = user_info['data']['usertoken']

                                url = f"http://cf-v1.uapis.cn/api/cztunnel.php"
                                params = {
                                    "usertoken": user_token,
                                    "userid": user_id,
                                    "tunnelid": tunnel['id'],
                                    "type": tunnel['type'],
                                    "node": new_node or tunnel['node'],
                                    "name": tunnel['name'],
                                    "ap": tunnel.get('ap', ''),
                                    "dorp": str(tunnel['dorp']),
                                    "localip": new_local_ip or tunnel['localip'],
                                    "encryption": new_encryption if new_encryption is not None else tunnel.get(
                                        'encryption', False),
                                    "compression": new_compression if new_compression is not None else tunnel.get(
                                        'compression', False),
                                    "nport": str(new_local_port) if new_local_port else str(tunnel['nport'])
                                }
                                headers = get_headers()
                                response = requests.get(url, params=params, headers=headers)
                                response_content = response.text

                                if "success" in response_content.lower():
                                    print(f"隧道 '{tunnel['name']}' 更新成功")
                                    success_count += 1
                                else:
                                    print(f"隧道 '{tunnel['name']}' 更新失败: {response_content}")
                                    fail_count += 1
                        else:
                            # V2 API更新
                            payload = {
                                "token": self.token,
                                "tunnelid": tunnel['id'],
                                "tunnelname": tunnel['name'],
                                "node": new_node or tunnel['node'],
                                "localip": new_local_ip or tunnel['localip'],
                                "porttype": tunnel['type'],
                                "localport": int(new_local_port) if new_local_port else tunnel['nport'],
                                "encryption": new_encryption if new_encryption is not None else tunnel.get('encryption',
                                                                                                           False),
                                "compression": new_compression if new_compression is not None else tunnel.get(
                                    'compression', False)
                            }

                            if tunnel['type'] in ['tcp', 'udp']:
                                payload["remoteport"] = int(tunnel['dorp'])
                            else:
                                payload["banddomain"] = tunnel['dorp']

                            headers = get_headers(request_json=True)
                            url = "http://cf-v2.uapis.cn/update_tunnel"
                            response = requests.post(url, headers=headers, json=payload)
                            response_data = response.json()

                            if response_data['code'] == 200:
                                print(f"隧道 '{tunnel['name']}' 更新成功")
                                success_count += 1
                            else:
                                print(f"隧道 '{tunnel['name']}' 更新失败: {response_data.get('msg', '未知错误')}")
                                fail_count += 1

                except Exception as e:
                    print(f"更新隧道 '{tunnel['name']}' 时发生错误: {str(e)}")
                    fail_count += 1

            print(f"\n批量编辑完成: {success_count} 个成功, {fail_count} 个失败")

        except Exception as e:
            print(f"批量编辑时发生错误: {str(e)}")

    def delete_tunnel_interactive(self):
        """交互式删除隧道"""
        if not self.token:
            print("未登录")
            return

        tunnels = API.get_user_tunnels(self.token)
        if not tunnels:
            print("没有隧道")
            return

        self.list_tunnels()

        try:
            choice = int(input("选择要删除的隧道编号: ")) - 1
            if 0 <= choice < len(tunnels):
                tunnel = tunnels[choice]
                confirm = input(f"确定要删除隧道 '{tunnel['name']}' 吗? (y/n): ").strip().lower()

                if confirm == 'y':
                    # 尝试使用v2 API删除
                    url = f"http://cf-v2.uapis.cn/deletetunnel"
                    params = {"token": self.token, "tunnelid": tunnel['id']}
                    headers = get_headers()
                    response = requests.post(url, headers=headers, params=params)

                    if response.status_code == 200:
                        print(f"隧道 '{tunnel['name']}' 删除成功")
                    else:
                        # 尝试使用v1 API删除
                        user_info = API.userinfo(self.token)
                        if user_info and user_info['code'] == 200:
                            user_id = user_info['data']['id']
                            user_token = user_info['data']['usertoken']

                            url = f"http://cf-v1.uapis.cn/api/deletetl.php"
                            params = {
                                "token": user_token,
                                "userid": user_id,
                                "nodeid": tunnel['id'],
                            }
                            headers = get_headers()
                            response = requests.get(url, params=params, headers=headers)

                            if response.status_code == 200:
                                print(f"隧道 '{tunnel['name']}' 删除成功 (v1 API)")
                            else:
                                print(f"删除隧道失败: {response.text}")
                        else:
                            print("获取用户信息失败，无法使用v1 API")
            else:
                print("无效的选择")
        except ValueError:
            print("请输入有效的数字")
        except Exception as e:
            print(f"删除隧道时发生错误: {str(e)}")

    def list_domains(self):
        """列出所有域名"""
        if not self.token:
            print("未登录")
            return

        try:
            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {"token": self.token}
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if data['code'] != 200:
                print(f"获取域名列表失败: {data.get('msg', '未知错误')}")
                return

            domains = data['data']
            if not domains:
                print("没有域名")
                return

            print(f"\n=== 域名列表 ===")
            for i, domain in enumerate(domains, 1):
                print(f"{i}. {domain['record']}.{domain['domain']}")
                print(f"   类型: {domain['type']}")
                print(f"   目标: {domain['target']}")
                print(f"   TTL: {domain['ttl']}")
                print(f"   备注: {domain.get('remarks', '无')}")
                print()

        except Exception as e:
            print(f"获取域名列表时发生错误: {str(e)}")

    def create_domain_interactive(self):
        """交互式创建域名"""
        if not self.token:
            print("未登录")
            return

        TTL_OPTIONS = [
            "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
            "1小时", "2小时", "5小时", "12小时", "1天"
        ]

        print("\n=== 创建域名 ===")

        # 获取可用主域名
        try:
            url = "http://cf-v2.uapis.cn/list_available_domains"
            headers = get_headers()
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print("获取主域名列表失败")
                return

            data = response.json()
            if data['code'] != 200:
                print(f"获取主域名失败: {data['msg']}")
                return

            domains = data['data']
            print("可用主域名:")
            for i, domain_info in enumerate(domains, 1):
                print(f"{i}. {domain_info['domain']}")

            domain_choice = int(input("选择主域名编号: ")) - 1
            if not 0 <= domain_choice < len(domains):
                print("无效的选择")
                return

            main_domain = domains[domain_choice]['domain']
        except Exception as e:
            print(f"获取主域名时发生错误: {str(e)}")
            return

        record = input("子域名: ").strip()
        if not record:
            print("子域名不能为空")
            return

        print("\n记录类型:")
        types = ["A", "AAAA", "CNAME", "SRV"]
        for i, t in enumerate(types, 1):
            print(f"{i}. {t}")

        try:
            type_choice = int(input("选择类型编号: ")) - 1
            if not 0 <= type_choice < len(types):
                print("无效的选择")
                return
            record_type = types[type_choice]
        except ValueError:
            print("请输入有效的数字")
            return

        target = input("目标 (IP地址或域名): ").strip()
        if not target:
            print("目标不能为空")
            return

        # 验证目标格式
        if record_type == "A":
            if EnterInspector.is_valid_domain(target):
                # 域名检测，提供解析或切换选项
                choice = input(
                    "您输入了一个域名。您希望如何处理？\n1. 解析为IPv4地址\n2. 切换到CNAME记录\n选择 (1/2): ").strip()
                if choice == "1":
                    try:
                        ip = socket.gethostbyname(target)
                        if EnterInspector.is_valid_ipv4(ip):
                            target = ip
                        elif EnterInspector.is_valid_ipv6(ip):
                            if input("解析结果是IPv6地址。是否要切换到AAAA记录? (y/n): ").strip().lower() == 'y':
                                record_type = "AAAA"
                                target = ip
                            else:
                                print("无法将域名解析为IPv4地址")
                                return
                        else:
                            raise Exception("解析失败")
                    except Exception:
                        if input("无法将域名解析为IP地址。是否要切换到CNAME记录? (y/n): ").strip().lower() == 'y':
                            record_type = "CNAME"
                        else:
                            return
                elif choice == "2":
                    record_type = "CNAME"
                else:
                    print("无效的选择")
                    return
            elif EnterInspector.is_valid_ipv6(target):
                if input("检测到IPv6地址。是否要切换到AAAA记录? (y/n): ").strip().lower() == 'y':
                    record_type = "AAAA"
                else:
                    print("A记录必须使用IPv4地址")
                    return
            elif not EnterInspector.is_valid_ipv4(target):
                print("请输入有效的IPv4地址")
                return

        elif record_type == "AAAA":
            if EnterInspector.is_valid_ipv4(target):
                if input("检测到IPv4地址。是否要切换到A记录? (y/n): ").strip().lower() == 'y':
                    record_type = "A"
                else:
                    print("AAAA记录必须使用IPv6地址")
                    return
            elif EnterInspector.is_valid_domain(target):
                choice = input(
                    "您输入了一个域名。您希望如何处理？\n1. 解析为IPv6地址\n2. 切换到CNAME记录\n选择 (1/2): ").strip()
                if choice == "1":
                    try:
                        ip = socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]
                        if EnterInspector.is_valid_ipv6(ip):
                            target = ip
                        elif EnterInspector.is_valid_ipv4(ip):
                            if input("解析结果是IPv4地址。是否要切换到A记录? (y/n): ").strip().lower() == 'y':
                                record_type = "A"
                                target = ip
                            else:
                                print("无法将域名解析为IPv6地址")
                                return
                        else:
                            raise Exception("解析失败")
                    except Exception:
                        if input("无法将域名解析为IP地址。是否要切换到CNAME记录? (y/n): ").strip().lower() == 'y':
                            record_type = "CNAME"
                        else:
                            return
                elif choice == "2":
                    record_type = "CNAME"
                else:
                    print("无效的选择")
                    return
            elif not EnterInspector.is_valid_ipv6(target):
                print("请输入有效的IPv6地址")
                return

        elif record_type == "CNAME":
            if EnterInspector.is_valid_ipv4(target):
                if input("检测到IPv4地址。是否要切换到A记录? (y/n): ").strip().lower() == 'y':
                    record_type = "A"
                else:
                    print("CNAME记录不能指向IP地址")
                    return
            elif EnterInspector.is_valid_ipv6(target):
                if input("检测到IPv6地址。是否要切换到AAAA记录? (y/n): ").strip().lower() == 'y':
                    record_type = "AAAA"
                else:
                    print("CNAME记录不能指向IP地址")
                    return
            elif not EnterInspector.is_valid_domain(target):
                print("请输入有效的域名")
                return

        elif record_type == "SRV":
            priority = input("优先级 (默认: 10): ").strip() or "10"
            weight = input("权重 (默认: 10): ").strip() or "10"
            port = input("端口: ").strip()

            if not port:
                print("端口不能为空")
                return

            if not all(x.isdigit() and 0 <= int(x) <= 65535 for x in [priority, weight, port]):
                print("优先级、权重和端口必须是0-65535之间的整数")
                return

            # 处理SRV目标
            srv_target = target
            if ':' in srv_target and not srv_target.startswith('['):  # 可能是IPv6
                srv_target = f"[{srv_target}]"

            # 检查目标是否带有端口
            if ':' in srv_target.strip('[]'):
                # 分割目标和端口
                srv_host, srv_port = srv_target.rsplit(':', 1)
                srv_host = srv_host.strip('[]')
                # 如果目标包含端口，提示用户
                if input(f"检测到目标已包含端口 {srv_port}。是否使用该端口? (y/n): ").strip().lower() == 'y':
                    port = srv_port
                srv_target = srv_host

            if not (EnterInspector.is_valid_domain(srv_target) or EnterInspector.is_valid_ipv4(
                    srv_target) or EnterInspector.is_valid_ipv6(srv_target)):
                print("SRV目标必须是有效的域名或IP地址")
                return

            target = f"{priority} {weight} {port} {srv_target}"

        print("\nTTL选项:")
        for i, ttl in enumerate(TTL_OPTIONS, 1):
            print(f"{i}. {ttl}")

        try:
            ttl_choice = int(input("选择TTL编号 (默认: 1): ").strip() or "1") - 1
            if not 0 <= ttl_choice < len(TTL_OPTIONS):
                print("无效的选择")
                return
            ttl = TTL_OPTIONS[ttl_choice]
        except ValueError:
            print("请输入有效的数字")
            return

        remarks = input("备注 (可选): ").strip()

        try:
            url = "http://cf-v2.uapis.cn/create_free_subdomain"
            payload = {
                "token": self.token,
                "domain": main_domain,
                "record": record,
                "type": record_type,
                "ttl": ttl,
                "target": target,
                "remarks": remarks
            }

            headers = get_headers(request_json=True)
            response = requests.post(url, headers=headers, json=payload)
            response_data = response.json()

            if response_data['code'] == 200:
                print("域名创建成功!")
            else:
                print(f"域名创建失败: {response_data['msg']}")
        except Exception as e:
            print(f"创建域名时发生错误: {str(e)}")

    def edit_domain_interactive(self):
        """交互式编辑域名 - 仅允许修改TTL和目标"""
        if not self.token:
            print("未登录")
            return

        try:
            # 获取域名列表
            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {"token": self.token}
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if data['code'] != 200:
                print(f"获取域名列表失败: {data.get('msg', '未知错误')}")
                return

            domains = data['data']
            if not domains:
                print("没有域名")
                return

            # 显示域名列表
            self.list_domains()

            # 选择要编辑的域名
            choice = int(input("选择要编辑的域名编号: ")) - 1
            if not 0 <= choice < len(domains):
                print("无效的选择")
                return

            domain = domains[choice]

            print(f"\n=== 编辑域名 '{domain['record']}.{domain['domain']}' ===")
            print(f"当前类型: {domain['type']}")
            print(f"当前目标: {domain['target']}")
            print(f"当前TTL: {domain['ttl']}")

            # TTL选项
            TTL_OPTIONS = [
                "1分钟", "2分钟", "5分钟", "10分钟", "15分钟", "30分钟",
                "1小时", "2小时", "5小时", "12小时", "1天"
            ]

            print("\nTTL选项:")
            for i, ttl in enumerate(TTL_OPTIONS, 1):
                print(f"{i}. {ttl}")

            try:
                ttl_choice = input(f"选择新TTL编号 (留空保持原值 '{domain['ttl']}'): ").strip()
                if ttl_choice:
                    ttl_index = int(ttl_choice) - 1
                    if 0 <= ttl_index < len(TTL_OPTIONS):
                        new_ttl = TTL_OPTIONS[ttl_index]
                    else:
                        print("无效的TTL选择，保持原值")
                        new_ttl = domain['ttl']
                else:
                    new_ttl = domain['ttl']
            except ValueError:
                print("无效的输入，保持原TTL")
                new_ttl = domain['ttl']

            # 目标修改
            new_target = input(f"新目标 (留空保持原值 '{domain['target']}'): ").strip()
            if not new_target:
                new_target = domain['target']
            else:
                # 验证新目标格式
                record_type = domain['type']
                if record_type == "A":
                    if not EnterInspector.is_valid_ipv4(new_target):
                        print("A记录必须使用IPv4地址")
                        return
                elif record_type == "AAAA":
                    if not EnterInspector.is_valid_ipv6(new_target):
                        print("AAAA记录必须使用IPv6地址")
                        return
                elif record_type == "CNAME":
                    if EnterInspector.is_valid_ipv4(new_target) or EnterInspector.is_valid_ipv6(new_target):
                        print("CNAME记录不能指向IP地址")
                        return
                    elif not EnterInspector.is_valid_domain(new_target):
                        print("请输入有效的域名")
                        return
                elif record_type == "SRV":
                    # 解析当前SRV记录
                    current_priority, current_weight, current_port, current_srv_target = EnterInspector.parse_srv_target(
                        domain['target'])

                    # 询问是否要修改各个部分
                    print(
                        f"当前SRV记录: 优先级={current_priority}, 权重={current_weight}, 端口={current_port}, 目标={current_srv_target}")

                    new_priority = input(f"新优先级 (留空保持原值 '{current_priority}'): ").strip() or current_priority
                    new_weight = input(f"新权重 (留空保持原值 '{current_weight}'): ").strip() or current_weight
                    new_port = input(f"新端口 (留空保持原值 '{current_port}'): ").strip() or current_port
                    new_srv_target = input(
                        f"新目标 (留空保持原值 '{current_srv_target}'): ").strip() or current_srv_target

                    # 验证SRV参数
                    if not all(str(x).isdigit() and 0 <= int(x) <= 65535 for x in [new_priority, new_weight, new_port]):
                        print("优先级、权重和端口必须是0-65535之间的整数")
                        return

                    if not (EnterInspector.is_valid_domain(new_srv_target) or EnterInspector.is_valid_ipv4(
                            new_srv_target) or EnterInspector.is_valid_ipv6(new_srv_target)):
                        print("SRV目标必须是有效的域名或IP地址")
                        return

                    new_target = f"{new_priority} {new_weight} {new_port} {new_srv_target}"

            # 确认修改
            print(f"\n将进行以下修改:")
            if new_ttl != domain['ttl']:
                print(f"TTL: {domain['ttl']} -> {new_ttl}")
            if new_target != domain['target']:
                print(f"目标: {domain['target']} -> {new_target}")

            if new_ttl == domain['ttl'] and new_target == domain['target']:
                print("没有任何修改")
                return

            if input("确认修改? (y/n): ").strip().lower() != 'y':
                print("取消编辑")
                return

            # 执行更新
            try:
                url = "http://cf-v2.uapis.cn/update_free_subdomain"
                payload = {
                    "token": self.token,
                    "domain": domain['domain'],
                    "record": domain['record'],
                    "type": domain['type'],
                    "ttl": new_ttl,
                    "target": new_target,
                    "remarks": domain.get('remarks', '')
                }

                headers = get_headers(request_json=True)
                response = requests.post(url, headers=headers, json=payload)

                if response.status_code == 200:
                    print("域名更新成功")
                else:
                    print(f"更新域名失败: {response.text}")
            except Exception as e:
                print(f"更新域名时发生错误: {str(e)}")

        except ValueError:
            print("请输入有效的数字")
        except Exception as e:
            print(f"编辑域名时发生错误: {str(e)}")

    def delete_domain_interactive(self):
        """交互式删除域名"""
        if not self.token:
            print("未登录")
            return

        try:
            url = f"http://cf-v2.uapis.cn/get_user_free_subdomains"
            params = {"token": self.token}
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()

            if data['code'] != 200:
                print(f"获取域名列表失败: {data.get('msg', '未知错误')}")
                return

            domains = data['data']
            if not domains:
                print("没有域名")
                return

            self.list_domains()

            choice = int(input("选择要删除的域名编号: ")) - 1
            if 0 <= choice < len(domains):
                domain = domains[choice]
                confirm = input(f"确定要删除域名 '{domain['record']}.{domain['domain']}' 吗? (y/n): ").strip().lower()

                if confirm == 'y':
                    url = "http://cf-v2.uapis.cn/delete_free_subdomain"
                    payload = {
                        "token": self.token,
                        "domain": domain['domain'],
                        "record": domain['record']
                    }

                    headers = get_headers(request_json=True)
                    response = requests.post(url, headers=headers, json=payload)

                    if response.status_code == 200:
                        print(f"域名 '{domain['record']}.{domain['domain']}' 删除成功")
                    else:
                        print(f"删除域名失败: {response.text}")
            else:
                print("无效的选择")
        except ValueError:
            print("请输入有效的数字")
        except Exception as e:
            print(f"删除域名时发生错误: {str(e)}")

    def list_nodes(self):
        """列出所有节点状态"""
        try:
            response = API.is_node_online(tyen="all")
            if response and 'data' in response and isinstance(response['data'], list):
                nodes = response['data']
                print(f"\n=== 节点状态 ===")
                for i, node in enumerate(nodes, 1):
                    print(f"{i}. {node['node_name']}")
                    print(f"   状态: {'在线' if node['state'] == 'online' else '离线'}")
                    print(f"   节点组: {node['nodegroup']}")
                    print(f"   带宽使用率: {node['bandwidth_usage_percent']}%")
                    print(f"   CPU使用率: {node['cpu_usage']}%")
                    print()
            else:
                print("获取节点状态失败")
        except Exception as e:
            print(f"获取节点列表时发生错误: {str(e)}")

    def show_node_details(self):
        """显示节点详细信息"""
        try:
            response = API.is_node_online(tyen="all")
            if response and 'data' in response and isinstance(response['data'], list):
                nodes = response['data']
                self.list_nodes()

                choice = int(input("选择要查看详情的节点编号: ")) - 1
                if 0 <= choice < len(nodes):
                    node = nodes[choice]
                    details = f"""
节点名称: {node.get('node_name', 'N/A')}
状态: {'在线' if node.get('state') == 'online' else '离线'}
节点组: {node.get('nodegroup', 'N/A')}
是否允许udp: {'允许' if node.get('udp') == 'true' else '不允许'}
是否有防御: {'有' if node.get('fangyu') == 'true' else '无'}
是否允许建站: {'允许' if node.get('web') == 'true' else '不允许'}
是否需要过白: {'需要' if node.get('toowhite') == 'true' else '不需要'}
带宽使用率: {node.get('bandwidth_usage_percent', 'N/A')}%
CPU使用率: {node.get('cpu_usage', 'N/A')}%
当前连接数: {node.get('cur_counts', 'N/A')}
客户端数量: {node.get('client_counts', 'N/A')}
总流入流量: {self.format_traffic(node.get('total_traffic_in', 0))}
总流出流量: {self.format_traffic(node.get('total_traffic_out', 0))}"""
                    print(details)
                else:
                    print("无效的选择")
            else:
                print("获取节点状态失败")
        except ValueError:
            print("请输入有效的数字")
        except Exception as e:
            print(f"显示节点详情时发生错误: {str(e)}")

    @staticmethod
    def format_traffic(traffic_bytes):
        """格式化流量显示"""
        try:
            traffic_bytes = float(traffic_bytes)
            if traffic_bytes < 1024:
                return f"{traffic_bytes:.2f} B"
            elif traffic_bytes < 1024 * 1024:
                return f"{traffic_bytes / 1024:.2f} KB"
            elif traffic_bytes < 1024 * 1024 * 1024:
                return f"{traffic_bytes / (1024 * 1024):.2f} MB"
            else:
                return f"{traffic_bytes / (1024 * 1024 * 1024):.2f} GB"
        except (ValueError, TypeError):
            return "N/A"

    def get_messages(self):
        """获取系统消息"""
        if not self.token:
            print("未登录")
            return

        try:
            url = f"http://cf-v2.uapis.cn/messages"
            params = {"token": self.token}
            headers = get_headers()
            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 200:
                data = response.json()
                if data['code'] == 200:
                    messages = data.get('data', [])

                    if not messages:
                        print("暂无消息")
                        return

                    print("\n=== 系统消息 ===")
                    for i, message in enumerate(messages, 1):
                        is_global = message.get('quanti') == 'yes'
                        time_str = message.get('time', '').split('T')[0]
                        content = message.get('content', '')

                        print(f"{i}. [{time_str}] {'系统公告' if is_global else '个人通知'}")
                        print(f"   {content}")
                        print()
                else:
                    print(f"获取消息失败: {data.get('msg', '未知错误')}")
            else:
                print(f"网络错误: {response.status_code}")
        except Exception as e:
            print(f"获取消息时发生错误: {str(e)}")

    def clear_frpc_processes(self):
        """清除所有frpc进程"""
        try:
            if sys.platform == "win32":
                os.system('taskkill /f /im frpc.exe')
            else:
                os.system('pkill frpc')
            print("已清除所有frpc进程")
        except Exception as e:
            print(f"清除frpc进程时发生错误: {str(e)}")


def main():
    global logger  # 声明全局变量

    parser = argparse.ArgumentParser(description=f'{APP_NAME} - ChmlFrp CLI Client')
    parser.add_argument('command', nargs='?', help='要执行的命令')
    parser.add_argument('--token', help='直接使用token登录')
    args = parser.parse_args()

    # 设置日志
    try:
        settings_path = get_absolute_path("settings.json")
        if os.path.exists(settings_path):
            with open(settings_path, 'r') as f:
                settings = json.load(f)
                maxBytes = settings.get('log_size_mb', 10) * 1024 * 1024
                backupCount = settings.get('backup_count', 30)
        else:
            maxBytes = 10 * 1024 * 1024
            backupCount = 30
    except Exception:
        maxBytes = 10 * 1024 * 1024
        backupCount = 30

    # 配置日志
    logger = logging.getLogger('CHMLFRP_CLI')
    logger.setLevel(logging.DEBUG)
    file_handler = RotatingFileHandler('CHMLFRP_CLI.log', maxBytes=maxBytes, backupCount=backupCount)
    file_handler.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # 初始化应用
    app = CLIApp()

    # 自动登录
    credentials = CredentialManager.load_credentials()
    if args.token:
        app.login(token=args.token)
    elif credentials.get('token'):
        app.login(token=credentials['token'])
    elif credentials.get('username') and credentials.get('password'):
        app.login(username=credentials['username'], password=credentials['password'])
    else:
        print("未找到保存的登录信息")

    # 初始化隧道管理器
    if app.token:
        app.tunnel_manager = TunnelManager(app.token)

    def show_menu():
        """显示主菜单"""
        print(f"\n{APP_NAME} v{APP_VERSION}")
        print("=====================")
        print("1. 登录")
        print("2. 显示用户信息")
        print("3. 隧道管理")
        print("4. 域名管理")
        print("5. 节点状态")
        print("6. 系统消息")
        print("7. 清除所有frpc进程")
        print("8. 退出")
        print("=====================")

    def tunnel_menu():
        """隧道管理菜单"""
        print("\n隧道管理")
        print("1. 列出所有隧道")
        print("2. 启动隧道")
        print("3. 停止隧道")
        print("4. 创建隧道")
        print("5. 删除隧道")
        print("6. 编辑隧道")
        print("7. 批量编辑隧道")
        print("8. 返回主菜单")

    def domain_menu():
        """域名管理菜单"""
        print("\n域名管理")
        print("1. 列出所有域名")
        print("2. 创建域名")
        print("3. 删除域名")
        print("4. 编辑域名")
        print("5. 返回主菜单")

    # 主循环
    try:
        while True:
            show_menu()
            choice = input("请选择操作: ").strip()

            if choice == "1":
                if not app.interactive_login():
                    continue
                if app.token:
                    app.tunnel_manager = TunnelManager(app.token)

            elif choice == "2":
                app.display_user_info()

            elif choice == "3":
                if not app.token:
                    print("请先登录")
                    continue

                while True:
                    tunnel_menu()
                    tunnel_choice = input("请选择操作: ").strip()

                    if tunnel_choice == "1":
                        app.list_tunnels()
                    elif tunnel_choice == "2":
                        app.start_tunnel_interactive()
                    elif tunnel_choice == "3":
                        app.stop_tunnel_interactive()
                    elif tunnel_choice == "4":
                        app.create_tunnel_interactive()
                    elif tunnel_choice == "5":
                        app.delete_tunnel_interactive()
                    elif tunnel_choice == "6":
                        app.edit_tunnel_interactive()
                    elif tunnel_choice == "7":
                        app.batch_edit_tunnels()
                    elif tunnel_choice == "8":
                        break
                    else:
                        print("无效的选择")

            elif choice == "4":
                if not app.token:
                    print("请先登录")
                    continue

                while True:
                    domain_menu()
                    domain_choice = input("请选择操作: ").strip()

                    if domain_choice == "1":
                        app.list_domains()
                    elif domain_choice == "2":
                        app.create_domain_interactive()
                    elif domain_choice == "3":
                        app.delete_domain_interactive()
                    elif domain_choice == "4":
                        app.edit_domain_interactive()
                    elif domain_choice == "5":
                        break
                    else:
                        print("无效的选择")

            elif choice == "5":
                app.list_nodes()
                if input("查看节点详情? (y/n): ").strip().lower() == 'y':
                    app.show_node_details()

            elif choice == "6":
                app.get_messages()

            elif choice == "7":
                app.clear_frpc_processes()

            elif choice == "8":
                # 清理并退出
                if app.tunnel_manager:
                    for tunnel_name in app.tunnel_manager.list_running_tunnels():
                        app.tunnel_manager.stop_tunnel(tunnel_name)
                print("感谢使用，再见！")
                break

            else:
                print("无效的选择")

    except KeyboardInterrupt:
        print("\n正在退出...")
        if app.tunnel_manager:
            for tunnel_name in app.tunnel_manager.list_running_tunnels():
                app.tunnel_manager.stop_tunnel(tunnel_name)
        sys.exit(0)
    except Exception as e:
        if logger:
            logger.exception("发生错误")
        print(f"发生错误: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()