import os
import time
import subprocess
import logging
from datetime import datetime
import psutil
import socket
import sys
current_file_path = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_file_path))
if project_root not in sys.path:
    sys.path.append(project_root)

logger = logging.getLogger(__name__)
import os
import config
# 在 Monitor 类的方法内或外部定义脚本所在的绝对目录
# 获取当前文件（monitor.py）所在的目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# 配置参数
#MITMPROXY_PORT = config.MITM_PORT_BY_DEVICE
MITMPROXY_PORT = 8080
REMOTE_TCPDUMP_PATH = "/data/local/tmp/tcpdump"


class Monitor:
    """
    完善后的网络监控类
    使用 adb reverse 隧道技术，确保模拟器 100% 连通网络
    """

    def __init__(self, package_name, app_name, device_address, output_base_dir, algo=None):
        self.package_name = package_name
        self.app_name = app_name
        self.device_address = device_address
        self.algo = algo
        self.output_base_dir = output_base_dir

        # 监控状态
        self.is_monitoring = False
        self.mitm_process = None
        self.tcpdump_pid = None
        self.start_time = None

        # 文件路径
        self.pcap_file = None
        self.mitm_file = None
        self.mitm_log = None
        self.tls_log = None

        logger.info(f"✅ Monitor 初始化完成: {package_name} (设备: {device_address})")

    def _setup_adb_reverse(self):
        """强制建立隧道并检查结果"""
        try:
            adb_cmd = ["adb", "-s", self.device_address]
            # 1. 先清理
            subprocess.run(adb_cmd + ["reverse", "--remove-all"], capture_output=True)
            # 2. 建立隧道
            result = subprocess.run(
                adb_cmd + ["reverse", f"tcp:{MITMPROXY_PORT}", f"tcp:{MITMPROXY_PORT}"],
                capture_output=True, text=True
            )
            # 3. 验证
            check = subprocess.run(adb_cmd + ["reverse", "--list"], capture_output=True, text=True)
            if f"tcp:{MITMPROXY_PORT}" in check.stdout:
                logger.info("✅ ADB 隧道建立成功")
                return True
            else:
                logger.error(f"❌ 隧道验证失败！输出: {check.stdout}")
                return False
        except Exception as e:
            logger.error(f"❌ 隧道建立异常: {e}")
            return False

    def _remove_adb_reverse(self):
        """清理 ADB 逆向转发"""
        try:
            logger.info("🧹 清除 adb reverse 规则...")
            subprocess.run(["adb", "-s", self.device_address, "reverse", "--remove-all"], capture_output=True,
                           timeout=5)
        except Exception as e:
            logger.warning(f"⚠️ 清除 adb reverse 失败: {e}")

    def start_monitoring(self, stage=1):
        """启动网络监控"""
        try:
            logger.info(f"🚀 启动网络监控 (阶段 {stage})...")
            os.makedirs(self.output_base_dir, exist_ok=True)

            suffix = f"-{stage}"
            self.pcap_file = f"/data/local/tmp/{self.package_name}{suffix}.pcap"
            self.mitm_file = os.path.join(self.output_base_dir, f"mitmdump{suffix}.mitm")
            self.mitm_log = os.path.join(self.output_base_dir, f"mitmdump{suffix}.log")
            self.tls_log = os.path.join(self.output_base_dir, f"tls_passthrough{suffix}.log")

            # 1. 彻底清理残留进程
            self._kill_port_process(MITMPROXY_PORT)

            # 2. 设置 adb reverse (最关键的一步)
            if not self._setup_adb_reverse():
                logger.error("❌ 无法建立 ADB 隧道，监控停止")
                return False

            # 3. 启动 mitmproxy (开启透明模式以配合 Frida)
            if not self._start_mitmproxy():
                logger.error("❌ mitmproxy 启动失败")
                self._remove_adb_reverse()
                return False

            if not self._start_tcpdump():
                logger.error("❌ tcpdump 启动失败")

            # 5. 验证连通性
            if not self._verify_proxy_connection():
                logger.warning("⚠️ 代理验证未完全通过，可能是证书校验问题，继续监控...")

            self.is_monitoring = True
            self.start_time = time.time()
            return True

        except Exception as e:
            logger.error(f"❌ 启动监控失败: {e}", exc_info=True)
            self._cleanup()
            return False

    def _start_mitmproxy(self):
        """启动 mitmproxy"""
        try:
            env = os.environ.copy()
            env['PASSTHROUGH_LOG'] = self.tls_log
            # 记录 SSL 密钥日志，方便 Wireshark 解密
            env['SSLKEYLOGFILE'] = self.tls_log

            cmd = [
                "mitmdump",
                "--listen-host", "0.0.0.0",
                "--listen-port", str(MITMPROXY_PORT),
                "-w", self.mitm_file,
                "--ssl-insecure",
                "--set", "block_global=false",
                "--set", "validate_inbound_headers=false",
                "--ignore-hosts", "^(amdcopen\.m\.taobao\.com|127\.0\.0\.1|localhost)",
            ]
            # 加载外部脚本
            script_name ="tls_passthrough.py"
            # 拼接成绝对路径
            script_path = os.path.join(current_dir, script_name)

            if os.path.exists(script_path):
                cmd.extend(["-s", script_path])
                logger.info(f"➕ 已检测到插件并加载: {script_name}")
            else:
                logger.warning(f"⚠️ 未找到插件脚本: {script_path}")

            logger.info(f"📝 启动 mitmdump: {' '.join(cmd)}")

            log_file = open(self.mitm_log, "w", encoding='utf-8')
            self.mitm_process = subprocess.Popen(
                cmd, stdout=log_file, stderr=subprocess.STDOUT, env=env
            )

            # 等待监听就绪
            for i in range(15):
                if self._check_port_listening(MITMPROXY_PORT):
                    logger.info(f"✅ mitmdump 监听已就绪 (耗时 {i}s)")
                    return True
                if self.mitm_process.poll() is not None:
                    break
                time.sleep(1)

            return False
        except Exception as e:
            logger.error(f"❌ mitmproxy 启动异常: {e}")
            return False

    def _set_device_proxy(self):
        """设置设备代理指向本地环回地址 (127.0.0.1:8080)"""
        PROXY_LOCAL_HOST = "127.0.0.1"
        PROXY_LOCAL_PORT = str(MITMPROXY_PORT)
        
        try:
            # 1. 设置系统代理指向本地 127.0.0.1:8080
            logger.info(f"不设置系统代理到 {PROXY_LOCAL_HOST}:{PROXY_LOCAL_PORT}...")
            return True
        except Exception as e:
            logger.error(f"❌ 设置代理失败: {e}")
            return False


    def stop_monitoring(self):
        """停止监控并彻底清理"""
        if not self.is_monitoring:
            return None
        try:
            self._stop_tcpdump()
            self._stop_mitmproxy()
            self._clear_device_proxy()
            self._remove_adb_reverse()
            self._kill_port_process(MITMPROXY_PORT)

            self.is_monitoring = False
            logger.info("✅ 网络监控已停止并清理")
            return {"success": True}
        except Exception as e:
            logger.error(f"❌ 停止监控失败: {e}")
            self._cleanup()
            return {"success": False}

    def _verify_proxy_connection(self):
        """验证代理连接"""
        try:
            # 在模拟器内部测试能否通过 127.0.0.1:8080 访问网页
            test_cmd = f"curl -x http://127.0.0.1:{MITMPROXY_PORT} http://www.baidu.com -I -m 5 -s"
            result = self._adb_shell(test_cmd)
            if "HTTP/" in result:
                logger.info("✅ 代理连通性测试通过")
                return True
            return False
        except:
            return False

    # --- 以下是原有的辅助工具方法，保持不变或做了微调 ---

    def _adb_shell(self, command):
        try:
            cmd = ["adb", "-s", self.device_address, "shell", command]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return result.stdout.strip()
        except:
            return ""

    def _clear_device_proxy(self):
        self._adb_shell("settings delete global http_proxy")
        self._adb_shell("settings delete global global_http_proxy_host")
        self._adb_shell("settings delete global global_http_proxy_port")
        self._adb_shell("settings delete global global_http_proxy_exclusion_list ''")

    def _check_port_listening(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(('127.0.0.1', port)) == 0

    def _kill_port_process(self, port):
        """强力清理残留进程"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if "mitmdump" in proc.info['name'].lower():
                    proc.kill()
            if os.name == 'nt':
                # Windows 环境下清理端口占用
                result = subprocess.run(f'netstat -ano | findstr :{port}', shell=True, capture_output=True, text=True)
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        pid = line.split()[-1]
                        os.system(f'taskkill /F /PID {pid} /T >nul 2>&1')
        except:
            pass

    def _cleanup(self):
        self._stop_mitmproxy()
        self._clear_device_proxy()
        self._remove_adb_reverse()
        self._kill_port_process(MITMPROXY_PORT)
        self.is_monitoring = False

    def _stop_mitmproxy(self):
        if self.mitm_process:
            self.mitm_process.terminate()
            try:
                self.mitm_process.wait(timeout=5)
            except:
                self.mitm_process.kill()
            self.mitm_process = None

    def _start_tcpdump(self):
        try:
            # 1. 检查二进制文件
            if "No such file" in self._adb_shell(f"ls {REMOTE_TCPDUMP_PATH}"):
                logger.error(f"❌ 手机端未找到 tcpdump: {REMOTE_TCPDUMP_PATH}")
                return False
            # 2. 构造命令
            # 建议去掉 nohup，直接使用后台运行符，并确保输出到文件
            # 如果权限允许，甚至可以先 touch 一下文件确保路径可写
            self._adb_shell(f"touch {self.pcap_file} && chmod 666 {self.pcap_file}")
            
            cmd = f"{REMOTE_TCPDUMP_PATH} -i any -s 96 -w {self.pcap_file}"
            # 使用 su -c 启动，并确保它在后台持续运行
            # 注意：在 adb shell 中使用 & 有时需要加 sleep 或特定的重定向
            full_cmd = f"su -c '{cmd} > /dev/null 2>&1 &'"
            self._adb_shell(full_cmd)
            
            # 3. 关键：等待并确认文件是否生成
            time.sleep(2)
            check_file = self._adb_shell(f"ls -l {self.pcap_file}")
            if self.pcap_file in check_file:
                logger.info(f"✅ tcpdump 已启动，文件已创建: {check_file}")
                return True
            else:
                logger.error(f"❌ tcpdump 启动失败：文件 {self.pcap_file} 未生成。检查手机是否 Root？")
                return False
        except Exception as e:
            logger.error(f"❌ _start_tcpdump 异常: {e}")
            return False
            
    def _stop_tcpdump(self):
        try:
            logger.info("🛑 正在停止手机端 tcpdump...")
            # 尝试多种停止方式
            self._adb_shell("pkill -f tcpdump")
            self._adb_shell("su -c 'pkill -f tcpdump'")
            
            # 强制将缓存写入磁盘
            self._adb_shell("sync") 
            time.sleep(2) 
            # 检查文件大小
            file_info = self._adb_shell(f"ls -lh {self.pcap_file}")
            logger.info(f"📊 准备拉取文件信息: {file_info}")
            local_pcap_path = os.path.join(self.output_base_dir, os.path.basename(self.pcap_file))
            
            # 执行 pull
            pull_cmd = ["adb", "-s", self.device_address, "pull", self.pcap_file, local_pcap_path]
            result = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logger.info(f"✅ pcap 文件已同步到本地: {local_pcap_path}")
                # 拉取成功后再删除
                self._adb_shell(f"rm {self.pcap_file}")
            else:
                logger.error(f"❌ pcap 拉取失败: {result.stderr}")
        except Exception as e:
            logger.error(f"❌ _stop_tcpdump 停止异常: {e}")
