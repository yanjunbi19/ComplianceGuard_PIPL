import uiautomator2 as u2
from loguru import logger
import time
import subprocess
import functools
import uiautomator2 as u2
from loguru import logger
import time
import subprocess
import functools


class DriverManager:
    """全局驱动管理器 - 稳定模式"""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.__dict__['_driver'] = None
            cls._instance.__dict__['_device_address'] = None
            cls._instance.__dict__['_auto_restart_uia'] = False
        return cls._instance

    def init(self, device_address: str, force_reinit: bool = False, auto_restart_uia: bool = False):
        """初始化驱动"""
        self.__dict__['_device_address'] = device_address
        self.__dict__['_auto_restart_uia'] = auto_restart_uia

        self._ensure_adb_connected()

        if self._driver is not None and not force_reinit:
            return self._driver

        logger.info(f"🚀 连接设备: {device_address}")

        try:
            self.__dict__['_driver'] = u2.connect(device_address)
            self._driver.settings['wait_timeout'] = 10
            self._driver.set_new_command_timeout(300)

            # ✅ 关键修复：确保 AccessibilityService 完全启动
            if not self._wait_accessibility_ready(timeout=15):
                raise RuntimeError("AccessibilityService 未能启动")

            logger.info(f"✅ 驱动初始化完成")

        except Exception as e:
            logger.error(f"❌ 驱动初始化失败: {e}")
            raise

        return self._driver

    def _wait_accessibility_ready(self, timeout=30):
        """
        等待 AccessibilityService 完全就绪
        通过尝试调用 dump_hierarchy 来验证
        """
        logger.info("⏳ 等待 AccessibilityService 就绪...")
        start = time.time()

        while time.time() - start < timeout:
            try:
                # 尝试获取 UI 层次结构（最容易触发 NullPointerException 的操作）
                xml = self._driver.dump_hierarchy(compressed=False)
                if xml and len(xml) > 100:  # 确保返回了有效数据
                    logger.info(f"✅ AccessibilityService 已就绪 (耗时 {time.time() - start:.1f}s)")
                    return True
            except Exception as e:
                err_msg = str(e)
                if "NullPointerException" in err_msg:
                    logger.debug(f"AccessibilityService 尚未就绪，继续等待... ({time.time() - start:.0f}s)")
                else:
                    logger.warning(f"未知错误: {err_msg[:100]}")

            time.sleep(1)

        logger.error("❌ AccessibilityService 启动超时")
        return False

    def _ensure_adb_connected(self):
        """✅ 确保 ADB 连接正常"""
        addr = self._device_address
        if not addr:
            return

        logger.info(f"🔌 确保 ADB 连接: {addr}")

        try:
            # 执行 adb connect
            result = subprocess.run(
                ["adb", "connect", addr],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout + result.stderr
            if "connected" in output.lower() or "already" in output.lower():
                logger.info(f"✅ ADB 已连接: {addr}")
            else:
                logger.warning(f"⚠️ ADB 连接输出: {output.strip()}")

            # 验证连接状态
            time.sleep(0.5)
            if self.check_adb_alive():
                logger.info("✅ ADB 连接验证通过")
            else:
                logger.warning("⚠️ ADB 连接可能不稳定")

        except subprocess.TimeoutExpired:
            logger.error("❌ ADB 连接超时")
        except Exception as e:
            logger.error(f"❌ ADB 连接异常: {e}")

    def check_adb_alive(self):
        """检查 ADB 状态"""
        addr = self._device_address
        try:
            res = subprocess.run(
                ["adb", "-s", addr, "get-state"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return "device" in res.stdout
        except:
            return False

    def _wait_uiautomator_ready(self, timeout=60):
        """等待 UIAutomator 就绪"""
        logger.info(f"⏳ 等待 UIAutomator 就绪...")
        start = time.time()

        while time.time() - start < timeout:
            try:
                _ = self._driver.info
                logger.info(f"✅ UIAutomator 已就绪 (耗时 {time.time() - start:.1f}s)")
                return True
            except:
                time.sleep(1)

        logger.error("❌ UIAutomator 启动超时")
        return False

    def _safe_wrapper(self, func):
        """安全调用装饰器"""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            max_retries = 3
            last_error = None

            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    err_msg = str(e)

                    if any(kw in err_msg for kw in ['NullPointerException', '-32001', 'jsonrpc']):
                        logger.warning(f"⚠️ UIAutomator 异常 ({attempt + 1}/{max_retries})")

                        if self._auto_restart_uia and attempt < max_retries - 1:
                            self._restart_uiautomator()
                            time.sleep(2)
                        else:
                            # 不重启，只等待
                            time.sleep(3)
                    else:
                        if attempt < max_retries - 1:
                            time.sleep(1)

            # 返回默认值或抛出异常
            if func.__name__ == "app_current":
                return {"package": "unknown", "activity": ""}
            if func.__name__ in ["dump_hierarchy", "screenshot"]:
                return None
            if last_error:
                raise last_error
            return None

        return wrapper

    def _restart_uiautomator(self):
        """重启 UIAutomator"""
        if not self._auto_restart_uia:
            return False

        try:
            self._driver.uiautomator.stop()
            time.sleep(0.5)
            self._driver.uiautomator.start()
            return self._wait_uiautomator_ready(timeout=50)
        except Exception as e:
            logger.error(f"重启失败: {e}")
            return False

    # ================= 安全方法 =================
    def safe_dump_hierarchy(self, compressed=False, max_retries=5, retry_interval=2):
        """
        安全获取页面布局
        增加 AccessibilityService 检测
        """
        for attempt in range(max_retries):
            try:
                result = self._driver.dump_hierarchy(compressed=compressed)
                if result and len(result) > 100:  # ✅ 验证返回数据有效
                    return result
                else:
                    logger.warning(f"dump_hierarchy 返回空数据 ({attempt + 1}/{max_retries})")
            except Exception as e:
                err_msg = str(e)
                logger.warning(f"⚠️ dump_hierarchy 失败 ({attempt + 1}/{max_retries}): {err_msg[:80]}")

                # ✅ 如果是 NullPointerException，说明服务未就绪
                if "NullPointerException" in err_msg:
                    logger.warning("检测到 AccessibilityService 异常，等待恢复...")
                    time.sleep(retry_interval * 2)  # 加倍等待时间
                else:
                    time.sleep(retry_interval)

        logger.error("❌ dump_hierarchy 最终失败")
        return None

    def safe_screenshot(self, max_retries=3):
        """安全截图"""
        for attempt in range(max_retries):
            try:
                return self._driver.screenshot()
            except:
                if attempt < max_retries - 1:
                    time.sleep(1)
        return None

    def safe_app_current(self):
        """安全获取当前应用"""
        try:
            return self._driver.app_current()
        except:
            return {"package": "unknown", "activity": ""}

    def shell(self, cmd):
        """执行 shell 命令"""
        if self._driver:
            return self._driver.shell(cmd)
        return ""

    def repair_device_env(self):
        """环境修复 - 只重连 ADB，不重启 UIAutomator"""
        logger.info("🔧 尝试修复环境...")
        self._ensure_adb_connected()

    def __getattr__(self, name):
        driver = self.__dict__.get('_driver')
        if driver is None:
            if self._device_address:
                self.init(self._device_address)
                driver = self._driver
            else:
                raise RuntimeError("Driver not initialized.")
        attr = getattr(driver, name, None)
        if attr is not None:
            return self._safe_wrapper(attr) if callable(attr) else attr
        raise AttributeError(f"No attribute: {name}")

    # 在 driver_manager.py 中添加以下方法
    def ensure_app_running(self, package_name: str, activity_name: str = None, app_env=None):
        """
        确保指定 App 正在运行

        Args:
            package_name: 应用包名
            activity_name: 启动 Activity（可选）
            app_env: RLApplicationEnv 实例（可选，用于刷新状态）

        Returns:
            bool: App 是否正在运行
        """
        try:
            current = self.safe_app_current()
            current_pkg = current.get('package', '')

            # 检查是否已在前台
            if current_pkg == package_name:
                logger.debug(f"✅ App {package_name} 已在前台")
                return True

            # App 不在前台，需要启动
            logger.warning(f"⚠️ App 不在前台 (当前: {current_pkg})，正在启动 {package_name}")

            # 启动 App
            if activity_name:
                self._driver.app_start(package_name, activity_name, wait=True)
            else:
                self._driver.app_start(package_name, wait=True)

            # 等待启动
            time.sleep(2)

            # 验证是否启动成功
            for _ in range(5):
                current = self.safe_app_current()
                if current.get('package', '') == package_name:
                    logger.info(f"✅ App {package_name} 已启动")

                    # 如果提供了 app_env，刷新状态
                    if app_env and hasattr(app_env, 'refreshNewObservation'):
                        try:
                            app_env.refreshNewObservation()
                        except:
                            pass

                    return True
                time.sleep(1)

            logger.error(f"❌ App {package_name} 启动失败")
            return False

        except Exception as e:
            logger.error(f"❌ ensure_app_running 异常: {e}")
            return False

    def app_start(self, package_name: str, activity_name: str = None, wait: bool = True):
        """
        启动 App

        Args:
            package_name: 应用包名
            activity_name: 启动 Activity（可选）
            wait: 是否等待启动完成
        """
        try:
            if activity_name:
                self._driver.app_start(package_name, activity_name, wait=wait)
            else:
                self._driver.app_start(package_name, wait=wait)
            return True
        except Exception as e:
            logger.error(f"❌ 启动 App 失败: {e}")
            return False

    def app_stop(self, package_name: str):
        """停止 App"""
        try:
            self._driver.app_stop(package_name)
            return True
        except Exception as e:
            logger.error(f"❌ 停止 App 失败: {e}")
            return False


def start_uiautomator(device_address="127.0.0.1:5555"):
    """启动并验证 UIAutomator 服务"""
    print(f"🚀 连接设备: {device_address}")

    try:
        d = u2.connect(device_address)
        try:
            d.uiautomator.stop()
            time.sleep(1)
        except:
            pass
        d.uiautomator.start()

        for i in range(60):
            try:
                info = d.info
                return True
            except Exception as e:
                if i % 10 == 0:
                    print(f"   等待中... ({i}s)")
                time.sleep(1)

        logger.error("❌ UIAutomator 启动超时")
        return False

    except Exception as e:
        logger.error(f"❌ 启动失败: {e}")
        return False


# 全局单例
#start_uiautomator("127.0.0.1:5555")

driver_manager = DriverManager()
