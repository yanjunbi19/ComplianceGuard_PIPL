import os
import time
import collections
from mitmproxy import ctx, tls, http
# 从环境变量获取日志路径
TLS_PASSTHROUGH_LOG = os.environ.get("PASSTHROUGH_LOG", "tls_passthrough.log")

# =========================================================
# 🚩 核心配置：硬编码白名单
# 只要域名包含在下面列表中，mitmproxy 将直接透传（不做解密）
# 这样 App 就能看到原厂证书，不会弹窗报错。
# =========================================================
ALWAYS_PASSTHROUGH = [
    "wtzw.com",       # 核心业务域名（必须透传以保住登录和通网）
    "qm989.com",      # 广告域名
    "qq.com",         # 腾讯系（极强校验）
    "tencent.com",
    "qlogo.cn",
    "gtimg.cn",
    "kuaishou.com",   # 快手 SDK
    "e.kuaishou.com",
    "mob.com",        # Mob 统计
    "umeng.com",      # 友盟
    "amap.com",       # 高德地图
    "alicdn.com"      # 阿里 CDN
]

class MaybeTls:
    def __init__(self):
        # 存储握手失败的历史记录，自动学习需要透传的域名
        self.history = set()

    def tls_clienthello(self, data: tls.ClientHelloData):
        """
        当客户端（App）尝试发起 TLS 连接时触发
        """
        sni = data.client_hello.sni
        if not sni:
            return

        # 策略 1: 检查是否在硬编码白名单中
        is_whitelisted = any(domain in sni for domain in ALWAYS_PASSTHROUGH)
        
        # 策略 2: 检查是否在失败历史中
        was_failed = (sni in self.history)

        if is_whitelisted or was_failed:
            ctx.log.info(f"直接透传 (Whitelist/History): {sni}")
            # 🚩 关键指令：告诉 mitmproxy 忽略此连接，不做中间人截解
            data.ignore_connection = True
            self.write_log(f"TLS Passthrough (Immediate): {sni}")

    def tls_failed_client(self, data: tls.TlsData):
        """
        如果握手失败（即使不在白名单），记录下来，下次直接透传
        """
        sni = data.conn.sni
        if sni:
            self.history.add(sni)
            ctx.log.warn(f"TLS 握手失败，已记录并加入下次透传名单: {sni}")
            self.write_log(f"TLS Failure (Recorded): {sni}")

    def tls_established_client(self, data: tls.TlsData):
        """
        握手成功记录
        """
        sni = data.conn.sni
        if sni:
            self.write_log(f"TLS Success: {sni}")

    def response(self, flow: http.HTTPFlow):
        # 1. 获取 Content-Type（如 image/jpeg, video/mp4）
        content_type = flow.response.headers.get("Content-Type", "").lower()
        
        # 2. 定义需要剔除的媒体类型
        # image: 图片, video: 视频, audio: 音频, application/octet-stream: 通常是二进制流
        media_types = ["image", "video", "audio", "octet-stream"]
        # 3. 如果匹配到媒体类型，或者 URL 以常见的媒体后缀结尾
        is_media = any(m in content_type for m in media_types)
        
        # 额外检查一些常见的静态资源后缀（防止 Header 不准）
        path = flow.request.path.lower()
        is_media_extension = any(path.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".gif", ".mp4", ".webm", ".zip", ".rar"])
        if is_media or is_media_extension:
            # 这里的操作是关键：
            # 将响应体清空，这样存盘的时候就不会占用空间
            original_size = len(flow.response.content) if flow.response.content else 0
            flow.response.content = b"Content Stripped by Script" # 替换为空白或简单字符串
   

    def write_log(self, log_msg):
        with open(TLS_PASSTHROUGH_LOG, "a", encoding='utf-8') as f:
            f.write(f"{log_msg}, {time.time()}\n")

# 注册插件
addons = [MaybeTls()]
