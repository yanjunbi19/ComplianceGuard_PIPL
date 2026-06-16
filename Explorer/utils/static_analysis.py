# utils/static_analysis.py

import os
import re
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from loguru import logger

# =================== 工具函数 ===================

def safe_decode(data):
    """安全地将 bytes 或 str 转为 str"""
    if isinstance(data, str):
        return data
    elif isinstance(data, bytes):
        return data.decode('utf-8', errors='ignore')
    else:
        return str(data)


def parse_descriptor(desc):
    """
    解析 DEX 方法描述符，格式为 (参数)返回值
    示例: (Landroid/content/Context;I)Z → params=[..., int], ret=boolean
    """
    type_map = {
        "V": "void", "Z": "boolean", "B": "byte", "S": "short",
        "C": "char", "I": "int", "J": "long", "F": "float", "D": "double"
    }

    desc = safe_decode(desc).strip()
    match = re.match(r'^\(([^)]*)\)(.*)$', desc)
    if not match:
        return [], "void"

    params_encoded, ret_encoded = match.groups()

    def decode_type(t):
        if t in type_map:
            return type_map[t]
        if t.startswith('L'):
            return t[1:-1].replace('/', '.')  # Ljava/lang/String; → java.lang.String
        if t.startswith('['):
            inner = decode_type(t[1:])
            return inner + '[]'  # [I → int[], [[B → byte[][]
        return t

    param_types = []
    if params_encoded.strip():
        # 匹配基本类型、对象、数组：如 I, Lxxx;, [I, [Ljava/lang/Object;
        tokens = re.findall(r'(\[?L[^;]+;|\[?[ZBSCIJFDV])', params_encoded)
        param_types = [decode_type(t) for t in tokens]

    return_type = decode_type(ret_encoded)
    return param_types, return_type


# =================== 主函数 ===================
_analysis_cache = {}  # 缓存分析结果


def analyze_apk_for_hooks(apk_path):
    """
    对指定 APK 进行静态分析，自动识别敏感方法用于 Frida Hook
    返回: List[Dict] 符合 apimonitor 格式的 hook 列表
    """
    if not os.path.exists(apk_path):
        logger.warning(f"APK file not found: {apk_path}")
        return []

    # 使用文件修改时间作为缓存 key
    mtime = os.path.getmtime(apk_path)
    cache_key = (apk_path, mtime)
    if cache_key in _analysis_cache:
        logger.debug(f"Using cached analysis result for: {apk_path}")
        return _analysis_cache[cache_key]

    hooks = []  # 存储最终 hook 配置

    try:
        logger.info(f"Starting static analysis on: {apk_path}")
        apk = APK(apk_path)

        method_count = 0
        max_methods = 500000  # 防止超大 APK 卡死

        for dex_data in apk.get_all_dex():
            try:
                dex = DalvikVMFormat(dex_data)
            except Exception as e:
                logger.debug(f"Skip DEX due to error: {e}")
                continue

            for method in dex.get_methods():
                if method_count >= max_methods:
                    logger.warning("Reached method limit, stopping early.")
                    break

                try:
                    # === 获取类名 ===
                    class_name = safe_decode(method.get_class_name())
                    if not (class_name.startswith('L') and class_name.endswith(';')):
                        continue
                    class_name = class_name[1:-1].replace('/', '.')

                    # === 获取方法名 ===
                    method_name = safe_decode(method.get_name())
                    if method_name == "<init>":
                        method_name = "$init"
                    elif method_name == "<clinit>":
                        method_name = "$clinit"

                    # === 获取并解析 descriptor ===
                    desc_str = safe_decode(method.get_descriptor())
                    try:
                        params_str, return_str = parse_descriptor(desc_str)
                    except Exception as de:
                        logger.debug(f"Failed to parse descriptor '{desc_str}': {de}")
                        continue

                    # === 过滤无关方法 ===
                    if method_name.endswith("-impl"):
                        continue
                    if "$" in class_name or "$" in method_name:
                        continue
                    if len(method_name) == 0:
                        continue

                    # === 1. Root 检测方法：boolean isRooted(), hasRoot() 等 ===
                    if "root" in method_name.lower() and return_str == "boolean":
                        if not any(x in class_name for x in ["google", "kotlin", "androidx", "support"]):
                            hooks.append({
                                "HookType": "Java",
                                "Category": "Root Detection",
                                "hooks": [{
                                    "clazz": class_name,
                                    "method": method_name
                                }]
                            })
                            logger.debug(f"Found root check: {class_name}.{method_name}")

                    # === 2. 加密方法：encrypt / decrypt ===
                    lower_name = method_name.lower()
                    if ("encrypt" in lower_name or "decrypt" in lower_name):
                        # 至少有一个 String 或 byte[] 参数或返回值
                        crypto_related = (
                            any("String" in p or "byte" in p for p in params_str) or
                            "String" in return_str or "byte" in return_str
                        )
                        if len(params_str) >= 1 and crypto_related:
                            hooks.append({
                                "HookType": "Java",
                                "Category": "Crypto",
                                "hooks": [{
                                    "clazz": class_name,
                                    "method": method_name
                                }]
                            })
                            logger.debug(f"Found crypto method: {class_name}.{method_name}({params_str}) -> {return_str}")

                    # === 3. WebView 高危接口：addJavascriptInterface ===
                    if method_name == "addJavascriptInterface":
                        hooks.append({
                            "HookType": "Java",
                            "Category": "WebView Risk",
                            "hooks": [{
                                "clazz": class_name,
                                "method": method_name
                            }]
                        })
                        logger.debug(f"Found WebView risk: {class_name}.{method_name}")

                except Exception as e_inner:
                    logger.debug(f"Skip method due to error: {e_inner}")
                    continue

                method_count += 1

        logger.info(f"✅ Static analysis completed. Found {len(hooks)} suspicious methods.")

    except Exception as e:
        logger.exception(f"❌ Static analysis failed: {e}")
        return []

    # 缓存结果
    _analysis_cache[cache_key] = hooks
    return hooks