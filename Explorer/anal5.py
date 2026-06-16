
import base64
import binascii
import bz2
from enum import unique
import gzip
import hashlib
import json
import math
import multiprocessing
import os
import socket
import string
import sys
import urllib
import zlib
from itertools import repeat
from operator import itemgetter
from zipfile import ZipFile
import re
import xmltodict
import shutil
from tqdm import tqdm
import time
import dpkt
import io as oio
from mitmproxy import io, tcp, http
from mitmproxy.exceptions import FlowReadException
from utils.api_analyzer import APIPrivacyAnalyzer
from utils.integrated_analyzer import IntegratedPrivacyAnalyzer
from datetime import datetime
from collections import defaultdict
import pandas as pd




def b64url_to_bytes(s):
    """
    Decode base64url string to bytes (handles missing padding).
    Returns None if decode fails.
    """
    if s is None:
        return None
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            return None
    if not isinstance(s, str):
        s = str(s)

    t = s.strip()
    if not t:
        return None

    pad = (-len(t)) % 4
    if pad:
        t = t + ("=" * pad)

    try:
        return base64.urlsafe_b64decode(t.encode("utf-8"))
    except Exception:
        return None


# ==================== 全局收集器 ====================
LEAK_RECORDS_COLLECTOR = []
LEAK_RECORDS_CONTEXT = {
    "source": "unknown",
    "category_mapping": {}
}

# 新增：API-流量时间关联收集器
API_TRAFFIC_CORRELATIONS = []

_TS_RE = re.compile(r"^\d{14}$")


def is_real_host(host: str) -> bool:
    """
    判断是否是真实的网络域名（而非本地文件路径）
    """
    if not host:
        return False

    # 排除本地文件路径特征
    local_patterns = [
        "/", "\\",  # 路径分隔符
        ".txt", ".json", ".xml", ".db", ".log", ".tmp", ".cache",  # 文件扩展名
        "files-", "fs-", "LOCAL_FILE",  # 本地文件标识
        "CryptoAPI",  # 加密 API 标识
    ]

    for pattern in local_patterns:
        if pattern in host:
            return False

    # 检查是否像域名（包含点）
    if "." in host:
        return True

    # 检查是否是 localhost 或 IP
    if host in ["localhost", "127.0.0.1"]:
        return True

    return False


def generate_leak_by_source_summary(leak_records, app_package, sdk_info=None):
    """
    按来源（APP自身/第三方SDK）统计泄露 - 修复版
    """
    sdk_info = sdk_info or []

    summary = {
        "app_self": {
            "hosts": defaultdict(lambda: {"count": 0, "fields": [], "records": []}),
            "total_count": 0,
            "fields": defaultdict(int),
        },
        "third_party": {
            "sdks": defaultdict(lambda: {
                "sdk_name": "",
                "company": "",
                "category": "",
                "hosts": [],
                "count": 0,
                "fields": [],
                "records": [],
            }),
            "total_count": 0,
            "fields": defaultdict(int),
        },
        "local_file": {  # 新增：本地文件泄露单独统计
            "paths": defaultdict(lambda: {"count": 0, "fields": []}),
            "total_count": 0,
            "fields": defaultdict(int),
        },
        "unknown": {
            "hosts": defaultdict(lambda: {"count": 0, "fields": [], "records": []}),
            "total_count": 0,
            "fields": defaultdict(int),
        },
    }

    for rec in leak_records:
        host = rec.get("host", "Unknown")
        field = rec.get("privacy_field", "")
        source = rec.get("source", "")

        record_brief = {
            "ts": rec.get("ts", ""),
            "field": field,
            "host": host,
            "direction": rec.get("direction", ""),
            "encrypted": rec.get("encrypted", False),
        }

        # 1. 首先判断是否是本地文件
        if source in ("file_buffer", "whole_file", "crypt_direct") or not is_real_host(host):
            summary["local_file"]["paths"][host]["count"] += 1
            if field not in summary["local_file"]["paths"][host]["fields"]:
                summary["local_file"]["paths"][host]["fields"].append(field)
            summary["local_file"]["total_count"] += 1
            summary["local_file"]["fields"][field] += 1
            continue

        # 2. 尝试从域名识别第三方 SDK
        sdk_result = identify_sdk_from_host(host, sdk_info)

        if sdk_result.get("is_third_party"):
            # 第三方 SDK
            sdk_name = sdk_result.get("name", "") or host
            summary["third_party"]["sdks"][sdk_name]["sdk_name"] = sdk_name
            summary["third_party"]["sdks"][sdk_name]["company"] = sdk_result.get("company", "")
            summary["third_party"]["sdks"][sdk_name]["category"] = sdk_result.get("category", "")
            if host not in summary["third_party"]["sdks"][sdk_name]["hosts"]:
                summary["third_party"]["sdks"][sdk_name]["hosts"].append(host)
            summary["third_party"]["sdks"][sdk_name]["count"] += 1
            if field not in summary["third_party"]["sdks"][sdk_name]["fields"]:
                summary["third_party"]["sdks"][sdk_name]["fields"].append(field)
            summary["third_party"]["sdks"][sdk_name]["records"].append(record_brief)

            summary["third_party"]["total_count"] += 1
            summary["third_party"]["fields"][field] += 1

        elif is_internal_host(host, app_package):
            # APP 自身域名
            summary["app_self"]["hosts"][host]["count"] += 1
            if field not in summary["app_self"]["hosts"][host]["fields"]:
                summary["app_self"]["hosts"][host]["fields"].append(field)
            summary["app_self"]["hosts"][host]["records"].append(record_brief)

            summary["app_self"]["total_count"] += 1
            summary["app_self"]["fields"][field] += 1

        else:
            # 未知来源（真实域名但无法识别）
            summary["unknown"]["hosts"][host]["count"] += 1
            if field not in summary["unknown"]["hosts"][host]["fields"]:
                summary["unknown"]["hosts"][host]["fields"].append(field)
            summary["unknown"]["hosts"][host]["records"].append(record_brief)

            summary["unknown"]["total_count"] += 1
            summary["unknown"]["fields"][field] += 1

    # 转换 defaultdict 为 dict
    summary["app_self"]["hosts"] = dict(summary["app_self"]["hosts"])
    summary["app_self"]["fields"] = dict(summary["app_self"]["fields"])
    summary["third_party"]["sdks"] = dict(summary["third_party"]["sdks"])
    summary["third_party"]["fields"] = dict(summary["third_party"]["fields"])
    summary["local_file"]["paths"] = dict(summary["local_file"]["paths"])
    summary["local_file"]["fields"] = dict(summary["local_file"]["fields"])
    summary["unknown"]["hosts"] = dict(summary["unknown"]["hosts"])
    summary["unknown"]["fields"] = dict(summary["unknown"]["fields"])

    return summary


def _parse_ts(ts: str):
    """解析时间戳字符串为 datetime 对象"""
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S")
    except Exception:
        return None


def _ts_to_str(dt: datetime) -> str:
    """将 datetime 对象转换为时间戳字符串"""
    if dt is None:
        return ""
    try:
        return dt.strftime("%Y%m%d%H%M%S")
    except Exception:
        return ""


# ==================== SDK 信息加载 ====================
def load_sdk_info(sdk_info_path: str) -> list:
    """
    加载 sdk_info.json，用于 SDK 识别
    格式: [{"name": "支付宝", "packages": [...], "domains": [...], "category": "...", "company": "..."}]
    """
    if not sdk_info_path or not os.path.exists(sdk_info_path):
        return []

    try:
        with open(sdk_info_path, 'r', encoding='utf-8') as f:
            sdk_data = json.load(f)
        return sdk_data
    except Exception as e:
        print(f"⚠️ 加载 sdk_info.json 失败: {e}")
        return []


def identify_sdk_from_stack(stack: str, sdk_info: list) -> dict:
    """
    从调用栈中识别 SDK

    Args:
        stack: 调用栈字符串
        sdk_info: SDK 信息列表

    Returns:
        dict: SDK 信息 {"name": "...", "company": "...", "category": "...", "is_third_party": bool}
    """
    result = {
        "name": "",
        "company": "",
        "category": "",
        "package": "",
        "is_third_party": False
    }

    if not stack or not sdk_info:
        return result

    # 解析调用栈，提取包名
    lines = stack.split("\n") if isinstance(stack, str) else []
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # 提取类名（格式: at com.example.Class.method(File.java:123)）
        match = re.search(r"at\s+([\w.$]+)\.", line)
        if not match:
            continue

        class_name = match.group(1)

        # 遍历 SDK 信息进行匹配
        for sdk in sdk_info:
            for pkg_prefix in sdk.get("packages", []):
                if class_name.startswith(pkg_prefix):
                    result["name"] = sdk.get("name", "")
                    result["company"] = sdk.get("company", "")
                    result["category"] = sdk.get("category", "")
                    result["package"] = pkg_prefix
                    result["is_third_party"] = True
                    return result

    return result


def identify_sdk_from_host(host: str, sdk_info: list) -> dict:
    """
    从域名识别 SDK

    Args:
        host: 域名
        sdk_info: SDK 信息列表

    Returns:
        dict: SDK 信息
    """
    result = {
        "name": "",
        "company": "",
        "category": "",
        "domain": "",
        "is_third_party": False
    }

    if not host or not sdk_info:
        return result

    host_lower = host.lower()

    for sdk in sdk_info:
        for domain in sdk.get("domains", []):
            if domain.lower() in host_lower or host_lower.endswith("." + domain.lower()):
                result["name"] = sdk.get("name", "")
                result["company"] = sdk.get("company", "")
                result["category"] = sdk.get("category", "")
                result["domain"] = domain
                result["is_third_party"] = True
                return result

    return result


# ==================== UI 事件加载 ====================
def load_ui_events(dumps_pkg_dir: str):
    """
    加载 UI 交互事件数据
    目录结构: dumps/{pkg}/{timestamp}/
    """
    events = []
    if not dumps_pkg_dir or not os.path.isdir(dumps_pkg_dir):
        return events

    for name in os.listdir(dumps_pkg_dir):
        if not _TS_RE.match(name):
            continue
        ui_dir = os.path.join(dumps_pkg_dir, name)
        if not os.path.isdir(ui_dir):
            continue

        xml_path = os.path.join(ui_dir, "xml_at_trigger.xml")
        sem_path = os.path.join(ui_dir, "textual_semantics.json")
        screenshot_path = os.path.join(ui_dir, "screenshot.png")

        ev = {
            "trace_id": name,
            "ts": name,
            "ts_dt": _parse_ts(name),
            "ui": {
                "dir": ui_dir,
                "xml": xml_path if os.path.exists(xml_path) else "",
                "semantics": sem_path if os.path.exists(sem_path) else "",
                "screenshot": screenshot_path if os.path.exists(screenshot_path) else "",
            },
            "op": {
                "text": "",
                "bounds": "",
                "api_name_list": [],
                "action_type": "",
                "widget_class": "",
            }
        }

        # 解析语义化描述
        if ev["ui"]["semantics"]:
            try:
                with open(ev["ui"]["semantics"], "r", encoding="utf-8") as f:
                    sem = json.load(f)
                if isinstance(sem, dict):
                    ev["op"]["text"] = sem.get("op_widget_text", "") or sem.get("op_text", "")
                    ev["op"]["bounds"] = sem.get("op_widget_bounds", "") or sem.get("op_bounds", "")
                    ev["op"]["api_name_list"] = sem.get("api_name_list", [])
                    ev["op"]["action_type"] = sem.get("action_type", "")
                    ev["op"]["widget_class"] = sem.get("widget_class", "")
            except Exception:
                pass

        events.append(ev)

    events.sort(key=lambda x: x.get("ts_dt") or datetime.min)
    return events


# ==================== Frida API 调用加载 ====================
def load_frida_privacy_calls(app_folder: str, sdk_info: list = None):
    """
    读取 permission-1.txt/permission-2.txt 中的敏感 API 调用记录
    """
    calls = []
    sdk_info = sdk_info or []

    for fn in ("permission-1.txt", "permission-2.txt"):
        p = os.path.join(app_folder, fn)
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                ts = obj.get("ts", "")
                stack = obj.get("stack", "")

                # 使用 sdk_info 识别 SDK
                sdk_result = identify_sdk_from_stack(stack, sdk_info)

                calls.append({
                    "ts": ts,
                    "ts_dt": _parse_ts(ts),
                    "category": obj.get("category", ""),
                    "class": obj.get("class", ""),
                    "method": obj.get("method", ""),
                    "api": (str(obj.get("class", "")) + "." + str(obj.get("method", ""))).strip("."),
                    "args": obj.get("args", []),
                    "returnValue": obj.get("returnValue", obj.get("ret", "")),
                    "calledFrom": obj.get("calledFrom", ""),
                    "source_file": fn,
                    "line_no": line_no,
                    "sdk": sdk_result,
                    "raw": obj
                })

    calls.sort(key=lambda c: c.get("ts_dt") or datetime.min)
    return calls


# ==================== 时间窗口匹配 ====================
from bisect import bisect_left, bisect_right


def _calls_in_window(sorted_calls, center_ts: str, pre_s: int = 2, post_s: int = 5):
    """获取时间窗口内的 API 调用"""
    cdt = _parse_ts(center_ts)
    if cdt is None:
        return []
    left_dt = datetime.fromtimestamp(cdt.timestamp() - pre_s)
    right_dt = datetime.fromtimestamp(cdt.timestamp() + post_s)

    dts = [c.get("ts_dt") or datetime.min for c in sorted_calls]
    l = bisect_left(dts, left_dt)
    r = bisect_right(dts, right_dt)
    return sorted_calls[l:r]


def _records_in_window(records, center_ts: str, pre_s: int = 2, post_s: int = 10):
    """获取时间窗口内的泄露记录"""
    cdt = _parse_ts(center_ts)
    if cdt is None:
        return []
    left_dt = datetime.fromtimestamp(cdt.timestamp() - pre_s)
    right_dt = datetime.fromtimestamp(cdt.timestamp() + post_s)

    out = []
    for rec in records or []:
        rts = rec.get("ts", "") or ""
        rdt = _parse_ts(rts)
        if rdt and left_dt <= rdt <= right_dt:
            out.append(rec)
    return out


def _traffic_in_window(traffic_list, center_ts: str, pre_s: int = 2, post_s: int = 10):
    """获取时间窗口内的网络流量"""
    cdt = _parse_ts(center_ts)
    if cdt is None:
        return []
    left_dt = datetime.fromtimestamp(cdt.timestamp() - pre_s)
    right_dt = datetime.fromtimestamp(cdt.timestamp() + post_s)

    out = []
    for item in traffic_list or []:
        tts = item.get("timestamp", "") or ""
        tdt = _parse_ts(tts)
        if tdt and left_dt <= tdt <= right_dt:
            out.append(item)
    return out


# ==================== API-流量时间关联（新增功能）====================
def correlate_api_traffic(frida_calls, traffic_records, leak_records, sdk_info=None, time_window_s=5, max_calls=1000):
    """
    关联 API 调用与网络流量（优化版，添加数量限制）
    """
    correlations = []
    sdk_info = sdk_info or []

    # 限制处理的 API 调用数量，避免卡死
    calls_to_process = frida_calls[:max_calls] if len(frida_calls) > max_calls else frida_calls

    if len(frida_calls) > max_calls:
        print(f"   ⚠️ API 调用数量过多 ({len(frida_calls)})，仅处理前 {max_calls} 条")

    # 如果没有流量记录或泄露记录，直接返回
    if not traffic_records and not leak_records:
        print(f"   ⚠️ 无流量记录或泄露记录，跳过关联分析")
        return correlations

    processed = 0
    for call in calls_to_process:
        call_ts = call.get("ts", "")
        call_dt = call.get("ts_dt")

        if not call_dt:
            continue

        # 查找时间窗口内的流量
        related_traffic = _traffic_in_window(traffic_records, call_ts, pre_s=1, post_s=time_window_s)

        # 查找时间窗口内的泄露
        related_leaks = _records_in_window(leak_records, call_ts, pre_s=1, post_s=time_window_s)

        if not related_traffic and not related_leaks:
            continue

        # 识别流量目标的 SDK
        traffic_sdk_info = []
        for tr in related_traffic[:5]:  # 限制数量
            host = tr.get("host", "")
            if host:
                sdk_result = identify_sdk_from_host(host, sdk_info)
                if sdk_result.get("is_third_party"):
                    traffic_sdk_info.append({
                        "host": host,
                        "sdk": sdk_result
                    })

        correlation = {
            "api_call": {
                "ts": call_ts,
                "api": call.get("api", ""),
                "category": call.get("category", ""),
                "returnValue": safe_str(call.get("returnValue", ""), limit=100),
                "sdk": call.get("sdk", {}),
            },
            "related_traffic": [
                {
                    "ts": tr.get("timestamp", ""),
                    "host": tr.get("host", ""),
                    "path": tr.get("path", "")[:100],  # 限制路径长度
                    "direction": "outbound" if tr.get("direction") == b">" else "inbound",
                }
                for tr in related_traffic[:5]  # 限制数量
            ],
            "related_leaks": [
                {
                    "ts": lr.get("ts", ""),
                    "privacy_field": lr.get("privacy_field", ""),
                    "host": lr.get("host", ""),
                    "encrypted": lr.get("encrypted", False),
                }
                for lr in related_leaks[:5]  # 限制数量
            ],
            "traffic_sdk_info": traffic_sdk_info[:3],  # 限制数量
        }

        correlations.append(correlation)
        processed += 1

        # 限制总关联数量
        if processed >= 500:
            print(f"   ⚠️ 关联数量已达上限 (500)，停止处理")
            break

    return correlations


def calculate_correlation_score(api_call, traffic, leaks):
    """
    计算 API 调用与流量/泄露的关联分数
    """
    score = 0

    # 基础分：有关联流量或泄露
    if traffic:
        score += len(traffic) * 10
    if leaks:
        score += len(leaks) * 20

    # 加分：API 返回值在泄露中出现
    ret_val = str(api_call.get("returnValue", ""))
    if ret_val and len(ret_val) > 5:
        for leak in leaks:
            if ret_val in str(leak.get("value_preview", "")):
                score += 50
                break

    # 加分：SDK 匹配
    api_sdk = api_call.get("sdk", {})
    if api_sdk.get("is_third_party"):
        for tr in traffic:
            host = tr.get("host", "")
            if api_sdk.get("name", "").lower() in host.lower():
                score += 30
                break

    return score


# ==================== 辅助函数 ====================
def safe_str(x, limit=None):
    if x is None:
        s = ""
    elif isinstance(x, str):
        s = x
    elif isinstance(x, bytes):
        try:
            s = x.decode("utf-8")
        except Exception:
            try:
                s = x.decode("latin-1")
            except Exception:
                s = base64.b64encode(x).decode("utf-8", errors="ignore")
    else:
        s = str(x)
    if limit is not None and len(s) > limit:
        return s[: max(0, limit - 3)] + "..."
    return s


def remove(path):
    """ param <path> could either be relative or absolute. """
    if os.path.isfile(path) or os.path.islink(path):
        os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)
    else:
        raise ValueError("file {} is not a file or dir.".format(path))


def has_printable(input, n=33):
    printable_chars = bytes(string.printable, 'ascii')
    for p in [input[i:i + n] for i in range(0, len(input), n)]:
        if all(char in printable_chars for char in p):
            return True
    if input.endswith(b"\x00\x00\x00\x00"):
        return True
    return False


def is_close(a, b, tol=1e-9):
    return abs(a - b) <= tol


def partof(_part, _wholes, t="none"):
    wholes = _wholes if type(_wholes) == list else [_wholes]
    n = 66
    for whole in wholes:
        whole = extract(whole)
        if type(whole) == str:
            whole = whole.encode('utf-8')
        if len(whole) >= 16:
            for _encode_type, part in itemTransformer(_part).items():
                if type(part) == str:
                    part = part.encode('utf-8')
                if part in whole:
                    return True
                for p in [part[i:i + n] for i in range(0, len(part), n)]:
                    if (len(p) > 32 and p in whole):
                        if not all(c == 'A' or c == '=' for c in p):
                            return True
    return False


def is_internal_host(host, app_package):
    """
    判断一个主机名是否可能是应用自身的域名或本地 IP。
    """
    if not host or host in ["Unknown", "LOCAL_FILE_SYSTEM"]:
        return False

    INTERNAL_IPS = ["localhost", "127.0.0.1", "192.168.", "10.42.0.1", "10.0.2.2"]
    if any(host.startswith(ip) for ip in INTERNAL_IPS):
        return True

    if app_package:
        parts = app_package.split('.')[:-1]
        if len(parts) >= 2:
            core_name = parts[-1]
            if core_name in host:
                return True
            if app_package in host:
                return True

    return False


def zip_extract(data, apk=False):
    input_zip = ZipFile(oio.BytesIO(data))
    zip = bytes()
    for name in input_zip.namelist():
        if apk:
            skip_list = ("bmp", "gif", "jpg", "jpeg", "png", "psd", "tif", "tiff", "svg", "webp", "3gp", "avi", "flv",
                         "m4p", "m4v", "mkv", "mov", "mp4", "mpeg",
                         "mpg", "ogg", "ogv", "srt", "webm", "wmv", "aac", "flac", "m3u", "m4a", "mp3", "wav", "wma",
                         "doc", "docx", "odt", "pdf", "rtf", "_metadata")
            if name.endswith(skip_list):
                continue
        zip += extract(input_zip.read(name))
    return zip


def extract(data):
    if len(data) <= 4:
        return data
    if mayBase64(data):
        data = base64.b64decode(data)
    if type(data) == str:
        data = data.encode('utf-8', 'surrogateescape')
    if type(data) != bytes:
        return data
    if all(c < 128 for c in data) and len(re.findall(b"%[0-7][0-9a-fA-F]", data)) > 5:
        data = urllib.parse.unquote(data if type(data) == str else data.decode()).encode('utf-8')
    if data[:3] in (b"\x1F\x8B\x08"):
        try:
            data = gzip.decompress(data)
        except:
            pass
    elif data[:3] in (b"\x42\x5A\x68"):
        try:
            data = bz2.decompress(data)
        except:
            pass
    elif data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        try:
            data = zlib.decompress(data)
        except:
            pass
    elif data[:4] in (b"\x50\x4B\x03\x04", b"\x50\x4B\x07\x08"):
        try:
            data = zip_extract(data)
        except:
            pass
    if type(data) == str:
        data = data.encode('utf-8')
    return data


def mayBase64(s):
    if type(s) == str:
        try:
            s = s.encode('utf-8')
        except:
            return False
    try:
        if base64.b64encode(base64.b64decode(s, validate=True)) == s.rstrip() and len(s) > 6 and (
                (len(s.rstrip(b'=')) % 4 != 0 and s.endswith(b"=")) or (
                not s.endswith(b"=") and (len(s.strip(b'=')) % 4) == 0)) and 6.0 > entropy(s) > 4.1:
            try:
                int(s, 16)
                return False
            except:
                return True
    except Exception:
        return False
    return False


def entropy(string):
    "Calculates the Shannon entropy of a string"
    prob = [float(string.count(c)) / len(string)
            for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy


# ==================== 加密 API 处理 ====================
def cryptoAPI(crypt, crypts, keys, stage):
    res = dict()
    res["stage"] = stage
    res["ts"] = crypt["ts"]
    res["algorithm"] = None
    res["iv"] = None
    res["key"] = None
    res["3rd"] = None
    res["plaintext"] = None
    res["ciphertext"] = None
    res["encrypt"] = None
    res["class_name"] = crypt["class_name"]
    res["method_name"] = crypt["method_name"]
    _input = bytes()
    _output = bytes()

    if res["method_name"] == "doFinal":
        res["3rd"] = False
        key = None
        updates = []
        keys = [key for key in keys if crypt["hashcode"] ==
                key["hashcode"] and crypt["ts"] >= key["ts"]]
        if keys:
            key = max(keys, key=itemgetter("ts"))
        if key:
            res["encrypt"] = True if int(key["args"][0]) == 1 else False
            res["key"] = base64.b64decode(key["args"][1])
            res["iv"] = base64.b64decode(
                key["IV"]) if len(key["IV"]) > 1 else None
            res["algorithm"] = key["algorithm"]
        for i in range(crypts.index(crypt) - 1, -1, -1):
            if crypts[i]["class_name"] == "javax.crypto.Cipher":
                if crypts[i]["hashcode"] == crypt["hashcode"]:
                    if crypts[i]["method_name"] == "doFinal":
                        break
                    else:
                        updates.insert(0, crypts[i])

        for update in updates:
            arg_len = len(update["args"])
            _input += base64.b64decode(update["args"][0])
            if arg_len == 1:
                _output += base64.b64decode(update["ret"])
            if arg_len == 2:
                _output += base64.b64decode(update["args"][1])
            elif arg_len == 3:
                _output += base64.b64decode(update["ret"])[:int(update["args"][2])]
            elif arg_len == 4 or arg_len == 5:
                _output += base64.b64decode(update["args"][3])[:int(update["args"][2])]

        crypt_len = len(crypt["args"])

        if crypt_len == 0:
            _output += base64.b64decode(crypt["ret"])
        elif crypt_len == 1:
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["ret"])
        elif crypt_len == 2 and crypt["args"][1].isdigit():
            res["encrypt"] = res["encrypt"] if res["encrypt"] != None else (
                True if has_printable(_input) else False if has_printable(_output) else None)
            if res["encrypt"]:
                _input += base64.b64decode(crypt["args"][0])
            else:
                _output += base64.b64decode(crypt["args"][0])
        elif crypt_len == 2 and not crypt["args"][1].isdigit():
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["args"][1])
        elif crypt_len == 3:
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["ret"])
        elif crypt_len in (4, 5):
            _input += base64.b64decode(crypt["args"][0])
            _output += base64.b64decode(crypt["args"][3])

        res["encrypt"] = res["encrypt"] if res["encrypt"] != None else (
            True if has_printable(_input) else False if has_printable(_output) else None)

    elif "crypt" in res["method_name"].lower() and len(crypt["ret"]) > 5:
        _output = crypt["ret"]
        res["3rd"] = True
        arg = []
        if "encrypt" in res["method_name"].lower():
            res["encrypt"] = True
        else:
            res["encrypt"] = False
        for _arg in crypt["args"]:
            arg.append(base64.b64decode(_arg))
        if len(arg) == 1:
            _input = arg[0]
        if len(arg) == 2:
            _arg_0 = set()
            _arg_1 = set()
            [(_arg_0.add(_c["args"][0]), _arg_1.add(_c["args"][1])) for _c in crypts if res["class_name"] ==
             _c["class_name"] and res["method_name"] == _c["method_name"] and len(_c["args"]) == 2]
            if len(_arg_0) > len(_arg_1):
                _input = arg[0]
                res["key"] = arg[1]
            elif len(_arg_0) < len(_arg_1):
                _input = arg[1]
                res["key"] = arg[0]
            elif (((len(arg[1]) in (16, 24, 32) or (mayBase64(arg[1]) and len(base64.b64decode(arg[1])) in (16, 24, 32))) and "rsa" not in res[
                           "method_name"].lower()) or ((len(arg[1]) == 8 or (
                            mayBase64(arg[1]) and len(base64.b64decode(arg[1])) == 8)) and "des" in res[
            "method_name"].lower())):
                _input = arg[0]
                res["key"] = arg[1]
            elif (((len(arg[0]) in (16, 24, 32) or (
                    mayBase64(arg[0]) and len(base64.b64decode(arg[0])) in (16, 24, 32))) and "rsa" not in res[
                       "method_name"].lower()) or (
                          (len(arg[0]) == 8 or (mayBase64(arg[0]) and len(base64.b64decode(arg[0])) == 8)) and "des" in
                          res["method_name"].lower())):
                _input = arg[1]
                res["key"] = arg[0]
            elif len(arg[0]) > 32 and len(arg[0]) > len(arg[1]):
                _input = arg[0]
                res["key"] = arg[1]
            elif len(arg[1]) > 32 and len(arg[1]) > len(arg[0]):
                _input = arg[1]
                res["key"] = arg[0]
            else:
                _input = arg[0]
                res["key"] = arg[1]
        if len(arg) == 3:
            _arg_0 = set()
            _arg_1 = set()
            _arg_2 = set()
            [(_arg_0.add(_c["args"][0]), _arg_1.add(_c["args"][1]), _arg_2.add(_c["args"][2])) for _c in crypts if
             res["class_name"] ==
             _c["class_name"] and res["method_name"] == _c["method_name"] and len(_c["args"]) == 3]
            if ((len(arg[1]) in (16, 24, 32) and (len(arg[0]) in (16, 24, 32)) and "rsa" not in res[
                "method_name"].lower()) or (
                    mayBase64(arg[1]) and mayBase64(arg[0]) and len(base64.b64decode(arg[1])) in (16, 24, 32) and len(
                    base64.b64decode(arg[0])) in (16, 24, 32))):
                _input = arg[2]
                res["key"] = arg[1]
                res["iv"] = arg[0]
            elif ((len(arg[1]) in (16, 24, 32) and (len(arg[2]) in (16, 24, 32)) and "rsa" not in res[
                "method_name"].lower())) or (
                    mayBase64(arg[1]) and mayBase64(arg[2]) and len(base64.b64decode(arg[1])) in (16, 24, 32) and len(
                    base64.b64decode(arg[2])) in (16, 24, 32)):
                _input = arg[0]
                res["key"] = arg[1]
                res["iv"] = arg[2]
            elif ((len(arg[2]) in (16, 24, 32) and (len(arg[0]) in (16, 24, 32)) and "rsa" not in res[
                "method_name"].lower()) or (
                          mayBase64(arg[2]) and mayBase64(arg[0]) and len(base64.b64decode(arg[2])) in (16, 24,
                                                                                                        32) and len(
                          base64.b64decode(arg[0])) in (16, 24, 32))):
                _input = arg[1]
                res["key"] = arg[2]
                res["iv"] = arg[0]
            elif ((len(arg[0]) in (16, 24, 32) and "rsa" not in res["method_name"].lower()) or (
                    mayBase64(arg[0]) and len(base64.b64decode(arg[0])) in (16, 24, 32))):
                if len(arg[1]) > 32 and len(arg[1]) > len(arg[2]):
                    _input = arg[1]
                    res["key"] = arg[0]
                elif len(arg[2]) > 32 and len(arg[2]) > len(arg[1]):
                    _input = arg[2]
                    res["key"] = arg[0]
            elif ((len(arg[1]) in (16, 24, 32) and "rsa" not in res["method_name"].lower()) or (
                    mayBase64(arg[1]) and len(base64.b64decode(arg[1])) in (16, 24, 32))):
                if len(arg[0]) > 32 and len(arg[0]) > len(arg[2]):
                    _input = arg[0]
                    res["key"] = arg[1]
                elif len(arg[2]) > 32 and len(arg[2]) > len(arg[0]):
                    _input = arg[2]
                    res["key"] = arg[1]
            elif ((len(arg[2]) in (16, 24, 32) and "rsa" not in res["method_name"].lower()) or (
                    mayBase64(arg[2]) and len(base64.b64decode(arg[2])) in (16, 24, 32))):
                if len(arg[1]) > 32 and len(arg[1]) > len(arg[0]):
                    _input = arg[1]
                    res["key"] = arg[2]
                elif len(arg[0]) > 32 and len(arg[0]) > len(arg[1]):
                    _input = arg[0]
                    res["key"] = arg[2]
        if mayBase64(res["key"]) and res["key"][:-1] == '\n':
            res["key"] = res["key"].rstrip()
        if mayBase64(res["iv"]) and res["iv"][:-1] == '\n':
            res["iv"] = res["iv"].rstrip()
        if mayBase64(_input) and _input[:-1] == '\n':
            _input = _input.rstrip()
        _output = crypt["ret"].rstrip() if mayBase64(
            crypt["ret"]) and crypt["ret"][:-1] == '\n' else crypt["ret"]

        if res["encrypt"] == True:
            res["plaintext"] = _input
            res["ciphertext"] = _output
        else:
            res["plaintext"] = _output
            res["ciphertext"] = _input

        if _input and _output and len(_input) > 7 and len(_output) > 7 and not (
                all(c == 0 for c in _input) or all(c == 0 for c in _output)):
            return res
        else:
            return None


# ==================== 文件系统操作数据 ====================
def read_whole_files(app_path):
    """读取完整文件数据 (files-1/, files-2/)"""
    whole_files = dict()
    for folder in ("files-1", "files-2"):
        folder_path = os.path.join(app_path, folder)
        if not os.path.exists(folder_path):
            continue
        for root, _dirs, dump_files in os.walk(folder_path):
            for name in dump_files:
                file_path = os.path.join(root, name)
                try:
                    with open(file_path, "rb") as f:
                        whole_files[file_path[len(app_path):]] = f.read()
                except Exception:
                    pass
    return whole_files


def read_files_buffer(app_path):
    """读取文件写操作缓冲区数据 (fs-1.txt, fs-2.txt)"""
    files_buffer = dict()

    for stage in [1, 2]:
        fs_file = os.path.join(app_path, f"fs-{stage}.txt")
        if not os.path.exists(fs_file):
            continue

        try:
            with open(fs_file, "r", encoding='utf-8') as f:
                fs_records = [json.loads(line.strip()) for line in f.readlines() if line.strip()]
        except Exception:
            continue

        for fs in fs_records:
            if fs.get("function") != "write":
                continue

            key = f"{stage}-{fs.get('fd', '')}-{fs.get('path', '')}"
            if key in files_buffer:
                continue

            # 聚合同一文件描述符的所有写操作
            _buffer = bytes()
            for _fs in fs_records:
                if (_fs.get("function") == "write" and
                        fs.get("fd") == _fs.get("fd") and
                        fs.get("path") == _fs.get("path")):
                    try:
                        _buffer += base64.b64decode(_fs.get("data", ""))
                    except Exception:
                        pass

            if _buffer:
                files_buffer[key] = _buffer

    return files_buffer


def create_cryptApi(path, app):
    """
    解析 crypt-*.txt 文件，提取加密 API 调用数据
    """
    cryptApi = []
    seen = set()
    for stage in [1, 2]:
        fpath = os.path.join(path, app, f"crypt-{stage}.txt")
        if not os.path.exists(fpath):
            continue
        with open(fpath, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                category = obj.get("category", "")
                if category and category != "CryptoAPI":
                    continue
                class_name = obj.get("class") or obj.get("class_name") or ""
                method_name = obj.get("method") or obj.get("method_name") or ""
                args = obj.get("args", [])
                rv = obj.get("returnValue", obj.get("ret", ""))
                if not args or args[0] is None or args[0] == "" or rv is None or rv == "":
                    continue
                # plaintext
                a0 = args[0]
                if isinstance(a0, bytes):
                    plaintext = a0
                elif isinstance(a0, str):
                    plaintext = a0.encode("utf-8", errors="surrogateescape")
                else:
                    plaintext = str(a0).encode("utf-8", errors="surrogateescape")
                # ciphertext_text
                if isinstance(rv, bytes):
                    ciphertext_text = rv.strip()
                    rv_str = rv.decode("utf-8", errors="ignore")
                else:
                    rv_str = rv.strip() if isinstance(rv, str) else str(rv).strip()
                    ciphertext_text = rv_str.encode("utf-8", errors="surrogateescape") if rv_str else b""
                # ciphertext bytes
                ciphertext = b64url_to_bytes(rv_str) if rv_str else None
                if ciphertext is None:
                    ciphertext = b""
                # encrypt/decrypt 方向
                mn = method_name.lower()
                if "decrypt" in mn:
                    encrypt = False
                elif "encrypt" in mn:
                    encrypt = True
                else:
                    encrypt = True
                # 去重
                uniq = hashlib.md5(plaintext + ciphertext_text).hexdigest()
                if uniq in seen:
                    continue
                seen.add(uniq)
                if len(plaintext) == 0 or len(ciphertext_text) == 0:
                    continue
                res = {
                    "stage": stage,
                    "ts": obj.get("ts", ""),
                    "hashcode": obj.get("hashcode", ""),
                    "class_name": class_name,
                    "method_name": method_name,
                    "algorithm": obj.get("algorithm", None),
                    "key": None,
                    "iv": None,
                    "encrypt": encrypt,
                    "plaintext": plaintext,
                    "ciphertext": ciphertext,
                    "ciphertext_text": ciphertext_text,
                    "3rd": True,
                    "category": category,
                    "calledFrom": obj.get("calledFrom", ""),
                    "stack": obj.get("stack", ""),
                    "raw": obj
                }
                cryptApi.append(res)
    print(f"✅ 加密数据处理完成: {len(cryptApi)} 条有效记录")
    return cryptApi


# ==================== 网络流量解析 ====================
def extract_normal_http_https(mitmdump):
    """解析 mitm 文件，提取 HTTP/HTTPS 流量"""
    normal_http = list()
    normal_https = list()

    try:
        freader = io.FlowReader(open(mitmdump, "rb"))
        for request in freader.stream():
            if type(request) == tcp.TCPFlow:
                continue

            # 跳过 Google 相关域名
            skip_domains = (
                "googleadservices.com", "googleusercontent.com", "googlesyndication.com",
                "googlevideo.com", "google-analytics.com", "google.com", "googleapis.com",
                "gvt1.com", "doubleclick.net", "googletagservices.com", "googletagmanager.com",
                "google.ca", "google.ru", "3gppnetwork.org", "gstatic.com", "youtube.com",
                "googlezip.net", "app-measurement.com", "gvt2.com"
            )
            if any(request.request.host.endswith(h) for h in skip_domains):
                continue

            # 跳过 JS 文件
            if (request.request.path.endswith(".js") and
                    request.response is not None and
                    "content-type" in request.response.headers and
                    request.response.headers["content-type"] == "text/javascript"):
                continue

            # 提取时间戳
            req_ts = ""
            res_ts = ""
            try:
                if request.request is not None and getattr(request.request, "timestamp_start", None):
                    req_ts = datetime.fromtimestamp(request.request.timestamp_start).strftime("%Y%m%d%H%M%S")
            except Exception:
                pass
            tmp_res = {
                "host": request.request.host,
                "path": request.request.path,
                "timestamp": ""
            }
            tmp_req = {
                "req_headers": request.request.headers,
                "host": request.request.host,
                "path": request.request.path,
                "timestamp": req_ts,
                "ws": []
            }

            # WebSocket 消息
            if request.websocket is not None and len(request.websocket.messages) > 1:
                tmp_req["ws"] = [
                    ((m.content.encode('utf-8') + (b">" if m.from_client else b"<"))
                     if type(m.content) == str
                     else (m.content + (b">" if m.from_client else b"<")))
                    for m in request.websocket.messages if len(m.content) >= 1
                ]

            # 响应数据
            if request.response is not None:
                try:
                    if getattr(request.response, "timestamp_start", None):
                        res_ts = datetime.fromtimestamp(request.response.timestamp_start).strftime("%Y%m%d%H%M%S")
                except Exception:
                    pass
                tmp_res["timestamp"] = res_ts
                tmp_res["res_headers"] = request.response.headers

                # 响应内容（跳过大型媒体文件）
                skip_types = ("image/png", "image/jpeg", "image/webp", "text/css",
                              "image/gif", "application/zip", "image/x-icon",
                              "JPG", "audio/mpeg", "video/mpeg")
                if (request.response.raw_content is not None and
                        "content-type" in request.response.headers and
                        not (request.response.headers["content-type"] in skip_types and
                             len(request.response.raw_content) > 4 * 1024)):
                    tmp_res["res_raw"] = request.response.raw_content

            # 请求内容
            if request.request is not None and request.request.raw_content is not None:
                tmp_req["req_raw"] = request.request.raw_content

            # 分类存储
            if request.request.scheme == "http":
                normal_http.append(tmp_res)
                normal_http.append(tmp_req)
            else:
                normal_https.append(tmp_res)
                normal_https.append(tmp_req)
    except Exception as e:
        print(f"⚠️ 解析 mitm 文件时出错: {e}")

    return normal_http, normal_https


def extract_insecure_https(app_path, app, mitm_file):
    """提取不安全的 HTTPS 请求信息"""
    requests_list = list()
    responses_list = list()

    try:
        with open(mitm_file, "rb") as logfile:
            freader = io.FlowReader(logfile)
            for flow in freader.stream():
                if not isinstance(flow, http.HTTPFlow):
                    continue

                request = flow.request
                req_dict = {
                    "pkg": app,
                    "host": request.host,
                    "path": request.path,
                    "port": request.port,
                    "scheme": request.scheme,
                    "method": request.method,
                    "timestamp": datetime.fromtimestamp(request.timestamp_start).strftime("%Y%m%d%H%M%S")
                }
                requests_list.append(req_dict)
                if flow.response is not None:
                    response = flow.response
                    resp_dict = {
                        "pkg": app,
                        "status_code": response.status_code,
                        "timestamp": datetime.fromtimestamp(response.timestamp_start).strftime("%Y%m%d%H%M%S")
                    }
                    responses_list.append(resp_dict)
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")
    except Exception as e:
        print(f"Error: {e}")

    # 保存结果
    try:
        with open(os.path.join(app_path, "requests.json"), "w", encoding='utf-8') as f:
            json.dump(requests_list, f, ensure_ascii=False, indent=2)
        with open(os.path.join(app_path, "responses.json"), "w", encoding='utf-8') as f:
            json.dump(responses_list, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存请求/响应文件时出错: {e}")

    return requests_list, responses_list


# ==================== 分类映射加载 ====================
def load_category_mapping(device_info_path):
    """从 device_info.json 加载分类映射"""
    if not os.path.exists(device_info_path):
        return {}
    try:
        with open(device_info_path, 'r', encoding='utf-8') as f:
            device_info = json.load(f)
        return device_info.get("_categories", {})
    except Exception:
        return {}


def load_it_info(it_info_path):
    """加载 it_info.json，构建分类层级关系"""
    if not os.path.exists(it_info_path):
        return {}, {}
    try:
        with open(it_info_path, 'r', encoding='utf-8') as f:
            it_info = json.load(f)
        child_to_parent = {}
        for parent, children in it_info.items():
            for child in children:
                child_to_parent[child] = parent
        return it_info, child_to_parent
    except Exception:
        return {}, {}


def map_field_to_level1_level2(field_name, category_mapping):
    """映射字段到一级/二级分类"""
    cats = category_mapping.get(field_name)
    if not cats:
        return ("其他信息", "未分类")
    if isinstance(cats, (list, tuple)):
        if len(cats) == 1:
            return (cats[0], cats[0])
        return (cats[0], cats[1])
    return (str(cats), str(cats))


# ==================== finder_crypt_direct - 检测加密 API 明文里的敏感值 ====================
def finder_crypt_direct(data, cryptApi, path):
    """
    直接检测加密API中的隐私数据
    """
    leaks = set()
    if not cryptApi:
        return leaks

    def append_crypt_direct_record(privacy_field, value_preview, crypt):
        global LEAK_RECORDS_COLLECTOR, LEAK_RECORDS_CONTEXT
        category_mapping = LEAK_RECORDS_CONTEXT.get("category_mapping", {}) or {}
        level1, level2 = map_field_to_level1_level2(privacy_field, category_mapping)
        rec = {
            "ts": safe_str(crypt.get("ts", "")),
            "privacy_field": privacy_field,
            "category_level1": level1,
            "category_level2": level2,
            "direction": "outbound",
            "host": "CryptoAPI",
            "path": "",
            "source": "crypt_direct",
            "target": "args[0]",
            "meta": safe_str(crypt.get("class_name", "")) + "." + safe_str(crypt.get("method_name", "")),
            "encode_type": "normal",
            "encrypted": True,
            "is_key": False,
            "value_preview": safe_str(value_preview, limit=200),
            "crypt": {
                "stage": crypt.get("stage"),
                "algorithm": crypt.get("algorithm"),
                "third_party": bool(crypt.get("3rd")),
                "encrypt": bool(crypt.get("encrypt")),
            }
        }
        LEAK_RECORDS_COLLECTOR.append(rec)

    def safe_decode(d):
        if d is None:
            return ""
        if isinstance(d, str):
            return d
        if isinstance(d, bytes):
            try:
                return d.decode('utf-8')
            except:
                try:
                    return d.decode('latin-1')
                except:
                    return base64.b64encode(d).decode('utf-8')
        return str(d)

    def parse_java_byte_array(raw_data):
        """解析 Java byte[] 的字符串表示"""
        if raw_data is None:
            return b''
        if isinstance(raw_data, bytes):
            try:
                decoded = raw_data.decode('utf-8', errors='ignore')
            except:
                return raw_data
            if ',' not in decoded:
                return raw_data
            raw_data = decoded
        if isinstance(raw_data, str):
            try:
                raw_data = raw_data.strip()
                byte_values = []
                for num_str in raw_data.split(','):
                    num_str = num_str.strip()
                    if num_str:
                        num = int(num_str)
                        if num < 0:
                            num = num + 256
                        byte_values.append(num)
                return bytes(byte_values)
            except (ValueError, TypeError):
                return raw_data.encode('utf-8') if isinstance(raw_data, str) else raw_data
        return b''

    for idx, crypt in enumerate(cryptApi):
        if not isinstance(crypt, dict):
            continue
        raw_plaintext = crypt.get("plaintext", b"")
        if not raw_plaintext:
            continue
        plaintext = parse_java_byte_array(raw_plaintext)
        if len(plaintext) < 4:
            continue
        extracted_data = extract(plaintext)
        if isinstance(extracted_data, str):
            extracted_data = extracted_data.encode("utf-8")
        if len(extracted_data) < 4:
            continue
        # 遍历所有编码类型
        for _type_data, coded_data in data.items():
            for name_data, value_data in coded_data.items():
                for lv_data in (value_data if type(value_data) == list else [value_data]):
                    if not lv_data or len(lv_data) == 0:
                        continue
                    search_data = extracted_data if isinstance(extracted_data, bytes) else extracted_data.encode(
                        'utf-8')
                    search_value = lv_data if isinstance(lv_data, bytes) else lv_data.encode('utf-8')
                    # 关键词匹配
                    if name_data.endswith("-word"):
                        if _type_data != "normal":
                            continue
                        if search_data.isdigit():
                            continue
                        if search_value.lower() in search_data.lower():
                            result_str = "{}%{}[crypt:{}:{}:{}]".format(
                                name_data,
                                safe_decode(extracted_data)[:100],
                                crypt.get("stage", "?"),
                                "encrypt" if crypt.get("encrypt") else "decrypt",
                                crypt.get("algorithm", "?")
                            )
                            leaks.add(result_str)
                            append_crypt_direct_record(name_data, extracted_data, crypt)
                    # 精确值匹配
                    else:
                        if _type_data in ("md5hex", "sha1hex", "sha256hex", "md5", "sha1", "sha256"):
                            original_value = data.get("normal", {}).get(name_data, b"")
                            if isinstance(original_value, list):
                                original_value = original_value[0] if original_value else b""
                            if len(original_value) < 6:
                                continue
                        if search_value in search_data:
                            encode_suffix = "" if _type_data == "normal" else "[{}]".format(_type_data)
                            result_str = "{}%{}{}[crypt:{}:{}:{}]".format(
                                name_data,
                                safe_decode(lv_data),
                                encode_suffix,
                                crypt.get("stage", "?"),
                                "encrypt" if crypt.get("encrypt") else "decrypt",
                                crypt.get("algorithm", "?")
                            )
                            leaks.add(result_str)
                            append_crypt_direct_record(name_data, lv_data, crypt)
    return leaks


# ==================== finder - 网络流量隐私检测 ====================
# ==================== finder - 网络流量隐私检测 ====================
class CT:
    http = 1
    https = 2
    whole_file = 3
    file_buffer = 4
    non_http = 5


def finder(data, packets, t, path):
    """
    隐私数据检测函数（简化版，移除了加密流量匹配）
    """
    leaks = set()
    raw_data = list()
    final_raw_data = list()

    # ========== 准备原始数据 ==========
    if t == CT.https or t == CT.http:
        for m in packets:
            raw_data_item = dict()
            raw_data_item["path"] = m.get("path", "")
            raw_data_item["host"] = m["host"].encode("utf-8") if type(m["host"]) == str else m["host"]
            raw_data_item["direction"] = b">" if "req_raw" in m or "req_headers" in m else b"<"
            raw_data_item["timestamp"] = m.get("timestamp", "")
            for k, v in m.items():
                _raw_data_item = raw_data_item.copy()
                _raw_data_item["target"] = k
                if k == "ws" and v:
                    for ws in v:
                        __raw_data_item = _raw_data_item.copy()
                        __raw_data_item["direction"] = bytes([ws[-1]])
                        __raw_data_item["data"] = ws[:-1]
                        __raw_data_item["meta"] = "W->"
                        raw_data.append(__raw_data_item)
                else:
                    if k in ("req_headers", "res_headers"):
                        for ii, vv in v.items():
                            __raw_data_item = _raw_data_item.copy()
                            __raw_data_item["meta"] = "H->" + ii.lower()
                            __raw_data_item["data"] = vv.encode('utf-8', 'surrogateescape')
                            raw_data.append(__raw_data_item)
                        continue
                    _raw_data_item["data"] = v
                    raw_data.append(_raw_data_item)

    elif t == CT.file_buffer or t == CT.whole_file:
        for _packets in packets:
            for k, v in _packets.items():
                raw_data_item = dict()
                raw_data_item["host"] = k.encode("utf-8") if type(k) == str else k
                raw_data_item["direction"] = b">"
                raw_data_item["target"] = b""
                raw_data_item["data"] = v
                raw_data.append(raw_data_item)

    elif t == CT.non_http:
        for k, v in packets:
            raw_data_item = dict()
            raw_data_item["host"] = k.encode("utf-8") if type(k) == str else k
            raw_data_item["direction"] = (bytes([v[-1]]) if type(v[-1]) == int else v[-1])
            raw_data_item["target"] = b""
            raw_data_item["data"] = v
            raw_data.append(raw_data_item)

    # 注意：删除了 CT.*_crypt 相关的分支

    # ========== 递归提取数据 ==========
    for f_rawd in raw_data:
        full_rawd = []
        if type(f_rawd.get("data")) == list and f_rawd.get("target") == "ws":
            for ws in f_rawd["data"]:
                _f_rawd = f_rawd.copy()
                _f_rawd["direction"] = bytes([ws[-1]])
                _f_rawd["data"] = ws[:-1]
                _f_rawd["meta"] = "W->"
                full_rawd.append(_f_rawd)
        else:
            full_rawd = [f_rawd]
        for rawd in full_rawd:
            if "data" not in rawd:
                continue
            extract_1 = try_extract(rawd)
            if len(extract_1) <= 1:
                final_raw_data += extract_1
            else:
                for _extract_1 in extract_1:
                    extract_2 = try_extract(_extract_1)
                    if len(extract_2) <= 1:
                        final_raw_data += extract_2
                    else:
                        for _extract_2 in extract_2:
                            final_raw_data += try_extract(_extract_2)

    # ========== 辅助函数 ==========
    def safe_decode(data):
        if data is None:
            return ""
        if isinstance(data, str):
            return data
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8')
            except:
                try:
                    return data.decode('latin-1')
                except:
                    return base64.b64encode(data).decode('utf-8')
        return str(data)

    def build_readable_result(privacy_type, value, raw, encode_type="normal", max_value_len=500):
        result_parts = []

        def truncate(s, max_len, suffix="..."):
            s = safe_decode(s)
            if len(s) > max_len:
                return s[:max_len - len(suffix)] + suffix
            return s

        decoded_value = truncate(value, max_value_len)
        result_parts.append("{}%{}".format(privacy_type, decoded_value))
        if encode_type != "normal":
            result_parts.append("[{}]".format(encode_type))
        if "meta" in raw:
            result_parts.append("*{}".format(raw["meta"]))
        direction = ">" if raw.get("direction") == b">" else "<"
        host = safe_decode(raw.get("host", b""))
        result_parts.append("{}{}".format(direction, host))
        if raw.get("target") == "ws":
            result_parts.append("/ws")
        return "".join(result_parts)

    def append_record(privacy_field, value_for_preview, raw, encode_type):
        global LEAK_RECORDS_COLLECTOR, LEAK_RECORDS_CONTEXT
        category_mapping = LEAK_RECORDS_CONTEXT.get("category_mapping", {}) or {}
        source = LEAK_RECORDS_CONTEXT.get("source", "unknown")
        direction = "outbound" if raw.get("direction") == b">" else "inbound" if raw.get(
            "direction") == b"<" else "unknown"
        host = safe_str(raw.get("host", b"Unknown"))
        path_val = safe_str(raw.get("path", ""))
        level1, level2 = map_field_to_level1_level2(privacy_field, category_mapping)
        rec = {
            "ts": safe_str(raw.get("timestamp", "")),
            "privacy_field": privacy_field,
            "category_level1": level1,
            "category_level2": level2,
            "direction": direction,
            "host": host,
            "path": path_val,
            "source": source,
            "target": safe_str(raw.get("target", "")),
            "meta": safe_str(raw.get("meta", "")),
            "encode_type": encode_type,
            "encrypted": False,
            "is_key": False,
            "value_preview": safe_str(value_for_preview, limit=200),
        }
        LEAK_RECORDS_COLLECTOR.append(rec)

    # ========== Token收集 ==========
    tokens = set()

    # ========== 主要检测逻辑 ==========
    for raw in final_raw_data:
        if "data" not in raw:
            continue
        extracted_raw_data = extract(raw["data"])
        if isinstance(extracted_raw_data, str):
            extracted_raw_data = extracted_raw_data.encode("utf-8")
        if len(extracted_raw_data) == 0:
            continue
        for _type_data, coded_data in data.items():
            for name_data, value_data in coded_data.items():
                for lv_data in (value_data if type(value_data) == list else [value_data]):
                    if len(lv_data) == 0:
                        continue
                    # 关键词匹配
                    if name_data.endswith("-word"):
                        if _type_data != "normal":
                            continue
                        if extracted_raw_data.isdigit():
                            continue
                        if lv_data in extracted_raw_data.lower():
                            item_result = build_readable_result(
                                name_data,
                                extracted_raw_data,
                                raw,
                                encode_type="normal"
                            )
                            leaks.add(item_result)
                            append_record(name_data, extracted_raw_data, raw, "normal")
                            if name_data in ("token-word", "session-word", "cookie-word",
                                             "authorization-word", "secret-word", "password-word", "jwt-word"):
                                tokens.add((lv_data, extracted_raw_data))
                    # 精确值匹配
                    else:
                        if _type_data in ("md5hex", "sha1hex", "sha256hex", "md5", "sha1", "sha256"):
                            original_value = data.get("normal", {}).get(name_data, b"")
                            if isinstance(original_value, list):
                                original_value = original_value[0] if original_value else b""
                            if len(original_value) < 6:
                                continue
                        if lv_data in extracted_raw_data:
                            item_result = build_readable_result(
                                name_data,
                                lv_data,
                                raw,
                                encode_type=_type_data
                            )
                            leaks.add(item_result)
                            append_record(name_data, lv_data, raw, _type_data)
        # Token泄露检测
        if raw.get("direction") == b">":
            for k, v in tokens:
                if v in extracted_raw_data:
                    item_result = build_readable_result(
                        safe_decode(k) + "-token",
                        v,
                        raw,
                        encode_type="normal"
                    )
                    leaks.add(item_result)
                    append_record(safe_decode(k) + "-token", v, raw, "normal")

    return leaks


# ==================== 数据提取辅助函数 ====================
def extract_verify(v):
    try:
        if type(v) == str:
            v = v.encode("utf-8")
        if (type(v) == bytes and (len(v) <= 3 or (v.isdigit() and int(v) < 10000))) or (
                type(v) == int and v < 100000) or (type(v) == float and 1.1 > abs(v)):
            return False
        if (type(v) == bytes and (len(v.split(b".")) == 2 and v.lstrip(b'-').replace(b".", b"", 1).isdigit() and int(
                v.lstrip(b'-').split(b".")[0]) < 1)):
            return False
        if (type(v) == list and len(v) == 0) or (type(v) == bytes and v in (b"true", b"false", b"null", b"none")):
            return False
    except:
        return False
    return True


def try_extract(rawd):
    extracted_raw_data = extract(rawd["data"])
    final_raw_data = list()

    if len(extracted_raw_data) < 4:
        if extract_verify(rawd["data"]):
            return [rawd]
        else:
            return []

    new_raws = []
    p = ""
    try:
        new_raws = json.loads(extracted_raw_data)
        p = "J"
    except:
        try:
            new_raws = xmltodict.parse(extracted_raw_data)
            p = "X"
        except:
            pass

    if type(new_raws) == dict and len(new_raws) > 0:
        items = dict()
        dict_extract(new_raws, items, p)
        for i in items.items():
            _rawd = rawd.copy()
            if "meta" in _rawd:
                _rawd["meta"] = _rawd["meta"] + "@" + i[0].lower()
            else:
                _rawd["meta"] = i[0].lower()
            _rawd["data"] = extract(i[1])
            if extract_verify(i[1]):
                final_raw_data.append(_rawd)
        return final_raw_data

    try:
        final_raw_data.append(rawd)
        n_data = urllib.parse.parse_qs(extracted_raw_data)
        if len(n_data) > 0:
            items = dict()
            dict_extract(n_data, items, "U")
            for i in items.items():
                _rawd = rawd.copy()
                if "meta" in _rawd:
                    _rawd["meta"] = _rawd["meta"] + "@" + i[0].lower()
                else:
                    _rawd["meta"] = i[0].lower()
                _rawd["data"] = extract(i[1])
                if extract_verify(i[1]):
                    final_raw_data.append(_rawd)
    except:
        if "data" in rawd and extract_verify(rawd["data"]):
            return [rawd]
        else:
            return []

    return final_raw_data


def dict_extract(input, items, parent="-"):
    if type(input) == dict:
        for i in input.items():
            dict_extract(i[1], items, parent=parent + ">" + (i[0] if type(i[0]) == str else i[0].decode()))
        return
    if type(input) == type(None) or type(input) == bool:
        return
    if type(input) == list:
        for i, inp in enumerate(input):
            dict_extract(inp, items, parent=parent + "[{}]".format(i))
        return
    if (type(input) == str and len(input) > 3) or type(input) in (float, int):
        items[parent] = str(input).encode("utf-8")
        return items[parent]


def toHex(s):
    if type(s) == str:
        return ''.join([str('{:x}'.format(ord(o))) for o in s])
    if type(s) == bytes:
        return b''.join(['{:x}'.format(o).encode("utf-8") for o in s])


def transformer(data, path):
    """转换设备信息为多种编码格式"""
    res = {
        "normal": dict(), "capitalize": dict(), "upper": dict(), "lower": dict(),
        "hexCapitalize": dict(), "hexUpper": dict(), "hexLower": dict(),
        "UpperHexUpper": dict(), "UpperHexLower": dict(),
        "urlUpper": dict(), "urlLower": dict(), "base64": dict(),
        "md5hex": dict(), "sha1hex": dict(), "sha256hex": dict(),
        "md5": dict(), "sha1": dict(), "sha256": dict()
    }
    for k, v in data.items():
        if isinstance(k, str) and k.startswith("_"):
            continue
        if isinstance(v, dict):
            continue
        if v is None:
            continue
        if (not isinstance(v, list)) and isinstance(v, str) and v.startswith("@") and os.path.exists(
                path + "/" + v[1:] + ".txt"):
            with open(path + "/" + v[1:] + ".txt", 'r') as f:
                v = f.read().strip()

        res["normal"][k] = [_v.encode() for _v in v] if type(v) == list else v.encode()

        if not k.endswith("-word"):
            res["capitalize"][k] = [_v.capitalize().encode() for _v in v] if type(
                v) == list else v.capitalize().encode()
            res["upper"][k] = [_v.upper().encode() for _v in v] if type(v) == list else v.upper().encode()
            res["lower"][k] = [_v.lower().encode() for _v in v] if type(v) == list else v.lower().encode()
            res["hexCapitalize"][k] = [toHex(_v.capitalize()).encode() for _v in v] if type(v) == list else toHex(
                v.capitalize()).encode()
            res["hexUpper"][k] = [toHex(_v.upper()).encode() for _v in v] if type(v) == list else toHex(
                v.upper()).encode()
            res["hexLower"][k] = [toHex(_v.lower()).encode() for _v in v] if type(v) == list else toHex(
                v.lower()).encode()
            res["UpperHexUpper"][k] = [toHex(_v.upper()).upper().encode() for _v in v] if type(v) == list else toHex(
                v.upper()).encode()
            res["UpperHexLower"][k] = [toHex(_v.lower()).upper().encode() for _v in v] if type(v) == list else toHex(
                v.lower()).encode()
            res["urlUpper"][k] = [urllib.parse.quote_plus(_v.upper()).encode() for _v in v] if type(
                v) == list else urllib.parse.quote_plus(v.upper()).encode()
            res["urlLower"][k] = [urllib.parse.quote_plus(_v.lower()).encode() for _v in v] if type(
                v) == list else urllib.parse.quote_plus(v.lower()).encode()
            res["base64"][k] = [base64.b64encode(_v.encode())[:-4] for _v in v] if type(
                v) == list else base64.b64encode(v.encode())[:-4]
            res["md5hex"][k] = [hashlib.md5(_v.encode()).hexdigest().encode() for _v in v] if type(
                v) == list else hashlib.md5(v.encode()).hexdigest().encode()
            res["sha1hex"][k] = [hashlib.sha1(_v.encode()).hexdigest().encode() for _v in v] if type(
                v) == list else hashlib.sha1(v.encode()).hexdigest().encode()
            res["sha256hex"][k] = [hashlib.sha256(_v.encode()).hexdigest().encode() for _v in v] if type(
                v) == list else hashlib.sha256(v.encode()).hexdigest().encode()
            res["md5"][k] = [hashlib.md5(_v.encode()).digest() for _v in v] if type(v) == list else hashlib.md5(
                v.encode()).digest()
            res["sha1"][k] = [hashlib.sha1(_v.encode()).digest() for _v in v] if type(v) == list else hashlib.sha1(
                v.encode()).digest()
            res["sha256"][k] = [hashlib.sha256(_v.encode()).digest() for _v in v] if type(
                v) == list else hashlib.sha256(v.encode()).digest()
    return res


def itemTransformer(item):
    """将单个值转换为多种编码格式"""
    res = dict()
    if item is None:
        return res

    if type(item) == str:
        item = item.encode('utf-8')

    res["normal"] = item
    res["capitalize"] = item.capitalize()
    res["upper"] = item.upper()
    res["lower"] = item.lower()
    res["hexCapitalize"] = toHex(item.capitalize())
    res["hexUpper"] = toHex(item.upper())
    res["hexLower"] = toHex(item.lower())
    res["UpperHexUpper"] = toHex(item.upper()).upper()
    res["UpperHexLower"] = toHex(item.lower()).upper()
    res["urlUpper"] = urllib.parse.quote_plus(item.upper().decode()).encode()
    res["urlLower"] = urllib.parse.quote_plus(item.lower().decode()).encode()
    res["base64"] = base64.b64encode(item)
    res["md5hex"] = hashlib.md5(item).hexdigest().encode()
    res["sha1hex"] = hashlib.sha1(item).hexdigest().encode()
    res["sha256hex"] = hashlib.sha256(item).hexdigest().encode()
    res["md5"] = hashlib.md5(item).digest()
    res["sha1"] = hashlib.sha1(item).digest()
    res["sha256"] = hashlib.sha256(item).digest()

    return res


# ==================== 规范化 leak.json 输出 ====================
def normalize_leak_records(records, app_package, sdk_info=None):
    """
    规范化泄露记录，统一输出格式

    Args:
        records: 原始泄露记录列表
        app_package: 应用包名
        sdk_info: SDK 信息列表

    Returns:
        list: 规范化后的泄露记录列表
    """
    sdk_info = sdk_info or []
    normalized = []

    for rec in records:
        # 基础字段
        norm_rec = {
            "ts": rec.get("ts", ""),
            "privacy_field": rec.get("privacy_field", ""),
            "category_level1": rec.get("category_level1", "其他信息"),
            "category_level2": rec.get("category_level2", "未分类"),
            "direction": rec.get("direction", "unknown"),
            "host": rec.get("host", "Unknown"),
            "path": rec.get("path", ""),
            "source": rec.get("source", "unknown"),
            "target": rec.get("target", ""),
            "meta": rec.get("meta", ""),
            "encode_type": rec.get("encode_type", "normal"),
            "encrypted": rec.get("encrypted", False),
            "is_key": rec.get("is_key", False),
            "value_preview": rec.get("value_preview", ""),
        }

        # 加密信息
        if "crypt" in rec:
            norm_rec["crypt"] = rec["crypt"]

        # SDK 归因
        host = rec.get("host", "")
        sdk_result = identify_sdk_from_host(host, sdk_info)

        if sdk_result.get("is_third_party"):
            norm_rec["sdk"] = {
                "name": sdk_result.get("name", ""),
                "company": sdk_result.get("company", ""),
                "category": sdk_result.get("category", ""),
                "is_third_party": True
            }
        else:
            # 检查是否是应用自身域名
            if is_internal_host(host, app_package):
                norm_rec["sdk"] = {
                    "name": app_package,
                    "company": "",
                    "category": "app_self",
                    "is_third_party": False
                }
            else:
                norm_rec["sdk"] = {
                    "name": "",
                    "company": "",
                    "category": "unknown",
                    "is_third_party": False
                }

        normalized.append(norm_rec)

    return normalized


def aggregate_leak_summary(normalized_records):
    """
    聚合泄露记录，生成摘要（修复版：过滤本地文件）
    """
    summary = {
        "total_leaks": len(normalized_records),
        "by_category": defaultdict(lambda: {"count": 0, "fields": defaultdict(int)}),
        "by_host": defaultdict(lambda: {"count": 0, "fields": []}),
        "by_sdk": defaultdict(lambda: {"count": 0, "fields": [], "is_third_party": False}),
        "encrypted_count": 0,
        "plaintext_count": 0,
        "outbound_count": 0,
        "inbound_count": 0,
        "local_file_count": 0,  # 新增
        "network_leak_count": 0,  # 新增
    }

    for rec in normalized_records:
        # 按分类统计
        cat1 = rec.get("category_level1", "其他信息")
        field = rec.get("privacy_field", "")
        summary["by_category"][cat1]["count"] += 1
        summary["by_category"][cat1]["fields"][field] += 1

        # 判断是否是本地文件
        host = rec.get("host", "Unknown")
        source = rec.get("source", "")

        if source in ("file_buffer", "whole_file", "crypt_direct") or not is_real_host(host):
            summary["local_file_count"] += 1
        else:
            summary["network_leak_count"] += 1

            # 按主机统计（只统计真实域名）
            summary["by_host"][host]["count"] += 1
            if field not in summary["by_host"][host]["fields"]:
                summary["by_host"][host]["fields"].append(field)

            # 按 SDK 统计
            sdk_info = rec.get("sdk", {})
            sdk_name = sdk_info.get("name", "") or host
            summary["by_sdk"][sdk_name]["count"] += 1
            summary["by_sdk"][sdk_name]["is_third_party"] = sdk_info.get("is_third_party", False)
            if field not in summary["by_sdk"][sdk_name]["fields"]:
                summary["by_sdk"][sdk_name]["fields"].append(field)

        # 加密/明文统计
        if rec.get("encrypted"):
            summary["encrypted_count"] += 1
        else:
            summary["plaintext_count"] += 1

        # 方向统计
        if rec.get("direction") == "outbound":
            summary["outbound_count"] += 1
        elif rec.get("direction") == "inbound":
            summary["inbound_count"] += 1

    # 转换 defaultdict 为普通 dict
    summary["by_category"] = {k: {"count": v["count"], "fields": dict(v["fields"])}
                              for k, v in summary["by_category"].items()}
    summary["by_host"] = dict(summary["by_host"])
    summary["by_sdk"] = dict(summary["by_sdk"])

    return summary


def generate_analysis_report(app, leak_summary, leak_by_source, api_simplified_result):
    """
    生成分析报告内容（返回字符串）
    """
    lines = []

    lines.append("=" * 60)
    lines.append("📊 隐私分析报告")
    lines.append("=" * 60)
    lines.append(f"📦 应用包名: {app}")
    lines.append(f"📅 分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ===== 计算统计数据 =====
    api_total_calls = 0
    api_app_self_calls = 0
    api_third_party_calls = 0

    if api_simplified_result:
        for entity in api_simplified_result:
            total = sum(d.get("total_count", 0) for d in entity.get("details", []))
            api_total_calls += total
            if entity.get("entity_type") == "App-Owned":
                api_app_self_calls += total
            else:
                api_third_party_calls += total

    network_leak_count = (leak_by_source.get("app_self", {}).get("total_count", 0) +
                          leak_by_source.get("third_party", {}).get("total_count", 0) +
                          leak_by_source.get("unknown", {}).get("total_count", 0))

    local_file_leak_count = leak_by_source.get("local_file", {}).get("total_count", 0)
    total_leak_count = leak_summary.get("total_leaks", 0)

    # ===== 总体泄露情况 =====
    lines.append("")
    lines.append("─" * 50)
    lines.append("📈 总体隐私泄露情况")
    lines.append("─" * 50)
    lines.append(f"   🔍 API 隐私调用: {api_total_calls} 次")
    lines.append(f"   🌐 网络流量泄露: {network_leak_count} 条")
    lines.append(f"   📁 本地文件泄露: {local_file_leak_count} 条")
    lines.append(f"   📊 总计泄露记录: {total_leak_count} 条")

    lines.append("")
    lines.append("   📌 按来源分类:")
    lines.append(
        f"      • APP 自身: API {api_app_self_calls} 次, 网络 {leak_by_source.get('app_self', {}).get('total_count', 0)} 条")
    lines.append(
        f"      • 第三方SDK: API {api_third_party_calls} 次, 网络 {leak_by_source.get('third_party', {}).get('total_count', 0)} 条")
    lines.append(f"      • 未知来源: 网络 {leak_by_source.get('unknown', {}).get('total_count', 0)} 条")

    # ===== API 隐私调用详情 =====
    if api_simplified_result:
        lines.append("")
        lines.append("─" * 50)
        lines.append("📱 API 隐私调用详情")
        lines.append("─" * 50)

        # APP 自身
        for entity in api_simplified_result:
            if entity.get("entity_type") == "App-Owned":
                total = sum(d.get("total_count", 0) for d in entity.get("details", []))
                lines.append(f"   • 应用自身 ({entity.get('entity_name', app)}): {total} 次")
                for detail in sorted(entity.get("details", []), key=lambda x: x.get("total_count", 0), reverse=True)[
                    :5]:
                    cat = detail.get("category", "")
                    cat_total = detail.get("total_count", 0)
                    types_str = ", ".join([pt.get("type", "") for pt in detail.get("privacy_types", [])[:3]])
                    lines.append(f"      - {cat}: {cat_total} 次 [{types_str}]")
                break

        # 第三方 SDK
        third_party_entities = [e for e in api_simplified_result if e.get("entity_type") == "Third-Party"]
        if third_party_entities:
            lines.append("")
            lines.append("   🔌 第三方 SDK (Top 10):")
            sorted_sdks = sorted(
                third_party_entities,
                key=lambda x: sum(d.get("total_count", 0) for d in x.get("details", [])),
                reverse=True
            )[:10]
            for sdk in sorted_sdks:
                sdk_name = sdk.get("entity_name", "Unknown")
                total = sum(d.get("total_count", 0) for d in sdk.get("details", []))
                types = []
                for detail in sdk.get("details", []):
                    for pt in detail.get("privacy_types", []):
                        types.append(pt.get("type", ""))
                types_str = ", ".join(list(set(types))[:3])
                lines.append(f"      • {sdk_name}: {total} 次 [{types_str}]")

    # ===== 网络流量泄露详情 =====
    lines.append("")
    lines.append("─" * 50)
    lines.append("🌐 网络流量泄露详情")
    lines.append("─" * 50)
    lines.append(f"   • 加密传输: {leak_summary.get('encrypted_count', 0)} 条")
    lines.append(f"   • 明文传输: {leak_summary.get('plaintext_count', 0)} 条")
    lines.append(f"   • 出站流量: {leak_summary.get('outbound_count', 0)} 条")
    lines.append(f"   • 入站流量: {leak_summary.get('inbound_count', 0)} 条")

    # APP 自身域名泄露
    app_self_hosts = leak_by_source.get('app_self', {}).get('hosts', {})
    if app_self_hosts:
        lines.append("")
        lines.append("   📤 APP 自身域名泄露:")
        for host, info in sorted(app_self_hosts.items(), key=lambda x: x[1]['count'], reverse=True)[:5]:
            fields_str = ", ".join(info['fields'][:3])
            lines.append(f"      • {host}: {info['count']} 条 [{fields_str}]")

    # 第三方 SDK 泄露
    third_party_sdks = leak_by_source.get('third_party', {}).get('sdks', {})
    if third_party_sdks:
        lines.append("")
        lines.append("   🔌 第三方 SDK 泄露:")
        for sdk_name, info in sorted(third_party_sdks.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
            company = info.get('company', '')
            company_str = f" ({company})" if company else ""
            fields_str = ", ".join(info['fields'][:5])
            lines.append(f"      • {sdk_name}{company_str}: {info['count']} 条 [{fields_str}]")

    # 未知域名泄露
    unknown_hosts = leak_by_source.get('unknown', {}).get('hosts', {})
    if unknown_hosts:
        lines.append("")
        lines.append("   ❓ 未知域名泄露 (Top 10):")
        for host, info in sorted(unknown_hosts.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
            fields_str = ", ".join(info['fields'][:3])
            lines.append(f"      • {host}: {info['count']} 条 [{fields_str}]")

    # ===== 本地文件泄露详情 =====
    local_file_info = leak_by_source.get('local_file', {})
    if local_file_info.get('total_count', 0) > 0:
        lines.append("")
        lines.append("─" * 50)
        lines.append("📁 本地文件泄露详情")
        lines.append("─" * 50)
        lines.append(f"   • 总计: {local_file_info['total_count']} 条")
        lines.append(f"   • 涉及路径: {len(local_file_info.get('paths', {}))} 个")

        if local_file_info.get('fields'):
            fields_sorted = sorted(local_file_info['fields'].items(), key=lambda x: x[1], reverse=True)[:10]
            lines.append("   • 泄露字段 (Top 10):")
            for field, count in fields_sorted:
                lines.append(f"      - {field}: {count} 条")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


def analyze_single(data_path, app, device_info_path, sdk_info_path=None, api_info_path=None, it_info_path=None):
    """
    分析单个应用
    """
    global LEAK_RECORDS_COLLECTOR, LEAK_RECORDS_CONTEXT
    LEAK_RECORDS_COLLECTOR = []
    app_path = os.path.join(data_path, app)

    print(f"📱 开始分析应用: {app}")

    # ========== 1. 检查应用目录 ==========
    if not os.path.exists(app_path):
        print(f"   ❌ 应用目录不存在: {app_path}")
        return None

    # ========== 2. 加载配置文件 ==========
    print("   📂 加载配置文件...")

    sdk_info = []
    if sdk_info_path and os.path.exists(sdk_info_path):
        sdk_info = load_sdk_info(sdk_info_path)
        print(f"      ✅ SDK 信息: {len(sdk_info)} 个")

    if not os.path.exists(device_info_path):
        print(f"   ❌ 未找到设备信息文件: {device_info_path}")
        return None

    with open(device_info_path, 'r', encoding='utf-8') as f:
        device_info = json.load(f)
    print(f"      ✅ 设备信息: {len(device_info)} 个字段")

    category_mapping = load_category_mapping(device_info_path)
    LEAK_RECORDS_CONTEXT["category_mapping"] = category_mapping
    data = transformer(device_info, app_path)

    # ========== 3. API 隐私分析 ==========
    print("   🔍 分析 API 隐私调用...")
    api_privacy_result = None
    api_simplified_result = None

    if api_info_path and it_info_path and os.path.exists(api_info_path) and os.path.exists(it_info_path):
        try:
            api_analyzer = APIPrivacyAnalyzer(api_info_path, it_info_path, sdk_info_path)
            api_privacy_result = api_analyzer.analyze_app(app_path)
            api_privacy_result["package"] = app
            api_simplified_result = api_analyzer.get_simplified_result(api_privacy_result)
            print(f"      ✅ API 调用: {api_privacy_result['summary']['total_calls']} 条")
        except Exception as e:
            print(f"      ⚠️ API 分析失败: {e}")

    # ========== 4-5. 加载 UI 事件和 Frida 调用 ==========
    print("   📱 加载辅助数据...")
    base_path = os.path.dirname(data_path)
    explorer_root = os.path.normpath(os.path.join(base_path, ".."))
    dumps_base = os.path.join(explorer_root, "dumps")
    dumps_pkg_dir = os.path.join(dumps_base, app)

    ui_events = load_ui_events(dumps_pkg_dir)
    frida_calls = load_frida_privacy_calls(app_path, sdk_info)

    # ========== 6. 解析网络流量 ==========
    print("   🌐 解析网络流量...")
    normal_http, normal_https = [], []
    # 解析两个 mitm 文件
    for mitm_name in ("mitmdump-1.mitm", "mitmdump-2.mitm"):
        mitm_file = os.path.join(app_path, mitm_name)
        if os.path.exists(mitm_file):
            http_tmp, https_tmp = extract_normal_http_https(mitm_file)
            normal_http.extend(http_tmp)
            normal_https.extend(https_tmp)
            print(f"      ✅ {mitm_name}: HTTP {len(http_tmp)}, HTTPS {len(https_tmp)}")
    # 提取不安全请求信息（使用第一个存在的文件）
    for mitm_name in ("mitmdump-1.mitm", "mitmdump-2.mitm"):
        mitm_file = os.path.join(app_path, mitm_name)
        if os.path.exists(mitm_file):
            extract_insecure_https(app_path, app, mitm_file)
            break
    if not normal_http and not normal_https:
        print("      ⚠️ 未找到 mitm 流量文件")

    # ========== 7. 加载文件系统数据 ==========
    print("   📁 加载文件系统数据...")
    files_buffer = read_files_buffer(app_path)
    whole_files = read_whole_files(app_path)

    # ========== 8. 解析加密 API ==========
    print("   🔐 解析加密 API...")
    cryptApi = create_cryptApi(data_path, app)

    # ========== 9. 隐私泄露检测 ==========
    print("   🔍 执行隐私泄露检测...")
    leaks = set()

    LEAK_RECORDS_CONTEXT["source"] = "crypt_direct"
    leaks.update(finder_crypt_direct(data, cryptApi, app_path))

    if normal_http:
        LEAK_RECORDS_CONTEXT["source"] = "http"
        leaks.update(finder(data, normal_http, CT.http, app_path))

    if normal_https:
        LEAK_RECORDS_CONTEXT["source"] = "https"
        leaks.update(finder(data, normal_https, CT.https, app_path))

    if files_buffer:
        LEAK_RECORDS_CONTEXT["source"] = "file_buffer"
        leaks.update(finder(data, [files_buffer], CT.file_buffer, app_path))

    if whole_files:
        LEAK_RECORDS_CONTEXT["source"] = "whole_file"
        leaks.update(finder(data, [whole_files], CT.whole_file, app_path))

    # ========== 10. API-流量时间关联 ==========
    print("   ⏱️ 执行时间关联...")
    traffic_records = []
    for m in normal_http + normal_https:
        if m.get("timestamp"):
            traffic_records.append({
                "timestamp": m.get("timestamp", ""),
                "host": m.get("host", ""),
                "path": m.get("path", ""),
                "direction": b">" if "req_raw" in m or "req_headers" in m else b"<"
            })
    api_traffic_correlations = correlate_api_traffic(
        frida_calls, traffic_records, LEAK_RECORDS_COLLECTOR, sdk_info,
        time_window_s=5, max_calls=1000
    )

    # ========== 11-12. 规范化输出和统计 ==========
    print("   📝 生成统计数据...")
    normalized_leaks = normalize_leak_records(LEAK_RECORDS_COLLECTOR, app, sdk_info)
    leak_summary = aggregate_leak_summary(normalized_leaks)
    leak_by_source = generate_leak_by_source_summary(normalized_leaks, app, sdk_info)

    # ========== 13. 保存结果 ==========
    print("   💾 保存分析结果...")

    # 保存 leak.json
    leak_output = {
        "package": app,
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": leak_summary,
        "leak_by_source": leak_by_source,
        "records": normalized_leaks,
        "api_traffic_correlations": api_traffic_correlations[:100],
    }
    with open(os.path.join(app_path, "leak.json"), 'w', encoding='utf-8') as f:
        json.dump(leak_output, f, ensure_ascii=False, indent=2)

    # 保存 API 隐私分析结果
    if api_privacy_result:
        # 简化格式 api_privacy_summary.json
        if api_simplified_result:
            with open(os.path.join(app_path, "api_privacy_summary.json"), 'w', encoding='utf-8') as f:
                json.dump(api_simplified_result, f, ensure_ascii=False, indent=2)

        # 完整格式 api_privacy_full.json
        api_full_output = {
            "package": app,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": api_privacy_result.get("summary", {}),
            "categories": api_privacy_result.get("categories", {}),
        }
        with open(os.path.join(app_path, "api_privacy_full.json"), 'w', encoding='utf-8') as f:
            json.dump(api_full_output, f, ensure_ascii=False, indent=2)

    # 生成并保存分析报告
    report_content = generate_analysis_report(app, leak_summary, leak_by_source, api_simplified_result)
    report_path = os.path.join(app_path, "analysis_report.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    print(f"   ✅ 分析完成，报告已保存至: {report_path}")

    return {
        "package": app,
        "leaks": list(leaks),
        "leak_records": normalized_leaks,
        "leak_summary": leak_summary,
        "leak_by_source": leak_by_source,
        "api_privacy_result": api_privacy_result,
        "api_simplified_result": api_simplified_result,
    }


def analyze_batch(data_path, device_info_path, sdk_info_path=None):
    """
    批量分析所有应用
    """
    results = []

    # 获取所有应用目录
    apps = []
    for name in os.listdir(data_path):
        app_dir = os.path.join(data_path, name)
        if os.path.isdir(app_dir):
            # 检查是否有 mitm.mitm 或其他数据文件
            if (os.path.exists(os.path.join(app_dir, "mitm.mitm")) or
                    os.path.exists(os.path.join(app_dir, "crypt-1.txt")) or
                    os.path.exists(os.path.join(app_dir, "fs-1.txt"))):
                apps.append(name)

    print(f"\n🚀 开始批量分析 {len(apps)} 个应用...")

    for i, app in enumerate(apps, 1):
        print(f"\n[{i}/{len(apps)}] 分析应用: {app}")
        try:
            result = analyze_single(data_path, app, device_info_path, sdk_info_path)
            if result:
                results.append(result)
        except Exception as e:
            print(f"   ❌ 分析失败: {e}")
            import traceback
            traceback.print_exc()

    # 保存汇总结果
    summary_path = os.path.join(data_path, "analysis_summary.json")
    summary = {
        "total_apps": len(apps),
        "analyzed_apps": len(results),
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "apps": [
            {
                "package": r["package"],
                "total_leaks": r["leak_summary"]["total_leaks"],
                "encrypted_count": r["leak_summary"]["encrypted_count"],
                "plaintext_count": r["leak_summary"]["plaintext_count"],
            }
            for r in results
        ]
    }

    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 批量分析完成，汇总保存至: {summary_path}")

    return results

# ==================== 命令行入口 ====================
if __name__ == "__main__":
    import argparse

    # ==================== 默认配置 ====================
    BASE_PATH = r"G:\iie\mylab\guitest\Explorer\analysis"

    # 配置文件路径（都在 analysis 目录下）
    DEFAULT_SDK_INFO = os.path.join(BASE_PATH, "sdk_info.json")
    DEFAULT_API_INFO = os.path.join(BASE_PATH, "api_info.json")
    DEFAULT_IT_INFO = os.path.join(BASE_PATH, "it_info.json")
    DEFAULT_DEVICE_INFO = os.path.join(BASE_PATH, "device_info.json")  # 全局设备信息

    # 数据目录（包含各个应用的子目录）
    DEFAULT_DATA_PATH = os.path.join(BASE_PATH, "sacbot")

    SINGLE_APP ="com.luna.music"
    # 单个应用分析（设为 None 则批量分析所有应用）
    #SINGLE_APP = "com.kmxs.reader_noapi"
    #SINGLE_APP = "com.kmxs.reader_nowidgt"
    #SINGLE_APP = "com.kmxs.reader_noescape"
    #SINGLE_APP = "com.gotokeep.keep"


    # ==================== 解析命令行参数 ====================
    parser = argparse.ArgumentParser(description="隐私泄露分析工具")
    parser.add_argument("--path", default=DEFAULT_DATA_PATH,
                        help=f"数据目录路径 (默认: {DEFAULT_DATA_PATH})")
    parser.add_argument("--app", default=SINGLE_APP,
                        help="指定应用包名（不指定则批量分析）")
    parser.add_argument("--sdk-info", default=DEFAULT_SDK_INFO,
                        help="SDK 信息文件路径")
    parser.add_argument("--device-info", default=DEFAULT_DEVICE_INFO,
                        help="设备信息文件路径")

    args = parser.parse_args()

    # ==================== 打印配置信息 ====================
    print("=" * 60)
    print("🔧 分析配置")
    print("=" * 60)
    print(f"   📂 数据目录: {args.path}")
    print(f"   📱 目标应用: {args.app if args.app else '全部应用'}")
    print(f"   📄 SDK 信息: {args.sdk_info}")
    print(f"   📄 设备信息: {args.device_info}")
    print("=" * 60)

    # ==================== 执行分析 ====================
    if args.app:
        result = analyze_single(args.path, args.app, args.device_info, args.sdk_info,DEFAULT_API_INFO,DEFAULT_IT_INFO)
    else:
        results = analyze_batch(args.path, args.device_info, args.sdk_info)

