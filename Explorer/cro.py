# extract_crypto_double_base64.py - 支持双重 Base64 编码

import json
import base64
import sys
import os


def decode_double_base64(data_str):
    """
    解码双重 Base64 编码的数据

    步骤：
    1. 第一次 Base64 解码 -> 得到字符串形式的字节数组
    2. 解析字节数组 -> 得到真实字节数据

    Args:
        data_str: 可能是双重编码的字符串

    Returns:
        bytes: 解码后的字节数据
    """
    if not data_str:
        return b""

    # 移除换行符
    data_str = data_str.strip()

    # 第一次 Base64 解码
    try:
        decoded_once = base64.b64decode(data_str)
        decoded_str = decoded_once.decode('utf-8')

        # 检查是否是字节数组格式（逗号分隔的数字）
        if ',' in decoded_str and all(part.strip().lstrip('-').isdigit() for part in decoded_str.split(',')):
            # 第二次解析：字节数组字符串 -> 字节
            numbers = [int(n.strip()) for n in decoded_str.split(',')]
            # 处理负数（转换为无符号字节）
            unsigned = [(n + 256) if n < 0 else n for n in numbers]
            return bytes(unsigned)
        else:
            # 不是字节数组，直接返回第一次解码的结果
            return decoded_once

    except Exception as e:
        # 如果解码失败，返回原始字符串
        return data_str.encode('utf-8', errors='ignore')


def format_data(data, name="Data"):
    """格式化显示数据"""
    if not data:
        return f"{name}: (empty)\n"

    lines = [f"\n{name}:"]
    lines.append(f"  长度: {len(data)} bytes")

    # 1. 尝试显示为文本
    try:
        text = data.decode('utf-8', errors='ignore')
        # 检查是否大部分可打印
        printable_ratio = sum(1 for c in text if c.isprintable() or c in '\n\r\t') / len(text)
        if printable_ratio > 0.8:
            display_text = text[:500]
            lines.append(f"  [文本] {display_text}")
            if len(text) > 500:
                lines.append(f"         ... (共 {len(text)} 字符)")
    except:
        pass

    # 2. 显示十六进制
    hex_str = data.hex()
    if len(hex_str) <= 100:
        lines.append(f"  [Hex] {hex_str}")
    else:
        lines.append(f"  [Hex] {hex_str[:100]}...")
        lines.append(f"        (共 {len(data)} bytes)")

    # 3. 如果数据较短，显示字节数组
    if len(data) <= 32:
        byte_array = ','.join(str(b) for b in data)
        lines.append(f"  [字节] {byte_array}")

    return '\n'.join(lines)


def extract_crypto_data(crypt_file, output_dir=None):
    """提取加密数据"""

    if not os.path.exists(crypt_file):
        print(f"❌ 文件不存在: {crypt_file}")
        return

    # 设置输出目录
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(crypt_file), "extracted_crypto")

    os.makedirs(output_dir, exist_ok=True)

    print(f"📂 输出目录: {output_dir}\n")

    # 读取文件
    with open(crypt_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    print(f"📊 共 {len(lines)} 条记录\n")

    # 处理每条记录
    for i, line in enumerate(lines, 1):
        try:
            record = json.loads(line.strip())

            class_name = record.get('class_name', 'unknown')
            method_name = record.get('method_name', 'unknown')

            # 创建输出文件
            safe_class = class_name.split('.')[-1].replace('$', '_')
            output_file = os.path.join(output_dir, f"{i:04d}_{safe_class}_{method_name}.txt")

            with open(output_file, 'w', encoding='utf-8') as out:
                # 元信息
                out.write(f"{'=' * 70}\n")
                out.write(f"记录 #{i}\n")
                out.write(f"{'=' * 70}\n")
                out.write(f"类名: {class_name}\n")
                out.write(f"方法: {method_name}\n")
                out.write(f"时间: {record.get('ts', 'N/A')}\n")
                out.write(f"{'=' * 70}\n")

                # 处理参数
                args = record.get('args', [])
                for j, arg in enumerate(args, 1):
                    try:
                        decoded = decode_double_base64(arg)
                        formatted = format_data(decoded, f"参数 {j}")
                        out.write(formatted + "\n")
                    except Exception as e:
                        out.write(f"\n参数 {j}: 解码失败 - {e}\n")

                # 处理返回值
                ret = record.get('ret', '')
                if ret:
                    try:
                        decoded = decode_double_base64(ret)
                        formatted = format_data(decoded, "返回值")
                        out.write(formatted + "\n")
                    except Exception as e:
                        out.write(f"\n返回值: 解码失败 - {e}\n")

                # 处理堆栈跟踪
                if 'stackTrace' in record and record['stackTrace']:
                    try:
                        stack = decode_double_base64(record['stackTrace'])
                        stack_text = stack.decode('utf-8', errors='ignore')
                        out.write(f"\n堆栈跟踪:\n{'-' * 70}\n{stack_text}\n")
                    except Exception as e:
                        out.write(f"\n堆栈跟踪: 解码失败 - {e}\n")

            # 显示进度
            if i % 10 == 0 or i == len(lines):
                print(f"✅ 已处理: {i}/{len(lines)}")

        except Exception as e:
            print(f"⚠️ 记录 {i} 处理失败: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n✅ 完成！数据已保存到: {output_dir}")

    # 显示第一个文件的内容作为示例
    files = sorted(os.listdir(output_dir))
    if files:
        print(f"\n{'=' * 70}")
        print(f"📄 示例文件内容 ({files[0]}):")
        print(f"{'=' * 70}")
        with open(os.path.join(output_dir, files[0]), 'r', encoding='utf-8') as f:
            content = f.read()
            print(content[:800])
            if len(content) > 800:
                print("\n... (内容过长，已截断)")


def main():
    crypt_file = "G:\iie\mylab\guitest\Explorer\\analysis\com.kmxs.reader\\crypt-1.txt"
    output_dir="G:\iie\mylab\guitest\Explorer\\analysis\com.kmxs.reader\c"
    extract_crypto_data(crypt_file, output_dir)


if __name__ == "__main__":
    main()
