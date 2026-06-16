from androguard.core.bytecodes import apk
from collections import deque
import json
import os
from pathlib import Path
import zipfile
from androguard.core.bytecodes.apk import APK
import csv

def is_valid_apk(file_path):
    """检查文件是否为有效的 APK（即合法的 ZIP 文件）"""
    if not os.path.isfile(file_path):
        return False
    if os.path.getsize(file_path) == 0:
        return False
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            # 尝试读取 ZIP 目录（不展开内容）
            zf.testzip()  # 返回 None 表示无损坏，否则返回第一个损坏文件名
        return True
    except (zipfile.BadZipFile, OSError, ValueError):
        return False

def parse_pkg(apk_path, coverage_dict_template):
    a = apk.APK(apk_path)
    androguard_activities = a.get_activities()
    appPackage = a.get_package()
    appActivity = a.get_main_activity()
    permissions = a.get_permissions()
    for activity in androguard_activities:
        activity = activity.replace("..", ".")
        coverage_dict_template.update({activity: {'visited': False}})
    return appPackage, appActivity, permissions


def analyze(apk_path, coverage_dict_template):
    string_activities = '*'
    a = apk.APK(apk_path)
    activities, services, receivers, providers = find_exported_components(a)
    androguard_activities = a.get_activities()
    exported_activities = list()
    for activity in androguard_activities:
        activity = activity.replace("..", ".")
        coverage_dict_template.update({activity: {'visited': False}})
        for act in activities:
            if act in activity:
                exported_activities.append(activity)
    return exported_activities, services, receivers, providers, string_activities, a.package


def find_exported_components(apk):
    activities = list()
    services = list()
    receivers = list()
    providers = list()
    for tag in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ]:
        for item in apk.find_tags(tag):
            actions = deque()
            name = item.get(apk._ns("name"), "")
            exported = item.get(apk._ns("exported"), "")
            permission = item.get(apk._ns("permission"), "")

            if name.strip() and exported.lower() != "false":
                to_check = False
                has_actions_in_intent_filter = False
                for intent in item.findall("./intent-filter"):
                    for action in intent.findall("./action"):
                        my_action = action.get(apk._ns("name"), "")
                        if (my_action != 'edu.gatech.m3.emma.COLLECT_COVERAGE') and ('END_COVERAGE' not in
                                                                                     my_action) and ('END_EMMA' not in
                                                                                                     my_action):
                            actions.append(my_action)
                            has_actions_in_intent_filter = True

                if exported == "" and has_actions_in_intent_filter:
                    to_check = True

                if exported.lower() == "true":
                    to_check = True

                if to_check:
                    accessible = False
                    if not permission:
                        accessible = True
                    else:
                        detail = apk.get_declared_permissions_details().get(
                            permission
                        )
                        if detail:
                            level = detail["protectionLevel"]
                            if level == "None":
                                level = None
                            if (
                                    level
                                    and (
                                            int(level, 16) == 0x0
                                            or int(level, 16) == 0x1
                                    )
                            ) or not level:
                                accessible = True
                        else:
                            detail = apk.get_details_permissions().get(
                                permission
                            )
                            if detail:
                                level = detail[0].lower()
                                if level == "normal" or level == "dangerous":
                                    accessible = True
                    if accessible:
                        if (tag == "activity") or (tag == "activity-alias"):
                            activities.append(name)
                        elif tag == "service":
                            services.append({'type': 'service', 'name': name, 'action': actions})
                        elif tag == "receiver":
                            receivers.append({'type': 'receiver', 'name': name, 'action': actions})
                        elif tag == "provider":
                            providers.append({'type': 'provider', 'name': name, 'action': actions})
    return activities, services, receivers, providers


def get_app_label(apk_path):
    try:
        apk = APK(apk_path)
        package_name = apk.get_package()
        app_name = apk.get_app_name()  # 自动处理字符串资源，返回可读名称
        return package_name, app_name
    except Exception as e:
        print(f"❌ 解析失败: {apk_path} - {e}")
        return None, "N/A"


def process_apk_list_to_json(apk_paths, output_folder="apk_info_json"):
    """
    输入：APK 路径列表
    输出：在指定文件夹生成对应的 JSON 文件（包含中文应用名）
    """
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for apk_path in apk_paths:
        if not os.path.exists(apk_path):
            print(f"跳过：文件不存在 -> {apk_path}")
            continue
        if not is_valid_apk(apk_path):
            print(f"❌ 跳过无效 APK（非 ZIP 或已损坏）: {apk_path}")
            continue
        print(f"正在处理: {os.path.basename(apk_path)}...")

        raw_activity_info = {}
        pkg, main_act, perms = parse_pkg(apk_path, raw_activity_info)

        if not pkg:
            print(f"❌ 解析失败: {apk_path}")
            continue

        # ✅ 新增：提取中文应用名称
        app_name = get_app_label(apk_path)

        data_to_save = {
            "package_name": pkg,
            "app_name": app_name,  # ← 新增字段
            "main_activity": main_act,
            "permissions": perms,
            "activities": list(raw_activity_info.keys()),
            "total_activities": len(raw_activity_info)
        }

        file_name = os.path.splitext(os.path.basename(apk_path))[0] + ".json"
        folder_name = os.path.basename(os.path.dirname(apk_path))
        print(os.path.join(output_folder, file_name))
        save_path = os.path.join(output_folder, file_name)

        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=4, ensure_ascii=False)

        print(f"✅ 已保存至: {save_path} (App: '{app_name}', Activities: {len(raw_activity_info)})")


def get_app_info(apk_path):
    try:
        apk = APK(apk_path)
        package_name = apk.get_package()
        app_name = apk.get_app_name()  # 自动处理字符串资源，返回可读名称
        return package_name, app_name
    except Exception as e:
        print(f"❌ 解析失败: {apk_path} - {e}")
        return None, "N/A"

def get_app_info_main(apk_folder, output_csv):
    if not os.path.isdir(apk_folder):
        print(f"错误：'{apk_folder}' 不是有效文件夹")
        return

    apk_files = [f for f in os.listdir(apk_folder) if f.lower().endswith('.apk')]
    results = []

    for apk_file in apk_files:
        apk_path = os.path.join(apk_folder, apk_file)
        print(f"正在处理: {apk_file}")
        pkg, name = get_app_info(apk_path)
        # 如果文件名是 包名.apk，但我们仍以实际解析的包名为准（更可靠）
        results.append((pkg if pkg else apk_file[:-4], name))

    # 写入 CSV（UTF-8-BOM 保证 Excel 正确显示中文）
    with open(output_csv, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['Package Name', 'Display Name'])
        writer.writerows(results)

    print(f"\n✅ 完成！结果已保存到: {output_csv}")


# ================= 使用示例 =================
if __name__ == "__main__":
    # 1. 放入你的 APK 文件路径列表
    apk_dir = "G:\iie\mylab\guitest\Explorer//apps/ap5"
    #
    # apk_path = Path(apk_dir)
    # my_apks = [str(p) for p in apk_path.rglob("*.apk") if p.is_file()]
    # # 检查一下是否找到了文件
    # if not my_apks:
    #     print(f"提示：在文件夹 {apk_dir} 中没有找到任何 .apk 文件！")
    # else:
    #     print(f"找到 {len(my_apks)} 个 APK 文件，准备开始分析...")
    #
    #     # 3. 执行批量转换
    #     output_dir = "G:\iie\mylab\guitest\Explorer/apps/ap5/ap4info"
    #     process_apk_list_to_json(my_apks, output_folder=output_dir)
    get_app_info_main(r"G:\iie\mylab\guitest\Explorer\apps\ap6end",r"G:\iie\mylab\guitest\Explorer\apps\ap6\infoyes.csv")
