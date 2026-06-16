'''
按照指定的APP名称，从华为应用商店爬取隐私政策html链接，保存html文件
'''

import os
import re
import csv
import time
from urllib.parse import quote

from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException


# =========================
# 配置区
# =========================
# APP_LIST =[
#     "无尽分身",
#     "中华万年历HD",
#     "九号出行",
#     "WPS",
#     "学习强国",
#     "阿里巴巴",
#     "小度",
#     "作业帮",
#     "百度贴吧",
#     "悦龄生活",
#     "悟空浏览器",
#     "央视频",
#     "汽车之家",
#     "Deepseek",
#     "亲宝宝",
#     "中国移动",
#     "海康互联",
#     "扫描全能王",
#     "哈啰",
#     "百词斩",
#     "乔安智联",
#     "快影",
#     "豆包",
#     "美柚",
#     "乐橙",
#     "小鹰看看",
#     "夸克",
#     "美团",
#     "滴滴出行",
#     "网上国网",
#     "中国联通",
#     "今日头条",
#     "AI抖音",
#     "皮皮虾",
#     "闲鱼",
#     "淘宝特价版",
#     "QQ邮箱",
#     "TP-LINK物联",
#     "58同城",
#     "盒马",
#     "小红书",
#     "醒图",
#     "迅雷",
#     "拼多多",
#     "网易有道词典",
#     "万年历",
#     "小翼管家",
#     "智联招聘",
#     "知乎"
# ]
# APP_LIST=[
#     "唯品会",
#     "AI天气",
#     "安居客",
#     "菜鸟",
#     "快手极速版",
#     "剪映",
#     "贝壳找房",
#     "汽水音乐",
#     "墨迹天气",
#     "Seetong",
#     "WiFi万能钥匙",
#     "今日头条极速版",
#     "抖音火山版",
#     "抖音商城",
#     "同程旅行",
#     "番茄音乐（原畅听音乐）",
#     "携程旅行",
#     "饿了么",
#     "大麦",
#     "AI恋爱聊天键盘",
#     "千问",
#     "灵光",
#     "高德地图",
#     "百度地图",
#     "百度",
#     "Days Matter",
#     "移动爱家",
#     "手机闹钟",
#     "斑马百科",
#     "桌面时间",
#     "高途",
#     "Phone Clone",
#     "守护旺旺",
#     "考试一点通",
#     "公考雷达",
#     "360智慧生活",
#     "夸克",
#     "猫眼",
#     "搜狐新闻",
#     "抖音",
#     "闲鱼",
#     "淘宝特价版",
#     "测网速UUSpeed",
#     "我爱我家",
#     "WiFi万能高手",
#     "智能闹钟时钟",
#     "高能畅行导航",
#     "好课在线",
#     "博看书苑"
# ]
# 打印列表验证
# APP_LIST=[
#     "猫耳FM",
#     "百度",
#     "粉笔",
#     "手机克隆",
#     "WiFi万能钥匙"
# ]
APP_LIST= [
    "微信", "淘宝", "快手", "京东", "哔哩哔哩", "微博", "腾讯视频", "优酷视频",
    "钉钉", "企业微信", "UC浏览器", "酷狗音乐", "网易云音乐", "喜马拉雅",
    "西瓜视频", "Soul", "探探", "BOSS直聘", "飞书", "腾讯会议", "百度网盘",
    "QQ浏览器", "得物", "美团外卖", "大众点评", "去哪儿旅行", "云闪付",
    "招商银行", "平安口袋银行", "买单吧", "浦发银行", "中信银行", "东方财富",
    "雪球", "天天基金", "滴滴车主", "运满满", "曹操出行", "山姆会员商店",
    "多点", "永辉线上超市", "比亚迪", "米家", "斗鱼", "虎牙直播",
    "掌上英雄联盟", "元宝", "国家医保服务平台", "驾考宝典", "多邻国",
    "美图秀秀", "美颜相机", "下厨房", "芒果TV", "咪咕视频"
]
print(APP_LIST)
print(f"总计应用数量: {len(APP_LIST)}")
WAIT_TIMEOUT = 20

# chromedriver 路径：放脚本同目录下
CHROMEDRIVER_PATH = os.path.join(os.getcwd(), "chromedriver.exe")

# 保存目录
SAVE_DIR = r"G:\iie\lab8\privacypolicy\save_search"   # 建议用 raw string

# CSV 索引文件
CSV_PATH = os.path.join(SAVE_DIR, "huawei_privacy_index_from_search.csv")

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/127.0.0.0 Safari/537.36")


# =========================
# 工具函数
# =========================
def sanitize_filename(name: str) -> str:
    return re.sub(r'[\\/*?:"<>|]', ' ', name).strip()


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def accept_cookie_if_present(driver, timeout=6):
    try:
        cookie_button_xpath = "//div[@class='acceptAll' and (text()='同意' or contains(.,'同意'))]"
        WebDriverWait(driver, timeout).until(
            EC.element_to_be_clickable((By.XPATH, cookie_button_xpath))
        ).click()
        time.sleep(0.3)
    except Exception:
        pass


def open_first_app_detail_from_search(driver, keyword, wait_timeout=20):
    """
    打开搜索页，点击第一个结果的卡片主体（标题/图标），进入 /app/ 详情页
    返回：(real_app_name, detail_url)
    """
    ts = int(time.time() * 1000)
    search_url = f"https://appgallery.huawei.com/search/{quote(keyword)}?{ts}"
    driver.get(search_url)

    accept_cookie_if_present(driver)

    # 等搜索标题出现
    WebDriverWait(driver, wait_timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "p.searchTitle"))
    )

    # 若有加载中，等待消失
    try:
        WebDriverWait(driver, wait_timeout).until(
            EC.invisibility_of_element_located((By.CSS_SELECTOR, "div.tab-loading"))
        )
    except Exception:
        pass

    # 取第一个条目(i="0")里的第一张卡片
    cards = WebDriverWait(driver, wait_timeout).until(
        lambda d: d.find_elements(
            By.CSS_SELECTOR,
            "div.search.router-view div.content div[i='0'] div.tem.tem-big"
        )
    )
    if not cards:
        raise RuntimeError("未找到搜索结果卡片 div.tem.tem-big（页面结构可能更新）。")

    first_card = cards[0]

    # 读取卡片标题作为 app_name（用于文件名）
    try:
        real_app_name = first_card.find_element(By.CSS_SELECTOR, "div.intro_left > p").text.strip()
        if not real_app_name:
            real_app_name = keyword
    except Exception:
        real_app_name = keyword

    # 点击：尽量点标题/图标，避免点到“安装”
    clicked = False
    for css in ["div.intro_left > p", "img", "div.intro_left", "div.intro"]:
        try:
            el = first_card.find_element(By.CSS_SELECTOR, css)
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
            time.sleep(0.2)
            try:
                el.click()
            except WebDriverException:
                driver.execute_script("arguments[0].click();", el)
            clicked = True
            break
        except Exception:
            continue

    if not clicked:
        driver.execute_script("arguments[0].scrollIntoView({block:'center'});", first_card)
        time.sleep(0.2)
        driver.execute_script("arguments[0].click();", first_card)

    # 新开窗口/同窗口兼容
    old_url = driver.current_url
    old_handles = driver.window_handles
    time.sleep(0.8)
    new_handles = driver.window_handles
    if len(new_handles) > len(old_handles):
        driver.switch_to.window(new_handles[-1])

    # 等进入详情页
    WebDriverWait(driver, wait_timeout).until(lambda d: "/app/" in d.current_url and d.current_url != old_url)
    return real_app_name, driver.current_url


def open_privacy_policy_page(driver, wait_timeout=20):
    """
    在 APP 详情页点击“隐私政策”，并切换到隐私政策页
    返回：(privacy_url, opened_new_tab: bool)
    """
    detail_url = driver.current_url
    old_handles = driver.window_handles

    # 多策略定位“隐私政策”
    privacy_locators = [
        (By.XPATH, "//div[contains(@class,'appSingleInfo') and .//div[normalize-space()='隐私政策']]"),
        (By.XPATH, "//*[normalize-space()='隐私政策']"),
        (By.XPATH, "//*[contains(normalize-space(),'隐私政策')]"),
    ]

    last_err = None
    for locator in privacy_locators:
        try:
            el = WebDriverWait(driver, wait_timeout).until(EC.presence_of_element_located(locator))
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", el)
            time.sleep(0.3)
            WebDriverWait(driver, wait_timeout).until(EC.element_to_be_clickable(locator))
            try:
                el.click()
            except WebDriverException:
                driver.execute_script("arguments[0].click();", el)
            last_err = None
            break
        except Exception as e:
            last_err = e

    if last_err:
        raise RuntimeError(f"未能点击到“隐私政策”入口：{last_err}")

    # 可能新开tab，也可能同tab跳转
    opened_new_tab = False
    try:
        WebDriverWait(driver, 4).until(lambda d: len(d.window_handles) > len(old_handles))
        opened_new_tab = True
    except TimeoutException:
        opened_new_tab = False

    if opened_new_tab:
        driver.switch_to.window(driver.window_handles[-1])
    else:
        WebDriverWait(driver, wait_timeout).until(lambda d: d.current_url != detail_url)

    privacy_url = driver.current_url
    return privacy_url, opened_new_tab


def wait_privacy_content_loaded(driver, timeout=8):
    """
    隐私政策页很多是动态渲染。尽量等一个标志性内容出现。
    不同隐私政策页面结构可能不同，所以做多策略等待。
    """
    selectors = [
        "#content-con",         # 你原来用的容器
        "#content-con h1",
        "body"
    ]
    start = time.time()
    while time.time() - start < timeout:
        for css in selectors:
            try:
                els = driver.find_elements(By.CSS_SELECTOR, css)
                if els:
                    txt = els[0].text.strip()
                    # body 可能一直有，但没内容；简单判断一下长度
                    if css != "body" or len(txt) > 50:
                        return
            except Exception:
                pass
        time.sleep(0.3)
    # 超时也继续保存（可能内容较短或结构不同）


# =========================
# 主程序
# =========================
def main():
    ensure_dir(SAVE_DIR)

    if not os.path.exists(CHROMEDRIVER_PATH):
        raise FileNotFoundError(f"chromedriver.exe 不存在：{CHROMEDRIVER_PATH}")

    # Chrome 配置
    options = ChromeOptions()
    # options.add_argument("--headless=new")  # 需要无头就取消注释
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    options.add_argument("--no-sandbox")
    options.add_argument("--start-maximized")
    options.add_argument(f"user-agent={USER_AGENT}")

    service = ChromeService(executable_path=CHROMEDRIVER_PATH)
    driver = webdriver.Chrome(service=service, options=options)

    # 降低 webdriver 特征
    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
        'source': "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
    })

    rows = []
    try:
        for keyword in APP_LIST:
            print(f"\n=== 处理关键词：{keyword} ===")
            keyword_dir = os.path.join(SAVE_DIR, sanitize_filename(keyword))
            ensure_dir(keyword_dir)

            # 1) 搜索并进入第一个 app 详情页
            app_name, detail_url = open_first_app_detail_from_search(driver, keyword, WAIT_TIMEOUT)
            print(f"[+] 详情页：{detail_url}")
            print(f"[+] AppName：{app_name}")

            detail_handle = driver.current_window_handle

            # 2) 点击隐私政策并切换到隐私页
            privacy_url, opened_new_tab = open_privacy_policy_page(driver, WAIT_TIMEOUT)
            print(f"[+] 隐私政策URL：{privacy_url} (new_tab={opened_new_tab})")

            # 3) 等待内容加载并保存 HTML
            wait_privacy_content_loaded(driver, timeout=8)

            html = driver.page_source
            file_name = sanitize_filename(app_name) or sanitize_filename(keyword)
            file_path = os.path.join(keyword_dir, f"{file_name}.html")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[+] 已保存：{file_path}")

            # 4) 关闭隐私页并回到详情页/搜索流程
            if opened_new_tab and len(driver.window_handles) > 1:
                driver.close()
                driver.switch_to.window(detail_handle)
            else:
                # 同窗口跳转的情况：返回详情页（可选）
                try:
                    driver.back()
                    time.sleep(0.5)
                except Exception:
                    pass

            rows.append({
                "Keyword": keyword,
                "AppName": app_name,
                "DetailURL": detail_url,
                "PrivacyPolicyURL": privacy_url,
                "LocalHTMLPath": file_path
            })

        # 5) 写 CSV
        file_exists = os.path.isfile(CSV_PATH)
        with open(CSV_PATH, "a" if file_exists else "w", encoding="utf-8-sig", newline="") as f:
            fieldnames = ["Keyword", "AppName", "DetailURL", "PrivacyPolicyURL", "LocalHTMLPath"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerows(rows)

        print(f"\n[+] 全部完成，CSV：{CSV_PATH}，共写入 {len(rows)} 条。")

    finally:
        driver.quit()


if __name__ == "__main__":
    main()