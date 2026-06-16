'''
从华为应用商店爬取隐私政策html链接，保存html文件,以及记录的表格
'''

r'''
AppName,Category,PrivacyPolicyURL,LocalHTMLPath
红果免费短剧,影音娱乐,https://reading.snssdk.com/wap-hongguo/dr-privacy-v3-ad.html,G:\iie\lab8\privacypolicy\save\影音娱乐\红果免费短剧.html
'''
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, StaleElementReferenceException
from loguru import logger
from selenium import webdriver

from webdriver_manager.chrome import ChromeDriverManager

import time
import os
import csv
import re  # 导入re模块，用于清理文件名

# --------------------------
# 配置区域
# --------------------------
BASE_URL = "https://appgallery.huawei.com/Apps"
#CLASSES = ["实用工具","影音娱乐","社交通讯","教育","新闻阅读","拍摄美化","美食","出行导航","旅游住宿","购物比价","商务","儿童","金融理财","运动健康","便捷生活","汽车"]
CLASSES = ["运动健康","便捷生活","汽车"]

WAIT_TIMEOUT = 20
TARGET_APP_COUNT = 1
# [新] HTML保存路径
HTML_SAVE_PATH = r"G:\iie\lab8\privacypolicy\save"

# --------------------------
# 日志设置
# --------------------------
logger.add("crawler_native_selenium.log", rotation="10 MB", level="INFO", encoding='utf-8')


# --------------------------
# [新] 辅助函数：清理文件名中的非法字符
# --------------------------
def sanitize_filename(filename):
    """移除文件名中的非法字符，替换为空格"""
    return re.sub(r'[\\/*?:"<>|]', ' ', filename)


# --------------------------
# 主程序
# --------------------------
if __name__ == "__main__":
    driver = None
    all_app_data = []  # 改为列表，因为要按顺序保存

    try:
        logger.info("初始化原生 Selenium WebDriver...")
        # ... (您的 WebDriver 初始化代码) ...
        driver_path = os.path.join(os.getcwd(), "chromedriver.exe")
        if not os.path.exists(driver_path):
            logger.error(f"错误: chromedriver.exe 不在脚本目录中！路径: {driver_path}")
            exit()
        service = ChromeService(executable_path=driver_path)
        options = ChromeOptions()
        # options.add_argument("--headless=new")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.add_argument("--no-sandbox")
        options.add_argument("--start-maximized")
        options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
        driver = webdriver.Chrome(service=service, options=options)
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        })
        logger.success("原生 Selenium WebDriver 初始化成功！")

        # --- 步骤一：访问页面并处理 Cookie 横幅 ---
        driver.get(BASE_URL)
        logger.info(f"成功访问页面：{BASE_URL}")
        try:
            cookie_button_xpath = "//div[@class='acceptAll' and text()='同意']"
            cookie_button = WebDriverWait(driver, 15).until(EC.element_to_be_clickable((By.XPATH, cookie_button_xpath)))
            cookie_button.click()
            logger.success("Cookie 同意按钮已成功点击。")
            time.sleep(1)
        except Exception:
            logger.info("未找到或无需点击 Cookie 同意按钮。")

        # --- 步骤二：循环处理每个分类 ---
        for class_name in CLASSES:
            logger.info(f"=== 开始处理分类：'{class_name}' ===")

            # [新] 为每个分类创建子文件夹
            category_save_path = os.path.join(HTML_SAVE_PATH, sanitize_filename(class_name))
            os.makedirs(category_save_path, exist_ok=True)
            logger.info(f"HTML内容将保存到: {category_save_path}")

            collected_count_in_category = 0
            processed_app_names = set()

            while collected_count_in_category < TARGET_APP_COUNT:

                try:
                    logger.info("确保在正确的分类列表页...")
                    if BASE_URL not in driver.current_url:
                        driver.get(BASE_URL)
                        time.sleep(2)
                    category_xpath = f"//span[contains(@class, 'childtab') and text()='{class_name}']"
                    category_element = WebDriverWait(driver, WAIT_TIMEOUT).until(
                        EC.element_to_be_clickable((By.XPATH, category_xpath)))
                    driver.execute_script("arguments[0].click();", category_element)
                    time.sleep(3)
                except Exception as e:
                    logger.error(f"无法导航到分类 '{class_name}' 的列表页，跳过此分类。错误: {e}")
                    break

                card_to_process = None
                app_name_to_process = None

                for _ in range(5):
                    app_cards = driver.find_elements(By.CSS_SELECTOR, "div.item")
                    for card in app_cards:
                        try:
                            app_name = card.find_element(By.CSS_SELECTOR, ".name").text.strip()
                            if app_name not in processed_app_names:
                                card_to_process = card
                                app_name_to_process = app_name
                                break
                        except Exception:
                            continue
                    if card_to_process:
                        break
                    else:
                        logger.info("当前页面无新应用，向下滚动...")
                        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                        time.sleep(4)

                if not card_to_process:
                    logger.warning(f"滚动多次后仍未找到新应用，结束对分类 '{class_name}' 的处理。")
                    break

                try:
                    logger.info(
                        f"正在处理 ({collected_count_in_category + 1}/{TARGET_APP_COUNT}): {app_name_to_process}")

                    card_to_process.click()

                    privacy_url = "NOT_FOUND"
                    detail_page_window = driver.current_window_handle

                    privacy_button_locator = (
                    By.XPATH, "//div[contains(@class, 'appSingleInfo') and .//div[text()='隐私政策']]")
                    privacy_button = WebDriverWait(driver, WAIT_TIMEOUT).until(
                        EC.presence_of_element_located(privacy_button_locator))
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", privacy_button)
                    time.sleep(1)
                    WebDriverWait(driver, WAIT_TIMEOUT).until(
                        EC.element_to_be_clickable(privacy_button_locator)).click()

                    WebDriverWait(driver, WAIT_TIMEOUT).until(EC.number_of_windows_to_be(2))

                    driver.switch_to.window(driver.window_handles[-1])
                    privacy_url = driver.current_url
                    logger.success(f"成功获取隐私政策URL: {privacy_url}")
                    # --- [关键修改] ---
                    # 等待动态内容加载完成
                    # 页面使用JS动态加载内容，我们需要等待一个标志性元素出现。
                    # 通过分析HTML源码，我们发现内容被加载到 <div id="content-con"> 中，
                    # 并且会有一个 <h1> 标题。我们就等待这个标题出现。
                    try:
                        logger.info("正在等待隐私政策的动态内容加载...")
                        # 设置一个专门用于等待内容的超时时间，例如15秒
                        wait_timeout_for_content = 3
                        WebDriverWait(driver, wait_timeout_for_content).until(
                            # 等待CSS选择器为 #content-con h1 的元素出现
                            EC.presence_of_element_located((By.CSS_SELECTOR, "#content-con h1"))
                        )
                        logger.success("动态内容加载完成！")
                    except TimeoutException:
                        # 如果超时了，打印一个警告，但程序可以继续，只是保存的HTML可能不完整
                        logger.warning(f"在 {wait_timeout_for_content} 秒内未等到动态内容加载完成，保存的HTML可能不完整。")
                    # [关键新增] 保存HTML源码
                    page_source = driver.page_source
                    clean_app_name = sanitize_filename(app_name_to_process)
                    file_path = os.path.join(category_save_path, f"{clean_app_name}.html")
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(page_source)
                    logger.success(f"HTML已保存到: {file_path}")

                    driver.close()
                    driver.switch_to.window(detail_page_window)

                    # 记录数据
                    all_app_data.append({
                        "AppName": app_name_to_process,
                        "Category": class_name,
                        "PrivacyPolicyURL": privacy_url,
                        "LocalHTMLPath": file_path
                    })
                    processed_app_names.add(app_name_to_process)
                    collected_count_in_category += 1

                except Exception as e:
                    logger.error(f"处理应用 '{app_name_to_process}' 时出错: {e}")
                    processed_app_names.add(app_name_to_process)

            logger.success(f"分类 '{class_name}' 爬取完成，共获得 {collected_count_in_category} 条记录。")

        # --- 步骤三：保存CSV数据 ---
        logger.info("所有分类处理完毕，正在保存CSV索引文件...")
        output_file = os.path.join(HTML_SAVE_PATH,"huawei_apps_privacy_index.csv")
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        # with open(output_file, "w", encoding="utf-8-sig", newline='') as f:
        #     # 定义表头
        #     fieldnames = ["AppName", "Category", "PrivacyPolicyURL", "LocalHTMLPath"]
        #     writer = csv.DictWriter(f, fieldnames=fieldnames)
        #     writer.writeheader()
        #     writer.writerows(all_app_data)
        file_exists = os.path.isfile(output_file)
        with open(output_file, "a" if file_exists else "w", encoding="utf-8-sig", newline='') as f:
            fieldnames = ["AppName", "Category", "PrivacyPolicyURL", "LocalHTMLPath"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            # 仅在新建文件时写入表头
            if not file_exists:
                writer.writeheader()

            writer.writerows(all_app_data)
        logger.success(f"所有数据索引已保存至 {output_file}，共 {len(all_app_data)} 条记录。")

    except Exception as e:
        logger.critical(f"程序发生致命错误: {e}", exc_info=True)
    finally:
        if driver:
            driver.quit()
            logger.info("WebDriver 已关闭。")
