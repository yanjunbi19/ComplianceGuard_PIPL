import os
from os import path

# 扫描文件夹列表,获取app
def scan_file(url):
    if path.isfile(url):
        return [url]
    file_names = []
    file_list = os.listdir(url)
    file_list.sort()
    for file_item in file_list:
        file_name = path.join(url,file_item)
        file_names.append(file_name)
    return file_names

def parse_pages(widget_list):
    for widget in widget_list:
        # user agreements

        if widget[0] == '我同意' or widget[0].find('同意')==0 or widget[0] == 'Agree':
            coord_list = [widget[2][0] * 1080, widget[2][1] * 1920, widget[2][2] * 1080, widget[2][3] * 1920]
            x,y = (coord_list[0] + coord_list[2])/2, (coord_list[1] + coord_list[3])/2
            print(f"🎯 匹配成功！准备点击文本: '{widget[0]}'")
            return (x,y), False
    for widget in widget_list:
        # slide UI pages
        if 'ViewPager' in widget[5]:
            x_diff = widget[2][2] - widget[2][0]
            y_diff = widget[2][3] - widget[2][1]
            if x_diff >= 0.9 and y_diff >= 0.7:
                coord_list = [widget[2][0] * 1080, widget[2][1] * 1920, widget[2][2] * 1080, widget[2][3] * 1920]
                x, y = (coord_list[0] + coord_list[2]) / 2, (coord_list[1] + coord_list[3]) / 2
                return (x,y), True
    return None, None

from loguru import logger

def parse_pages1(widget_list, screen_w=1080, screen_h=1920):
    def norm_text(x):
        if x is None:
            return ""
        return str(x).strip().replace("\n", "").replace(" ", "")

    agree_keywords = [
        "我同意",
        "同意并继续",
        "已阅读并同意",
        "同意",
        "允许并继续",
        "允许",
        "接受",
        "Agree",
        "Accept",
        "继续"
    ]

    for i, widget in enumerate(widget_list):
        try:
            text = norm_text(widget[0]) if len(widget) > 0 else ""
            cls = str(widget[5]) if len(widget) > 5 else ""
            bounds = widget[2] if len(widget) > 2 else None

            logger.debug(f"[GateScan] idx={i}, text={text!r}, cls={cls!r}, bounds={bounds}")

            if any(k in text for k in agree_keywords):
                coord_list = [
                    bounds[0] * screen_w,
                    bounds[1] * screen_h,
                    bounds[2] * screen_w,
                    bounds[3] * screen_h
                ]
                x = (coord_list[0] + coord_list[2]) / 2
                y = (coord_list[1] + coord_list[3]) / 2
                logger.info(f"🎯 匹配成功！准备点击文本: {text!r}, click=({x},{y})")
                return (x, y), False
        except Exception as e:
            logger.warning(f"parse_pages scan error at idx={i}: {e}")

    for i, widget in enumerate(widget_list):
        try:
            cls = str(widget[5]) if len(widget) > 5 else ""
            bounds = widget[2] if len(widget) > 2 else None
            if 'ViewPager' in cls:
                x_diff = bounds[2] - bounds[0]
                y_diff = bounds[3] - bounds[1]
                if x_diff >= 0.9 and y_diff >= 0.7:
                    coord_list = [
                        bounds[0] * screen_w,
                        bounds[1] * screen_h,
                        bounds[2] * screen_w,
                        bounds[3] * screen_h
                    ]
                    x = (coord_list[0] + coord_list[2]) / 2
                    y = (coord_list[1] + coord_list[3]) / 2
                    logger.info(f"🎯 匹配到引导页滑动区域, swipe center=({x},{y})")
                    return (x, y), True
        except Exception as e:
            logger.warning(f"parse_pages ViewPager scan error at idx={i}: {e}")

    return None, None
