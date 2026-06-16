from PIL import Image
from io import BytesIO
import numpy as np
from utils.screen_util import toimage
import cv2
from loguru import logger
class Widget:
    def __init__(self, text, text_class, bounds, operatable, widget_udid, current_screen,
                 resource_id='', class_string='', scrollable='false', content_desc='', index=''):
        self.text = text
        self.text_class = text_class
        self.bounds = bounds
        self.operatable = operatable
        self.widget_udid = widget_udid
        self.screen = self.crop_screen(current_screen)

        self.resource_id = resource_id
        self.class_string = class_string
        self.scrollable = scrollable
        self.content_desc = content_desc
        self.index = index

        self.nextGUI = None
        self.visitCount = 0
        self.shallow_visitCount = 0
        self.GUITrans = False
        self.maxVisitCount = 2
        self.nextGUIWidgetSet = set()
        self.sensitive_apis_trigged = []
        self.sensitive_apis_trigged_num = 0


    def crop_screen(self, current_screen):
        if current_screen is None:
            return None
        # --- 1. 将输入 current_screen 统一转换为 NumPy 数组 (np_screen) ---
        if isinstance(current_screen, Image.Image):
            # 如果是 PIL Image 对象，直接转换为 NumPy 数组
            # 注意：PIL 转换为 NumPy 已经是 RGB/BGR 格式，通常不需要解码
            np_screen = np.array(current_screen)
            # 如果 uiautomator2 返回的是 RGB 格式，cv2 操作可能需要 BGR 转换，但通常直接使用 np.array 即可
            
        elif isinstance(current_screen, bytes):
            # 如果是 Bytes 对象 (原始 PNG/JPEG 数据)，使用 cv2 解码
            try:
                np_screen = cv2.imdecode(np.frombuffer(current_screen, np.uint8), cv2.IMREAD_COLOR)
            except Exception as e:
                logger.error(f"Failed to decode bytes screen: {e}")
                return None
        else:
            # 如果是其他不支持的类型
            logger.error(f"Unsupported screen type passed to crop_screen: {type(current_screen)}")
            return None

        # 检查转换是否成功
        if np_screen is None:
            return None
        
        # --- 2. 裁剪逻辑 (保持不变) ---
        # 确保 bounds 是整数，防止切片错误
        x1 = int(self.bounds[0])
        y1 = int(self.bounds[1])
        x2 = int(self.bounds[2])
        y2 = int(self.bounds[3])

        # 裁剪操作：[y1:y2, x1:x2]
        screen_crop2 = np_screen[y1:y2, x1:x2]
        
        # --- 3. 重新编码为 PNG bytes (保持不变) ---
        # 检查裁剪结果是否为空 (例如 bounds 越界或面积为零)
        if screen_crop2.size == 0:
            return None
            
        temp2 = cv2.imencode('.png', screen_crop2)[1].tobytes() # 使用 tobytes() 代替 tostring() (Python 3 标准)
        
        return temp2

    def add_visit_count(self):
        self.visitCount += 1
        self.shallow_visitCount += 1

    def update_next_GUI(self, nextGUI):
        self.nextGUI = nextGUI

    def add_trigged_api(self,sens_api_name_list):
        for sens_api_name in sens_api_name_list:
            if sens_api_name not in self.sensitive_apis_trigged:
                self.sensitive_apis_trigged.append(sens_api_name)
                self.sensitive_apis_trigged_num += 1
