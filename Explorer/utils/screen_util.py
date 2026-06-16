import cv2
import numpy as np
import torch
from PIL import Image
from io import BytesIO
from xml.etree import ElementTree as ET
import json
import os
from loguru import logger
def imread(path):
    im = Image.open(path)
    return np.array(im)


def save_gui_image(path, img_dict, quality=60, scale=0.5):
    """
    优化后的图片保存函数
    :param path: 保存目录
    :param img_dict: {文件名: 图片数据(PIL对象或bytes)}
    :param quality: JPEG 压缩质量 (1-100)，建议 50-70
    :param scale: 缩放比例，建议 0.5 (即长宽各减半)
    """
    for name, img_data in img_dict.items():
        try:
            # 1. 将数据转换为 PIL Image 对象
            if isinstance(img_data, bytes):
                img = Image.open(io.BytesIO(img_data))
            else:
                img = img_data  # 假设已经是 PIL 对象

            # 2. 转换为 RGB 模式 (JPEG 不支持 RGBA)
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")

            # 3. 缩放分辨率 (极大减小体积)
            if scale != 1.0:
                new_size = (int(img.width * scale), int(img.height * scale))
                # 使用 Image.Resampling.LANCZOS (新版) 或 Image.ANTIALIAS (旧版)
                img = img.resize(new_size, Image.LANCZOS)

            # 4. 保存为 JPEG 格式
            save_path = os.path.join(path, f"{name}.jpg")  # 改为 .jpg 扩展名
            img.save(save_path, "JPEG", quality=quality, optimize=True)

        except Exception as e:
            print(f"Error saving optimized image {name}: {e}")

def save_xml_file(path,xml_dict):
    for xml_name in xml_dict.keys():
        xml_file = xml_dict[xml_name]
        with open(path+'/'+xml_name+'.xml','w',encoding='utf-8') as f:
            f.writelines(xml_file)

# 保存json
def save_json_file(path,json_dict):
    with open(path+'/textual_semantics.json','w') as file_obj:
        json.dump(json_dict,file_obj)

def toimage(arr):
    data = np.asarray(arr)
    shape = list(data.shape)
    strdata = data.tostring()
    shape = (shape[1], shape[0])
    image = Image.frombytes('RGB', shape, strdata)
    return image

def fromimage(im):
    return np.array(im)

def imresize(arr, size,interp='bilinear'):
    im = toimage(arr)
    size = (size[1], size[0])
    func = {'nearest': 0, 'lanczos': 1, 'bilinear': 2, 'bicubic': 3, 'cubic': 3}
    imnew = im.resize(size, resample=func[interp])
    return fromimage(imnew)

def get_screen_rgb(im=None):
    MEAN_TORCH_BGR = np.array((103.53, 116.28, 123.675), dtype=np.float32).reshape((1, 3, 1, 1))
    STD_TORCH_BGR = np.array((57.375, 57.12, 58.395), dtype=np.float32).reshape((1, 3, 1, 1))
    func = {'nearest': 0, 'lanczos': 1, 'bilinear': 2, 'bicubic': 3, 'cubic': 3}
    imnew = im.resize((180,320), resample=func['bilinear'])
    img = fromimage(imnew)
    norm_img = (img[..., [2, 1, 0]] - MEAN_TORCH_BGR.flat) / STD_TORCH_BGR.flat
    norm_img = np.transpose(norm_img, (2, 0, 1))[np.newaxis, ...]
    norm_img = torch.autograd.Variable(torch.Tensor(norm_img)).cuda()
    return norm_img


def get_screen(param=None, flag=None):
    """
    将屏幕截图转换为 PyTorch Tensor。
    输入比例修正为: Width=180, Height=320 (符合手机竖屏特征)
    输出维度: (1, 3, 320, 180) -> [Batch, Channel, Height, Width]
    """
    img = None
    # 预定义的均值和标准差 (ImageNet BGR 顺序)
    MEAN_TORCH_BGR = np.array((103.53, 116.28, 123.675), dtype=np.float32)
    STD_TORCH_BGR = np.array((57.375, 57.12, 58.395), dtype=np.float32)

    # 修正后的目标尺寸：宽=180，高=320
    TARGET_W, TARGET_H = 180, 320
    try:
        # 1. 统一解析输入图像为 Numpy 数组 (BGR 顺序)
        if flag is None and isinstance(param, Image.Image):
            # PIL Image -> 缩放 -> RGB Numpy
            im_resized = param.resize((TARGET_W, TARGET_H), Image.BILINEAR)
            img_rgb = np.array(im_resized)
            # 转换为 BGR 以匹配均值计算
            img = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2BGR)

        elif flag == 'img_path' or isinstance(param, str):
            # 路径加载
            screen = cv2.imread(param)
            if screen is not None:
                img = cv2.resize(screen, (TARGET_W, TARGET_H))

        elif flag == 'bytes_io' or isinstance(param, bytes):
            # 字节流加载
            screen = cv2.imdecode(np.frombuffer(param, np.uint8), cv2.IMREAD_COLOR)
            if screen is not None:
                img = cv2.resize(screen, (TARGET_W, TARGET_H))

        else:
            # 如果 param 已经是 numpy 数组 (来自 cv2)
            if isinstance(param, np.ndarray):
                img = cv2.resize(param, (TARGET_W, TARGET_H))
    except Exception as e:
        logger.error(f"❌ 图像预处理异常: {e}")
        img = None
    # 2. 如果处理失败，返回全 0 Tensor 占位
    if img is None:
        logger.warning("⚠️ 无法获取有效图像，返回空 Tensor")
        return torch.zeros(1, 3, TARGET_H, TARGET_W).cuda()
    # 3. 归一化处理
    # 此时 img 是 (320, 180, 3) 的 BGR 数组
    img = img.astype(np.float32)

    # 减均值，除以标准差 (利用广播机制)
    # [320, 180, 3] - [3] -> 每一层 Channel 分别计算
    norm_img = (img - MEAN_TORCH_BGR) / STD_TORCH_BGR

    # 4. 变换维度: [H, W, C] -> [C, H, W]
    # (320, 180, 3) -> (3, 320, 180)
    norm_img = np.transpose(norm_img, (2, 0, 1))

    # 5. 增加 Batch 维度: [3, 320, 180] -> [1, 3, 320, 180]
    norm_img = norm_img[np.newaxis, ...]

    # 6. 转换为 Tensor 并移动到 GPU
    norm_img_tensor = torch.from_numpy(norm_img).cuda()

    return norm_img_tensor

def image_match(bytes_target,bytes_image,value,reverse):
    img_gray = cv2.cvtColor(cv2.imdecode(np.frombuffer(bytes_image, np.uint8), cv2.IMREAD_COLOR), cv2.COLOR_BGR2GRAY)
    template = cv2.cvtColor(cv2.imdecode(np.frombuffer(bytes_target, np.uint8), cv2.IMREAD_COLOR), cv2.COLOR_BGR2GRAY)
    w, h = template.shape[::-1]
    thresholdFlag = True
    if thresholdFlag:
        ret0,img_gray = cv2.threshold(img_gray, 225, 255, cv2.THRESH_BINARY)
        ret1,template = cv2.threshold(template, 225, 255, cv2.THRESH_BINARY)
    if reverse:
        template = 255 - template
    res = cv2.matchTemplate(img_gray,template,cv2.TM_CCOEFF_NORMED)
    threshold = value
    res_max = np.amax(res)
    if res_max>=threshold:
        loc = np.where(res >= res_max)
    else:
        return None
    for pt in zip(*loc[::-1]):
        x = int(pt[0] + w/2)
        y = int(pt[1] + h/2)
        return (x,y)

def get_class_list(xml_a):
    ele_a = ET.fromstring(xml_a)
    elements_a = ele_a.findall('.//*')
    class_list = []
    for item in elements_a:
        class_ = item.attrib['class']
        class_list.append(class_)
    return class_list