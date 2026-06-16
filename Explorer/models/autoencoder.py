# autoencoder.py
from xml.etree import ElementTree as ET
import numpy as np
from PIL import Image
import torch
import torch.nn as nn
import torch.nn.functional as F
import re  # parseBounds 需要 re 模块

# --- 直接在这里定义设备分辨率 ---
# 请确保这些值与您收集XML数据时的设备屏幕分辨率一致
DEVICE_RESOLUTION_X = 1080  # 宽度
DEVICE_RESOLUTION_Y = 1920  # 高度


# ----------------------------------

# 为了让 autoencoder.py 独立运行，我们在此处提供一个简化的 parseBounds 函数
def parseBounds(boundStr):
    # 示例: "[0,0][1080,1920]" -> (0,0,1080,1920)
    parts = re.findall(r'\d+', boundStr)
    if len(parts) == 4:
        return int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
    raise ValueError(f"Invalid bounds string: {boundStr}")


class ScreenLayout():

    def __init__(self, xmlStr):
        self.pixels = np.full((100, 56, 2), 0, dtype=float)
        # 直接使用文件内定义的设备分辨率
        self.vert_scale = 100 / DEVICE_RESOLUTION_Y
        self.horiz_scale = 56 / DEVICE_RESOLUTION_X
        self.load_screen(xmlStr)

    def load_screen(self, xmlStr):
        xmlRoot = ET.fromstring(xmlStr)
        try:
            self.render_contents_u2(xmlRoot)
        except Exception as e:
            pass

    def render_contents_u2(self, node):
        if len(list(node)) != 0:
            for child_node in node:
                self.render_contents_u2(child_node)
        else:
            try:
                if 'visible-to-user' in node.attrib and node.attrib['visible-to-user'] == 'true':
                    if 'bounds' in node.attrib:
                        boundStr = node.attrib['bounds']
                        if len(boundStr) >= 10:
                            left, top, right, bottom = parseBounds(boundStr)

                            x1 = max(0, int(left * self.horiz_scale))
                            y1 = max(0, int(top * self.vert_scale))
                            x2 = min(56, int(right * self.horiz_scale))
                            y2 = min(100, int(bottom * self.vert_scale))

                            if x1 < x2 and y1 < y2:
                                if 'text' in node.attrib and node.attrib['text'] and node.attrib['text'].strip():
                                    self.pixels[y1:y2, x1:x2, 0] = 1
                                else:
                                    self.pixels[y1:y2, x1:x2, 1] = 1
            except Exception as e:
                pass

    def render_contents(self, node):  # 备用方法，当前代码未使用
        if len(list(node)) != 0:
            for child_node in node:
                self.render_contents(child_node)
        else:
            try:
                if ('displayed' in node.attrib and node.attrib['displayed'] == 'true'):
                    if 'bounds' in node.attrib:
                        if len(node.attrib['bounds']) >= 10:
                            boundStr = node.attrib['bounds']
                            left, top, right, bottom = parseBounds(boundStr)
                            x1 = max(0, int(left * self.horiz_scale))
                            y1 = max(0, int(top * self.vert_scale))
                            x2 = min(56, int(right * self.horiz_scale))
                            y2 = min(100, int(bottom * self.vert_scale))
                            if x1 < x2 and y1 < y2:
                                if 'text' in node.attrib and node.attrib['text'] and node.attrib['text'].strip():
                                    self.pixels[y1:y2, x1:x2, 0] = 1
                                else:
                                    self.pixels[y1:y2, x1:x2, 1] = 1
            except Exception as e:
                pass

    def convert_to_image(self):
        p = np.full((100, 56, 3), 255, dtype=np.uint)
        for y in range(len(self.pixels)):
            for x in range(len(self.pixels[0])):
                if (self.pixels[y][x][0] == 1 and self.pixels[y][x][1] == 0):
                    p[y][x] = [0, 0, 255]
                elif (self.pixels[y][x][0] == 0 and self.pixels[y][x][1] == 1):
                    p[y][x] = [255, 0, 0]
                elif (self.pixels[y][x][0] == 1 and self.pixels[y][x][1] == 1):
                    p[y][x] = [255, 0, 255]
        im = Image.fromarray(p.astype(np.uint8))
        return im


class LayoutEncoder(nn.Module):

    def __init__(self):
        super(LayoutEncoder, self).__init__()

        self.e1 = nn.Linear(11200, 2048)
        self.e2 = nn.Linear(2048, 256)
        self.e3 = nn.Linear(256, 64)

    def forward(self, input):
        encoded = F.relu(self.e3(F.relu(self.e2(F.relu(self.e1(input))))))
        return encoded


class LayoutDecoder(nn.Module):

    def __init__(self):
        super(LayoutDecoder, self).__init__()

        self.d1 = nn.Linear(64, 256)
        self.d2 = nn.Linear(256, 2048)
        self.d3 = nn.Linear(2048, 11200)

    def forward(self, input):
        decoded = F.relu(self.d3(F.relu(self.d2(F.relu(self.d1(input))))))
        return decoded


class LayoutAutoEncoder(nn.Module):

    def __init__(self):
        super(LayoutAutoEncoder, self).__init__()

        self.enc = LayoutEncoder()
        self.dec = LayoutDecoder()

    def forward(self, input):
        return F.relu(self.dec(self.enc(input)))

