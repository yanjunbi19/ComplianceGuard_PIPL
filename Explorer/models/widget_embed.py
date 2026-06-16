import torch
import torch.nn as nn
from sentence_transformers import SentenceTransformer
# Embedder 类的作用是对 widget 的文本、类别和 clickable 属性进行编码。
#
# WidgetEmbed 类的作用是将 Embedder 的输出进一步映射到统一的特征空间。

class Embedder(nn.Module):
    def __init__(self, bert, bert_size=768, num_classes=26, class_emb_size=6):
        super().__init__()
        self.text_embedder = bert
        self.UI_embedder = nn.Embedding(num_classes, class_emb_size).cuda()
        self.bert_size = bert_size
        self.class_size = class_emb_size

    def forward(self, widget_text, widget_class, widget_clickable):
        # 批次大小为 widget_clickable 的长度。
        if len(widget_clickable) == 1:
            n_batch = 1
        else:
            n_batch = len(widget_clickable)
        widget_embedding_list = []

        for batch_i in range(n_batch):
            # 使用 BERT 模型对 widget 的文本信息进行编码
            text_emb = torch.tensor(self.text_embedder.encode(widget_text[batch_i]),device=0)
            # 使用嵌入层对 widget 的类别进行编码
            class_emb = self.UI_embedder(torch.tensor(widget_class[batch_i], device=0))
            x = torch.cat((text_emb,class_emb),-1)
            # 将文本特征和类别特征拼接在一起。
            for index in range(len(widget_text[batch_i])):
                if widget_text[batch_i][index] == '':
                    # 如果 widget 的文本为空，则将其特征向量置为零向量
                    x[index] = torch.zeros(self.bert_size + self.class_size).cuda()
            # 将 widget 的 clickable 属性拼接到特征向量中
            x = torch.cat((x, torch.tensor(widget_clickable[batch_i],device=0).unsqueeze(-1)), -1)
            widget_embedding_list.append(x)
        return widget_embedding_list

class WidgetEmbed(nn.Module):
    def __init__(self, bert, bert_size=768, num_classes=26, class_emb_size=6, clickable_size = 1):
        super().__init__()
        self.embedder = Embedder(bert, bert_size, num_classes).cuda()
        self.lin = nn.Linear(bert_size + class_emb_size+clickable_size, bert_size)
        self.lin.cuda()

    def forward(self, widget_inputs):
        widget_text = widget_inputs[0]
        widget_class = widget_inputs[1]
        widget_clickable = widget_inputs[2]
        # 使用 Embedder 模型对 widget 的文本、类别和 clickable 属性进行编码，得到 widget 的特征表示。
        input_vector = self.embedder(widget_text, widget_class,widget_clickable)
        output_list = []
        for item_widget in input_vector:
            output = self.lin(item_widget)
            output_list.append(output)
        return output_list