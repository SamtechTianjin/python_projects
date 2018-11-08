# -*- coding:utf-8 -*-

import os,sys
import re
import collections
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib.units import inch
from reportlab.lib import colors
from common import CMM
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LIB_DIR,MAIN_LOG,PDF_RESULT
from conf.config import CMM_version

"""
处理logs/main.log的测试结果，生成PDF测试报告
"""

class PDFCreator(object):

    imgae = os.path.join(LIB_DIR,"sugon.jpg")       # logo图片文件
    title_font = "Courier-Bold"                     # 标题字体，Courier为等宽字体，其他字体：Helvetica等
    content_font = "Courier-Bold"                   # 内容字体
    info_font = "Courier"                           # info字体
    pass_fail_font = "Courier-Bold"                 # PASS/FAIL字体
    content_title_font_size = 12                    # 内容中标题的字体大小
    content_font_size = 10                          # 内容字体大小
    line_start = 1*inch                             # 行x轴开始位置
    line_end = 7.5*inch                             # 行x轴结束位置
    content_line_spacing = 0.25*inch                # 内容行间距
    content_head_line = 10.5*inch                   # 内容页顶部分割线y轴位置
    content_bottom_line = 0.7*inch                  # 内容页底部分割线y轴位置
    content_line_start = line_start+0.2*inch        # 内容行x轴开始位置
    pass_fail_x = line_end-0.8*inch                 # PASS/FAIL x轴位置
    info_start = content_line_start+0.4*inch        # info行x轴开始位置
    content_start = 10.2*inch                       # 内容y轴开始位置
    content_end = 1*inch                            # 内容y轴结束位置
    page_number_x = line_end-0.3*inch               # 页码x轴位置
    page_number_y = 0.4*inch                        # 页码y轴位置
    page_number = 1                                 # 页码开始数
    page_number_font_size = 10                      # 页码字体大小
    head_image_x = line_start                       # 内容页顶部logo x轴位置
    head_image_y = content_head_line+0.01*inch      # 内容页顶部logo y轴位置

    def __init__(self,filename):
        self.can = Canvas(filename=filename)

    def head(self,log_data=None,headtext=None,page=None):
        # PDF封面
        if page == "cover":
            self.can.setFillColor(aColor=colors.black)
            self.can.setFont(psfontname=self.title_font,size=20)
            self.can.drawString(x=self.line_start,y=10.3*inch,text=headtext)
            self.can.rect(x=self.line_start,y=10.1*inch,width=6.5*inch,height=0.1*inch,fill=1)
            self.can.line(x1=self.line_start,y1=10*inch,x2=self.line_end,y2=10*inch)
            self.can.drawImage(image=self.imgae,x=100,y=500,width=400,height=200)
            self.can.setFont(psfontname=self.title_font,size=16)
            length = 8
            date_info,version_info = "",""
            with open(MAIN_LOG,"r") as f:
                line = f.readline().strip()
                while True:
                    if re.search(r'Test start',line):
                        date_info = line.split()[0]
                        break
                    line = f.readline().strip()
            version_info = CMM_version
            date_info = "{0}{1}: {2}".format("Date"," "*(length-len("Date")),date_info)
            version_info = "{0}{1}: {2}".format("Version"," "*(length-len("Version")),version_info)
            self.can.drawString(x=4.5*inch,y=4*inch,text=date_info)
            self.can.drawString(x=4.5*inch,y=3.7*inch,text=version_info)
            self.can.showPage()
        # 测试结果汇总信息
        elif page == "summary":
            total_num,pass_num,fail_num = log_data[0:3]
            # Result Summary
            self.can.setFillColor(aColor=colors.black)
            self.can.setFont(psfontname=self.title_font,size=16)
            self.can.drawString(x=self.line_start,y=10.3*inch,text=headtext)
            self.can.rect(x=self.line_start,y=10.1*inch,width=6.5*inch,height=0.1*inch,fill=1)
            self.can.line(x1=self.line_start,y1=10*inch,x2=self.line_end,y2=10*inch)
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.drawString(x=self.line_start,y=9.7*inch,text="Total case: {0}".format(total_num))
            self.can.setFont(psfontname=self.title_font,size=12)
            self.can.setFillColor(aColor=colors.green)
            self.can.drawString(x=self.content_line_start,y=9.4*inch,text="PASS: {0}".format(pass_num))
            self.can.setFillColor(aColor=colors.red)
            self.can.drawString(x=self.content_line_start,y=9.1*inch,text="FAIL: {0}".format(fail_num))
            self.can.setFillColor(aColor=colors.black)
            self.can.line(x1=self.line_start,y1=9.0*inch,x2=self.line_end,y2=9.0*inch)
            # Error Datails
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.drawString(x=self.line_start,y=8.7*inch,text="FAIL Cases Information")
            # 设定页码
            self.can.line(x1=self.line_start, y1=self.content_bottom_line, x2=self.line_end,y2=self.content_bottom_line)
            self.can.setFont(psfontname=self.content_font, size=self.page_number_font_size)
            self.can.drawString(x=self.page_number_x, y=self.page_number_y, text="{0}".format(self.page_number))
            self.page_number += 1
        # 测试结果详细信息
        else:
            self.can.setFillColor(aColor=colors.black)
            self.can.drawImage(image=self.imgae,x=self.head_image_x,y=self.head_image_y,width=60,height=40)
            self.can.line(x1=self.line_start,y1=self.content_head_line,x2=self.line_end,y2=self.content_head_line)
            # 设定页码
            self.can.line(x1=self.line_start,y1=self.content_bottom_line,x2=self.line_end,y2=self.content_bottom_line)
            self.can.setFont(psfontname=self.content_font,size=self.page_number_font_size)
            self.can.drawString(x=self.page_number_x,y=self.page_number_y,text="{0}".format(self.page_number))
            self.page_number += 1

    def parse_log(self):
        total_dict = collections.OrderedDict()
        pass_dict = collections.OrderedDict()
        fail_dict = collections.OrderedDict()
        is_pass,is_fail,is_info = False,False,False
        key = "default"
        value = []
        total_num,pass_num,fail_num = 0,0,0
        with open(MAIN_LOG, "r") as f:
            line = f.readline().strip()
            while line:
                if line.startswith("#"):
                    line = f.readline().strip()
                    continue
                if re.search(r'Test finish', line): break
                if re.search(r'PASS:',line):
                    is_pass,is_fail,is_info = True,False,False
                    pass_num += 1
                    total_num += 1
                    key = re.search(r'PASS:.*',line).group().split("PASS:")[-1].strip()
                    value = []
                    pass_dict[key] = value
                    total_dict[key] = value
                elif re.search(r'FAIL:',line):
                    is_pass,is_fail,is_info = False,True,False
                    fail_num += 1
                    total_num += 1
                    key = re.search(r'FAIL:.*',line).group().split("FAIL:")[-1].strip()
                    value = []
                    fail_dict[key] = value
                    total_dict[key] = value
                elif re.search(r'INFO:',line):
                    is_info = True
                    line = re.search(r'INFO:.*',line).group().split("INFO:")[-1].strip()
                else: pass
                if is_info: value.append(line)
                line = f.readline().strip()
        CMM.save_data(MAIN_LOG,"total case: {0}".format(total_num))
        CMM.save_data(MAIN_LOG,"pass case: {0}".format(pass_num))
        CMM.save_data(MAIN_LOG,"fail case: {0}".format(fail_num))
        return total_num,pass_num,fail_num,total_dict,pass_dict,fail_dict

    def data(self,log_data,page="content"):
        index,length = 1,3
        if page == "content":
            location = self.content_start
            total_dict,pass_dict,fail_dict = log_data[-3:]
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.setFillColor(aColor=colors.black)
            self.can.drawString(x=self.line_start,y=location,text="Result Details Information")
            location -= 0.4*inch
            for case in total_dict:
                if location <= self.content_end:
                    self.can.showPage()
                    location = self.content_start
                    self.head(page="content")
                self.can.setFont(psfontname=self.title_font,size=self.content_title_font_size)
                self.can.setFillColor(aColor=colors.black)
                self.can.drawString(x=self.content_line_start,y=location,text="{0}.{1}{2}".format(index," "*(length-len(str(index))),case))
                self.can.setFont(psfontname=self.pass_fail_font,size=self.content_title_font_size)
                if case in pass_dict:
                    self.can.setFillColor(aColor=colors.green)
                    self.can.drawString(x=self.pass_fail_x,y=location,text="PASS")
                elif case in fail_dict:
                    self.can.setFillColor(aColor=colors.red)
                    self.can.drawString(x=self.pass_fail_x,y=location,text="FAIL")
                else:
                    pass
                location -= self.content_line_spacing
                if total_dict[case]:
                    self.can.setFont(psfontname=self.info_font, size=self.content_font_size)
                    self.can.setFillColor(aColor=colors.blue)
                    for info in total_dict[case]:
                        if location <= self.content_end:
                            self.can.showPage()
                            location = self.content_start
                            self.head(page="content")
                        self.can.drawString(x=self.info_start,y=location,text="{0}".format(info))
                        location -= self.content_line_spacing
                index += 1
            self.can.showPage()
        else:
            location = 8.3*inch
            fail_dict = log_data[-1]
            for fail_case in fail_dict:
                if location <= self.content_end:
                    self.can.showPage()
                    location = self.content_start
                    self.head(page="content")
                self.can.setFont(psfontname=self.content_font,size=self.content_title_font_size)
                self.can.setFillColor(aColor=colors.blue)
                self.can.drawString(x=self.content_line_start,y=location,text="{0}.{1}{2}".format(index," "*(length-len(str(index))),fail_case))
                location -= self.content_line_spacing
                index += 1
            self.can.showPage()     # 结束Result Summary页进入下一页，注意进入下一页后字体等设定将重置

    def save(self):
        self.can.save()

    @classmethod
    def finish_PDF(cls):
        pdf = cls(filename=PDF_RESULT)
        log_data = pdf.parse_log()
        pdf.head(headtext="CMM Test Report", page="cover")
        pdf.head(log_data, headtext="Result Summary", page="summary")
        pdf.data(log_data, page="summary")
        pdf.head(log_data, page="content")
        pdf.data(log_data, page="content")
        pdf.save()

if __name__ == '__main__':
    PDFCreator.finish_PDF()