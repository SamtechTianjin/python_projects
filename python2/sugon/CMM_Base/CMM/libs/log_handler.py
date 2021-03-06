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
from conf.common_config import LIB_DIR,MAIN_LOG,PDF_RESULT,IMAGE_DIR


"""
处理logs/main.log的测试结果 >>> 生成PDF测试报告
"""

FAN_LIST = []
PSU_API_DICT = {}
PSU_OEM_DICT = {}
TABLE_NUM = 1
FRU_LIST = []
NETWORK_LIST = {}
NODE_ASSET_DICT = {}
SENSOR_TABLE_LIST = []

"""
获取CMM最新迭代版本CMM_version
"""
def collectCMMVersion():
    vers = 0
    for item in os.listdir(IMAGE_DIR):
        if item.startswith("CMM"):
            m = re.search(r'\d+',item)
            if m:
                try:
                    temp_vers = int(m.group())
                except: pass
                else:
                    if temp_vers >= vers:
                        vers = temp_vers
    return vers



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
    INFO_MAX_LENGTH = 72

    def __init__(self,filename):
        self.can = Canvas(filename=filename)

    def head(self,log_data=None,headtext=None,page=None,page_show=True):
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
            with open(MAIN_LOG,"r") as f:
                line = f.readline().strip()
                while True:
                    if re.search(r'Test start',line):
                        date_info = line.split()[0]
                        break
                    line = f.readline().strip()
            vers = collectCMMVersion()
            version_info = "CMMSprint{0}".format(vers) if vers else "Unknown"
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
            self.can.setFillColor(aColor=colors.red)
            self.can.drawString(x=self.line_start,y=8.7*inch,text="FAIL Cases Information")
            self.can.setFillColor(aColor=colors.black)
            # 设定页码
            self.can.line(x1=self.line_start, y1=self.content_bottom_line, x2=self.line_end,y2=self.content_bottom_line)
            self.can.setFont(psfontname=self.content_font, size=self.page_number_font_size)
            if page_show:
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
            if page_show:
                self.can.drawString(x=self.page_number_x,y=self.page_number_y,text="{0}".format(self.page_number))
                self.page_number += 1

    def parse_log(self):
        global FAN_LIST
        global PSU_API_DICT
        global PSU_OEM_DICT
        global FRU_LIST
        global NETWORK_LIST
        global NODE_ASSET_DICT
        global SENSOR_TABLE_LIST
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
                elif re.search(r'^INFO:',line):
                    is_info = True
                    line = re.search(r'INFO:.*',line).group().split("INFO:")[-1].strip()
                elif re.search(r'FAN\d+_Duty\d+:.*',line):
                    line = re.search(r'FAN.*',line).group().split(":")[-1].strip()
                    FAN_LIST.append(eval(line))
                elif re.search(r'PSU_API_\d+:.*',line):
                    line = re.search(r'PSU.*',line).group().strip()
                    key,value = line.split(":",1)
                    PSU_API_DICT[key] = eval(value)
                elif re.search(r'PSU_OEM_\d+:.*',line):
                    line = re.search(r'PSU.*',line).group().strip()
                    key,value = line.split(":",1)
                    PSU_OEM_DICT[key] = eval(value)
                elif re.search(r'NETWORK_INFO:.*',line):
                    line = re.search(r'NETWORK_INFO:.*',line).group().strip()
                    key,value = line.split(":",1)
                    NETWORK_LIST = eval(value)
                elif re.search(r'FRU_INFO:.*',line):
                    line = re.search(r'FRU_INFO:.*',line).group().strip()
                    key,value = line.split(":",1)
                    FRU_LIST = eval(value)
                elif re.search(r'^Node_Asset_INFO:',line):
                    line = re.search(r'Node_Asset_INFO:.*',line).group().strip()
                    key,value = line.split(":",1)
                    NODE_ASSET_DICT = eval(value)
                elif re.search(r'^OEM_Sensor_Table_INFO:',line):
                    line = re.search(r'^OEM_Sensor_Table_INFO:.*',line).group().strip()
                    key,value = line.split(":",1)
                    SENSOR_TABLE_LIST = eval(value)
                else: pass
                if is_info:
                    value.append(line)
                    is_info = False
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
                    self.can.setFillColor(aColor=colors.darkblue)
                    for info in total_dict[case]:
                        if location <= self.content_end:
                            self.can.showPage()
                            location = self.content_start
                            self.head(page="content")
                        self.can.setFont(psfontname=self.info_font,size=self.content_font_size)
                        if info.startswith("-"):
                            temp_color = colors.darkblue
                            if not info.endswith("-"):
                                info = info.strip(" -")
                        else:
                            temp_color = aColor=colors.red
                        self.can.setFillColor(aColor=temp_color)
                        """ 考虑报告每行的最大长度为 INFO_MAX_LENGTH，自适应换行 """
                        div,mod = divmod(len(info),self.INFO_MAX_LENGTH)
                        temp_value = div if mod == 0 else div+1
                        start,end = 0,self.INFO_MAX_LENGTH
                        for i in range(temp_value):
                            text = info[start:end]
                            start += self.INFO_MAX_LENGTH
                            end += self.INFO_MAX_LENGTH
                            self.can.drawString(x=self.info_start, y=location, text="{0}".format(text))
                            location -= self.content_line_spacing
                            if location <= self.content_end:
                                self.can.showPage()
                                location = self.content_start
                                self.head(page="content")
                                self.can.setFont(psfontname=self.info_font, size=self.content_font_size)
                                self.can.setFillColor(aColor=temp_color)
                index += 1
            self.can.showPage()
        elif page == "FRU":
            if not FRU_LIST:
                return False
            location = self.content_start
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.setFillColor(aColor=colors.darkblue)
            self.can.drawString(x=self.line_start,y=location,text="[CMM FRU Information]")
            table_location = location - 0.5*inch
            column_width_a = 2.5 * inch
            column_width_b = 3.5 * inch
            line_width = column_width_a + column_width_b
            row_height = 0.2 * inch
            column_start = self.line_start + (6.5 * inch - line_width) / 2
            content_a_start = column_start + 0.1 * inch
            content_b_start = column_start + column_width_a + 0.1 * inch
            self.can.setFont(psfontname=self.title_font, size=8)
            for fru_dict in FRU_LIST:
                title_list = fru_dict.keys()
                R_block_start = table_location
                R_start = R_block_start
                for title in title_list:
                    temp_dict = fru_dict.get(title)
                    temp_key_list = temp_dict.keys()
                    global temp_length
                    temp_length = len(temp_dict)
                    for R_index in range(temp_length+1):
                        if R_index == 0:
                            C_start = column_start
                            self.can.setFillColor(aColor=colors.lightgrey)
                            self.can.rect(x=C_start, y=R_start, width=line_width, height=row_height, fill=1)
                            self.can.setFillColor(aColor=colors.black)
                            text_start = content_a_start
                            self.can.drawString(x=text_start, y=R_start + 0.06 * inch,text="{0}".format(title))
                        else:
                            C_start = column_start
                            self.can.rect(x=C_start, y=R_start, width=column_width_a, height=row_height, fill=0)
                            C_start += column_width_a
                            self.can.rect(x=C_start, y=R_start, width=column_width_b, height=row_height, fill=0)
                            self.can.setFillColor(aColor=colors.darkblue)
                            text_start = content_a_start
                            temp_text_1 = temp_key_list[R_index-1]
                            self.can.drawString(x=text_start, y=R_start + 0.06 * inch, text=str(temp_text_1))
                            self.can.setFillColor(aColor=colors.black)
                            text_start = content_b_start
                            temp_text_2 = temp_dict.get(temp_text_1)
                            self.can.drawString(x=text_start, y=R_start + 0.06 * inch, text=str(temp_text_2))
                        R_start -= row_height
                R_block_start -= (temp_length+1)*row_height
                self.can.showPage()
        elif page == "NODE_ASSET":
            if not NODE_ASSET_DICT:
                return False
            """
            # CPU INFO
            {
                "SocketRiserType": "4+4+4+4", 
                "nodeid": 4, 
                "cpuPresent": 1, 
                "UPIWidth": "Q3Q2Q1Q0/Q3Q2Q1Q0/Q3Q2Q1Q0", 
                "BrandName": "Intel(R) Xeon(R) Platinum 8276L CPU @ 2.20GHz", 
                "Location": "CPU0", 
                "cpuid": 1, 
                "Present": "Present", 
                "UPIFreq": "10.4GT/s"
            }
            # PCIE INFO
            {
                "pcieid": 1, 
                "Vendor": "LSI Logic", 
                "pciePresent": 1, 
                "BrandName": "SH08-L3008 8i SAS HBA", 
                "nodeid": 2, 
                "NegoLinkWidth": "x8", 
                "Location": "Riser1_Slot", 
                "CPUNo": "CPU0", 
                "Class": "SAS Card", 
                "Present": "Present", 
                "CurSpeed": "8.0GT/s"
            }
            """
            item_keys = ["CPU","PCIE"]
            cpu_keys = ["cpuid","BrandName","Location","UPIWidth","UPIFreq","SocketRiserType"]
            pcie_keys = ["pcieid","BrandName","Vendor","Class","CPUNo","Location","NegoLinkWidth","CurSpeed"]
            nodeNames = sorted(NODE_ASSET_DICT.keys())
            for nodeName in nodeNames:
                nodeInfo = NODE_ASSET_DICT.get(nodeName)
                if nodeInfo.get("Present") != "Y":
                    continue
                self.head(page="content")
                location = self.content_start
                self.can.setFont(psfontname=self.title_font, size=14)
                self.can.setFillColor(aColor=colors.darkblue)
                self.can.drawString(x=self.line_start, y=location, text="[{0} Asset Information]".format(nodeName))
                table_location = location - 0.5 * inch
                column_width_a = 2 * inch
                column_width_b = 4 * inch
                line_width = column_width_a + column_width_b
                row_height = 0.2 * inch
                column_start = self.line_start + (6.5 * inch - line_width) / 2
                content_a_start = column_start + 0.1 * inch
                content_b_start = column_start + column_width_a + 0.1 * inch
                self.can.setFont(psfontname=self.title_font, size=8)
                temp_keys = []
                R_start = table_location
                for item_key in item_keys:
                    if item_key == "CPU":
                        temp_keys = cpu_keys
                    elif item_key == "PCIE":
                        temp_keys = pcie_keys
                    if temp_keys:
                        temp_length = len(temp_keys)
                        temp_list = nodeInfo.get(item_key)
                        for index,temp_dict in enumerate(temp_list):
                            if index == 0:
                                C_start = column_start
                                self.can.setFillColor(aColor=colors.lightgrey)
                                self.can.rect(x=C_start, y=R_start, width=line_width, height=row_height, fill=1)
                                self.can.setFillColor(aColor=colors.black)
                                text_start = content_a_start
                                self.can.drawString(x=text_start, y=R_start + 0.06 * inch, text="{0} Asset Info".format(item_key))
                                R_start -= row_height
                            for R_index in range(temp_length):
                                k = temp_keys[R_index]
                                v = temp_dict.get(k)
                                C_start = column_start
                                self.can.rect(x=C_start, y=R_start, width=column_width_a, height=row_height, fill=0)
                                C_start += column_width_a
                                self.can.rect(x=C_start, y=R_start, width=column_width_b, height=row_height, fill=0)
                                self.can.setFillColor(aColor=colors.darkblue)
                                text_start = content_a_start
                                self.can.drawString(x=text_start, y=R_start + 0.06 * inch, text=str(k))
                                self.can.setFillColor(aColor=colors.black)
                                text_start = content_b_start
                                self.can.drawString(x=text_start, y=R_start + 0.06 * inch, text=str(v))
                                R_start -= row_height
                                if R_start <= self.content_end:
                                    self.can.showPage()
                                    self.head(page="content")
                                    self.can.setFont(psfontname=self.title_font, size=8)
                                    R_start = table_location
                self.can.showPage()
        elif page == "SENSOR_TABLE":
            if not SENSOR_TABLE_LIST:
                return False
            listLength = len(SENSOR_TABLE_LIST)
            location = self.content_start
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.setFillColor(aColor=colors.darkblue)
            self.can.drawString(x=self.line_start,y=location,text="[CMM Sensor Table Information]")
            table_location = location - 0.5*inch
            row_height = 0.2 * inch
            column_start = self.line_start - 0.5*inch
            R_start = table_location
            for index,tempStr in enumerate(SENSOR_TABLE_LIST):
                self.can.setFont(psfontname=self.title_font,size=7)
                self.can.setFillColor(aColor=colors.black)
                self.can.drawString(x=column_start,y=R_start,text=str(tempStr))
                R_start -= row_height
                if R_start <= self.content_end:
                    # 判断是否还有内容
                    if index == listLength - 1:
                        pass
                    else:
                        self.can.showPage()
                        self.head(page="content")
                        R_start = location
            self.can.showPage()
        elif page == "NETWORK":
            if not NETWORK_LIST:
                return False
            location = self.content_start
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.setFillColor(aColor=colors.darkblue)
            self.can.drawString(x=self.line_start,y=location,text="[CMM Network Information]")
            table_location = location - 0.5*inch
            column_width_a = 2 * inch
            column_width_b = 4 * inch
            line_width = column_width_a + column_width_b
            row_height = 0.3 * inch
            column_start = self.line_start + (6.5 * inch - line_width) / 2
            content_a_start = column_start + 0.1 * inch
            content_b_start = column_start + column_width_a + 0.1 * inch
            self.can.setFont(psfontname=self.title_font, size=8)
            # for network_dict in NETWORK_LIST: # 数据由list变为dict
            key_list, value_list = [], []
            for key, value in NETWORK_LIST.iteritems():
                key_list.append(key)
                value_list.append(value)
            key_num = len(key_list)
            # 绘制表格
            R_start = table_location
            for R_index in range(key_num+1):
                if R_index == 0:
                    C_start = column_start
                    self.can.setFillColor(aColor=colors.lightgrey)
                    self.can.rect(x=C_start, y=R_start, width=line_width, height=row_height, fill=1)
                else:
                    C_start = column_start
                    self.can.rect(x=C_start, y=R_start, width=column_width_a, height=row_height, fill=0)
                    C_start += column_width_a
                    self.can.rect(x=C_start, y=R_start, width=column_width_b, height=row_height, fill=0)
                R_start -= row_height
            # 填入数据
            R_start = table_location
            for R_index in range(key_num+1):
                if R_index == 0:
                    self.can.setFillColor(aColor=colors.black)
                    text_start = content_a_start
                    self.can.drawString(x=text_start, y=R_start + 0.1 * inch, text="Web API: /api/cmminfo/network/")
                else:
                    temp_index = R_index - 1
                    self.can.setFillColor(aColor=colors.darkblue)
                    text_start = content_a_start
                    temp_text = key_list[temp_index]
                    self.can.drawString(x=text_start,y=R_start+0.1*inch,text=str(temp_text))
                    self.can.setFillColor(aColor=colors.black)
                    text_start = content_b_start
                    temp_text = value_list[temp_index]
                    self.can.drawString(x=text_start,y=R_start+0.1*inch,text=str(temp_text))
                R_start -= row_height
            self.can.showPage()
        elif page == "PSU_API" or page == "PSU_OEM":
            if not PSU_API_DICT:
                return False
            if not PSU_OEM_DICT:
                return False
            location = self.content_start
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.setFillColor(aColor=colors.darkblue)
            self.can.drawString(x=self.line_start,y=location,text="[PSU details information]")
            location -= 0.5*inch
            if page == "PSU_API":
                PSU_keys = sorted(PSU_API_DICT.keys())
                KEY_keys = PSU_API_DICT[PSU_keys[0]].keys()
            else:
                PSU_keys = sorted(PSU_OEM_DICT.keys())
                KEY_keys = PSU_OEM_DICT[PSU_keys[0]].keys()
            PSU_num = len(PSU_keys)
            KEY_num = len(KEY_keys)
            if PSU_num == 4:
                column_width = 1.2 * inch
                line_width = (PSU_num+1)*column_width
                row_height = 0.3*inch
                column_start = self.line_start+(6.5*inch-line_width)/2
                content_text_start = column_start+0.1*inch
                self.can.setFont(psfontname=self.title_font,size=8)
                # 绘制表格
                R_start = location
                for R_index in range(KEY_num+1):
                    C_start = column_start
                    if R_index == 0:
                        for C_index in range(PSU_num+1):
                            self.can.setFillColor(aColor=colors.lightgrey)
                            self.can.rect(x=C_start,y=R_start,width=column_width,height=row_height,fill=1)
                            C_start += column_width
                    else:
                        for C_index in range(PSU_num + 1):
                            self.can.rect(x=C_start,y=R_start,width=column_width,height=row_height,fill=0)
                            C_start += column_width
                    R_start -= row_height
                # 填入数据
                psu_index = 1
                text_start = content_text_start
                for C_index in range(PSU_num+1):
                    R_start = location
                    if C_index == 0:
                        index = 0
                        for R_index in range(KEY_num+1):
                            if R_index != 0:
                                self.can.setFillColor(aColor=colors.darkblue)
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text="{0}".format(KEY_keys[index]))
                                index += 1
                            else:
                                if page == "PSU_API":
                                    temp_text = "Web API"
                                elif page == "PSU_OEM":
                                    temp_text = "OEM CMD"
                                else:
                                    temp_text = ""
                                self.can.setFillColor(aColor=colors.darkred)
                                self.can.drawString(x=text_start, y=R_start + 0.1 * inch, text=temp_text)
                            R_start -= row_height
                    else:
                        if page == "PSU_API":
                            PSU_key = "PSU_API_{0}".format(psu_index)
                            PSU_info = PSU_API_DICT[PSU_key]
                        else:
                            PSU_key = "PSU_OEM_{0}".format(psu_index)
                            PSU_info = PSU_OEM_DICT[PSU_key]
                        key_index = 0
                        self.can.setFillColor(aColor=colors.black)
                        for R_index in range(KEY_num+1):
                            if R_index != 0:
                                temp_key = KEY_keys[key_index]
                                temp_text = PSU_info.get(temp_key)
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text=str(temp_text))
                                key_index += 1
                            else:
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text="PSU-{0}".format(psu_index))
                                psu_index += 1
                            R_start -= row_height
                    text_start += column_width
                self.can.showPage()
        elif page == "FAN_API" or page == "FAN_OEM":
            if not FAN_LIST:
                return False
            Duty_list = [item for item in range(30,110,10)]
            location = self.content_start
            self.can.setFont(psfontname=self.title_font,size=14)
            self.can.setFillColor(aColor=colors.darkblue)
            self.can.drawString(x=self.line_start,y=location,text="[Fan Speed from Duty={0} to {1}]".format(Duty_list[0],Duty_list[-1]))
            table_location = location - 0.5*inch
            line_width = 6*inch
            row_height = 0.3*inch
            column_width = line_width/6
            column_start = self.line_start+(6.5*inch-line_width)/2
            content_text_start = column_start+0.1*inch
            FAN_num = len(FAN_LIST)/len(Duty_list)
            TEMP_LIST = []
            for fan_list in FAN_LIST:
                if page == "FAN_API":
                    temp = "{0} {1}".format(fan_list[1],fan_list[3])
                else:
                    temp = "{0} {1}".format(fan_list[0],fan_list[2])
                TEMP_LIST.append(temp)
            if FAN_num <= 5:
                table_num = 1
            elif FAN_num <= 10:
                table_num = 2
            elif FAN_num <=15:
                table_num = 3
            elif FAN_num <= 20:
                table_num = 4
            else:
                table_num = 1
            global TABLE_NUM
            TABLE_NUM = table_num
            if table_num == 1 and page == "FAN_OEM":
                table_location -= (len(Duty_list)+1)*0.3*inch
            fanspeed_index = 0
            fan_index = 1
            for i in range(table_num):
                num = FAN_num - i*5
                num = (5 if num >=5 else num) + 1
                if i >= 3:
                    if i % 3 == 0:
                        self.can.showPage()
                        self.head(log_data, page="content")
                    i = i%3
                location = table_location - i*9*0.3*inch
                R_start = location
                self.can.setFont(psfontname=self.title_font,size=8)
                text_start = content_text_start
                # 绘制表格
                for R_index in range(len(Duty_list)+1):
                    C_start = column_start
                    if R_index == 0:
                        for C_index in range(6):
                            self.can.setFillColor(aColor=colors.lightgrey)
                            self.can.rect(x=C_start,y=R_start,width=column_width,height=row_height,fill=1)
                            C_start += column_width
                    else:
                        for C_index in range(6):
                            self.can.rect(x=C_start,y=R_start,width=column_width,height=row_height,fill=0)
                            C_start += column_width
                    R_start -= row_height
                # 填入数据
                for C_index in range(num):
                    R_start = location
                    if C_index == 0:
                        index = 0
                        for R_index in range(len(Duty_list)+1):
                            if R_index != 0:
                                self.can.setFillColor(aColor=colors.darkblue)
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text="Duty={0}".format(Duty_list[index]))
                                index += 1
                            else:
                                self.can.setFillColor(aColor=colors.darkred)
                                if page == "FAN_API":
                                    temp_text = "Web API"
                                elif page == "FAN_OEM":
                                    temp_text = "OEM CMD"
                                else:
                                    temp_text = ""
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text=temp_text)
                            R_start -= row_height
                    else:
                        self.can.setFillColor(aColor=colors.black)
                        for R_index in range(len(Duty_list)+1):
                            if R_index != 0:
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text=TEMP_LIST[fanspeed_index])
                                fanspeed_index += 1
                            else:
                                self.can.drawString(x=text_start,y=R_start+0.1*inch,text="FAN-{0}".format(fan_index))
                                fan_index += 1
                            R_start -= row_height
                    text_start += column_width
            if table_num == 1 and page == "FAN_API":
                return
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
                self.can.setFillColor(aColor=colors.darkblue)
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
        # 封面页
        pdf.head(headtext="CMM Test Report", page="cover")
        # 结果总结页
        pdf.head(log_data, headtext="Result Summary", page="summary")
        pdf.data(log_data, page="summary")
        # Network 信息
        if NETWORK_LIST:
            pdf.head(page="content")
            pdf.data(log_data, page="NETWORK")
        # FRU 信息
        if FRU_LIST:
            pdf.head(page="content")
            pdf.data(log_data, page="FRU")
        # Sensor Table 信息
        if SENSOR_TABLE_LIST:
            pdf.head(page="content")
            pdf.data(log_data, page="SENSOR_TABLE")
        # Node 资产信息
        if NODE_ASSET_DICT:
            pdf.data(log_data, page="NODE_ASSET")
        # PSU API 信息
        if PSU_API_DICT:
            pdf.head(page="content")
            pdf.data(log_data, page="PSU_API")
        # PSU OEM 信息
        if PSU_OEM_DICT:
            pdf.head(page="content")
            pdf.data(log_data, page="PSU_OEM")
        if FAN_LIST:
            # FAN API 信息
            pdf.head(page="content")
            pdf.data(log_data, page="FAN_API")
            # FAN OEM 信息
            page_show = False if TABLE_NUM == 1 else True
            pdf.head(page="content", page_show=page_show)
            pdf.data(log_data, page="FAN_OEM")
        # 结果详细信息页
        pdf.head(page="content")
        pdf.data(log_data, page="content")
        pdf.save()

if __name__ == '__main__':
    PDFCreator.finish_PDF()