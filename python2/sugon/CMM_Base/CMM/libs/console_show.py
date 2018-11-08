# -*- coding:utf-8 -*-

import os,sys
import re

lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import TITLE_LENGTH,LINE_SPACING


def show_title(message="Test",color="green"):
    # red|green|yellow|blue
    if color.lower() == "red" or color.lower() == "r":
        num = 31
    elif color.lower() == "green" or color.lower() == "g":
        num = 32
    elif color.lower() == "yellow" or color.lower() == "y":
        num = 33
    elif color.lower() == "blue" or color.lower() == "b":
        num = 34
    elif color.lower() == "magenta" or color.lower() == "m":
        num = 35
    elif color.lower() == "cyan" or color.lower() == "c":
        num = 36
    else:
        num = ""
    def color_show(data,num=num):
        return "\033[1;{0}m{1}\033[0m".format(num,data)
    length = TITLE_LENGTH
    line_spacing = LINE_SPACING
    top = "#{0}#".format("="*(length-2))
    bottom = top
    middle_top = "#{0}#".format(" "*(length-2))
    middle_bottom = middle_top
    message = "#{0}#".format(str(message).center((length-2)," "))
    lines = ["\n"*line_spacing,top,middle_top,message,middle_bottom,bottom,"\n"*line_spacing]
    if num:
        lines = map(color_show,lines)
    for line in lines:
        print(line)

def format_item(item):
    item = " {0} ".format(item)
    return item.center(TITLE_LENGTH,"=")

def show_step_result(text,flag):
    item1 = "{0} {1} ".format(text, "-" * (TITLE_LENGTH - len(text) - 8))
    sys.stdout.write(item1)
    if flag.upper() == "PASS":
        print("\033[1;32m[PASS]\033[0m\n")
    elif flag.upper() == "FAIL":
        print("\033[1;31m[FAIL]\033[0m\n")
    elif flag.upper() == "WARN":
        print("\033[1;33m[WARN]\033[0m\n")
    else:
        pass

if __name__ == '__main__':
    show_title("High Available Stress Test -- IPMIMain process")
    show_title(color="m")
    print(format_item("Login Web"))
    show_step_result("Login web",flag="PASS")
    show_step_result("BMC cold reset status",flag="FAIL")
    show_step_result("Logout web",flag="WARN")