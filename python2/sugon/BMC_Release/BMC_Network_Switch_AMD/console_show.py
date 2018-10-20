# -*- coding:utf-8 -*-

TITLE_LENGTH = 64
CONSOLE_INDENT = 0
LINE_SPACING = 1

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
    indent = CONSOLE_INDENT
    line_spacing = LINE_SPACING
    top = "{0}#{1}#".format(" "*indent,"="*(length-2))
    bottom = top
    middle_top = "{0}#{1}#".format(" "*indent," "*(length-2))
    middle_bottom = middle_top
    message = "{0}#{1}#".format(" "*indent,str(message).center((length-2)," "))
    lines = ["\n"*line_spacing,top,middle_top,message,middle_bottom,bottom,"\n"*line_spacing]
    if num:
        lines = map(color_show,lines)
    for line in lines:
        print(line)


if __name__ == '__main__':
    show_title("High Available Stress Test -- IPMIMain process")
    show_title(color="m")