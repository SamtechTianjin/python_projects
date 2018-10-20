# -*- coding:utf-8 -*-

import shutil
import re
import importlib
import collections
import unittest
from conf.common_config import *
from libs.config_handler import cases_from_config
from libs.common import CMM
from libs.log_handler import PDFCreator
from libs.email_handler import MailSender

"""
cases目录：测试脚本
conf 目录：配置文件
libs 目录：测试调用模块
logs 目录：所有测试日志
tmp  目录：测试中临时使用的文件
执行 python Main.py
"""

TMP_DICT = dict()
CLASSES = collections.OrderedDict()

def collect_case():
    return cases_from_config(CASE_CONFIG)

def find_all_case_class(case_dir):
    if len(os.listdir(case_dir)) == 0:
        return
    global TMP_DICT
    for name in os.listdir(case_dir):
        name = os.path.join(case_dir, name)
        if os.path.isfile(name):
            filename = os.path.split(name)[-1]
            basename,extname = os.path.splitext(filename)
            if extname == ".py" and basename != "__init__":
                f = open(name, "r")
                data = f.readlines()
                f.close()
                find_class = False
                class_name,module_name,function_list = None,None,list()
                for line in data:
                    match_class = re.search(r'class \w+\(unittest.TestCase.*\)', line)    # 匹配类名
                    if match_class:
                        find_class = True
                        class_name = match_class.group().split()[-1].split("(")[0]
                        module_name = name.replace(os.sep, ".").strip(".py")
                        break
                if find_class:
                    TMP_DICT[basename] = {
                        "module": module_name,
                        "class": class_name,
                    }
        elif os.path.isdir(name):
                find_all_case_class(name)

def import_module(class_name, module_name):
    func_list = list()
    case_module = importlib.import_module(module_name)
    case_class = getattr(case_module, class_name)
    for func in dir(case_class):
        if re.match(r'[a-z]{1}_\w+$', func):
            func_list.append(func)
    return case_class,func_list

def parse_case():
    global CLASSES
    global TMP_DICT
    os.chdir(MAIN_DIR)
    case_dict = collect_case()
    cases = case_dict.keys()
    case_dirs = list(set(case_dict.values()))   # case脚本目录去重
    for case_dir in case_dirs:
        case_dir = os.path.join("cases", case_dir)
        if not os.path.exists(case_dir):
            continue
        find_all_case_class(case_dir)
    # 按照case.txt的顺序生成CLASSES
    for case in cases:
        if TMP_DICT.has_key(case):
            CLASSES[case] = TMP_DICT[case]

def init():
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)
    os.makedirs(LOG_DIR)
    cmm = CMM()
    cmm.save_data(MAIN_LOG,cmm.banner("Main log"),flag="w",timestamp=False)
    cmm.save_data(MAIN_LOG,"Test start...")


if __name__ == '__main__':
    if RUN:
        parse_case()
        case_number = len(CLASSES.keys())
        CMM.show_message("Total case: {0}".format(case_number),timestamp=False,color="blue",indent=CONSOLE_INDENT)
        init()
        suite = unittest.TestSuite()
        for value in CLASSES.itervalues():
            case_class,func_list = import_module(value["class"], value["module"])
            suite.addTests(map(case_class, func_list))
        runner = unittest.TextTestRunner(verbosity=0)
        runner.run(suite)
        CMM.save_data(MAIN_LOG,"Test finish.")
        PDFCreator.finish_PDF()
        if SEND_MAIL:
            MailSender.finish_email()
    else:
        CMM.show_message("No run case...",timestamp=False,color="red")