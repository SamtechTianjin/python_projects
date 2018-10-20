# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import re
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LOG_DIR,MAIN_LOG,CONSOLE_INDENT
from libs.common import CMM

module_name = os.path.splitext(os.path.basename(__file__))[0]
log_dir = os.path.join(LOG_DIR,module_name)
main_log = os.path.join(log_dir,"{0}.log".format(module_name))
MAIN_LOG_list = list()
CASE_PASS = True


def step_a():
    time.sleep(0.111)
    MAIN_LOG_list.append("A B C D E F G")
def step_b():
    time.sleep(0.111)
    MAIN_LOG_list.append("Memory Frequence: 2133Mhz")
def step_c():
    time.sleep(0.111)
    MAIN_LOG_list.append("CPU frequence: 3.10GHz")

@CMM.calc_runtime
def run_caseA(name):
    global CASE_PASS
    CMM.show_message(name,timestamp=False,indent=CONSOLE_INDENT)
    step_a()
    step_b()
    step_c()
    # CASE_PASS = False

@CMM.calc_runtime
def run_caseB(name):
    global CASE_PASS
    CMM.show_message(name,timestamp=False,indent=CONSOLE_INDENT)
    time.sleep(0.22)
    MAIN_LOG_list.append("SAM TEST ...")
    # CASE_PASS = False



class CMMTest(unittest.TestCase,CMM):
    def a_init(self):
        self.case_init(module_name, log_dir)
        CMM.save_data(main_log,self.banner(module_name),timestamp=False)
    def b_StepA(self):
        name = "Step A"
        CMM.save_data(main_log,name)
        returnValue = run_caseA(name)
        message = "RunTime: {0}s".format(returnValue)
        CMM.show_message(message,timestamp=False,indent=CONSOLE_INDENT)
        CMM.save_data(main_log,message)
    def c_StepB(self):
        name = "Step B"
        CMM.save_data(main_log,name)
        returnValue = run_caseB(name)
        message = "RunTime: {0}s".format(returnValue)
        CMM.show_message(message,timestamp=False,indent=CONSOLE_INDENT)
        CMM.save_data(main_log,message)
    def z_finish(self):
        CMM.save_data(MAIN_LOG,"{0} {1}".format("PASS:" if CASE_PASS else "FAIL:",module_name))
        infos = map(lambda x: "INFO: {0}".format(x),MAIN_LOG_list)
        for info in infos:
            CMM.save_data(MAIN_LOG, info, timestamp=False)



if __name__ == '__main__':
    func_list = list()
    funcs = dir(CMMTest)
    for func in funcs:
        if re.match(r'[a-z]{1}_\w+$', func):
            func_list.append(func)
    suite = unittest.TestSuite()
    suite.addTests(map(CMMTest, func_list))
    runner = unittest.TextTestRunner(verbosity=0)
    runner.run(suite)