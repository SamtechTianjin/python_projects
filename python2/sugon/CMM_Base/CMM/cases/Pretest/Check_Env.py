# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import re
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LOG_DIR,MAIN_LOG
from libs.common import CMM,unicode_convert,Remote
from libs.console_show import format_item,show_step_result
import conf.config as config

module_name = os.path.splitext(os.path.basename(__file__))[0]
log_dir = os.path.join(LOG_DIR,module_name)
main_log = os.path.join(log_dir,"{0}.log".format(module_name))
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD

# Global variable
PING_FAIL = False
IPMI_FAIL = False
LOGIN_FAIL = False
CSRFToken = ""
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)


"""
1. ping CMM IP
2. try IPMI command
3. curl login|logout web
...
"""


class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log,self.banner(case_name),timestamp=False)

    def b_ping_test(self):
        global CASE_PASS
        global PING_FAIL
        message = "- Ping CMM IP -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")
        status = Remote.ping_test(IP)
        if not status:
            CASE_PASS = False
            PING_FAIL = True
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")

    def c_ipmi_test(self):
        global CASE_PASS
        global IPMI_FAIL
        message = "- Check IPMI command -"
        CMM.show_message(format_item(message),timestamp=False,color="green")
        if PING_FAIL:
            return False
        cmd = "{0} raw 0x06 0x01".format(IPMITOOL)
        temp_text = message.strip(" -")
        status,output = CMM.retry_run_cmd(cmd)
        info = "IPMI command\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
        CMM.save_data(main_log,info,timestamp=False)
        if status == 0:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            IPMI_FAIL = True
            CASE_PASS = False
            CMM.show_message(output,timestamp=False)
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")

    def f_curl_login(self):
        global CASE_PASS
        global LOGIN_FAIL
        global CSRFToken
        if PING_FAIL:
            LOGIN_FAIL = True
            return False
        message = "- Login Web -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD, retry_count=3)
        if status == 0:
            CSRFToken = output.strip()
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            LOGIN_FAIL = True
            CASE_PASS = False
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")

    def y_curl_logout(self):
        global CASE_PASS
        if LOGIN_FAIL:
            return False
        message = "- Logout Web -"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        temp_text = message.strip(" -")
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
        if status == 0:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")
        else:
            CASE_PASS = False
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")

    def z_finish(self):
        if not CASE_PASS:
            temp_text = "Check env FAIL, exit..."
            CMM.save_data(MAIN_LOG,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="red")
            os._exit(1)



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