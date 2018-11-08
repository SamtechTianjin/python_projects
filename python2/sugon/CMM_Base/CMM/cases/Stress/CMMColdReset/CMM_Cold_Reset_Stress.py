# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time,datetime
import json
import re
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LOG_DIR,MAIN_LOG,IMAGE_DIR
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
STRESS_TIME = config.COLD_RESET_TIME
POWER_NUM = config.POWER_NUM
SWITCH_NUM = config.SWITCH_NUM
FAN_NUM = config.FAN_NUM

# Global variable
CSRFToken = ""
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)
RESET_OK = True
RESET_TIME = []
OEM_BASELINE = {}
API_BASELINE = {}
OEM_TEMP = {}
API_TEMP = {}
GET_POWER_OEM = "raw 0x3a 0x51"
GET_FAN_OEM = "raw 0x3a 0x53"
GET_SWITCH_OEM = "raw 0x3a 0x5f"
RESET_OEM = "raw 0x06 0x02"
GET_POWER_API = "/api/cmminfo/psus/"
GET_FAN_API = "/api/cmminfo/fans/"
GET_SWITCH_API = "/api/cmminfo/switches/"



@CMM.calc_runtime
def CMMColdReset(max_time=300):
    global RESET_OK
    cmd = "{0} {1}".format(IPMITOOL,RESET_OEM)
    status,output = CMM.retry_run_cmd(cmd)
    if status == 0:
        message = "CMM Cold Reset Command OK."
        show_step_result("CMM Cold Reset Command",flag="PASS")
        CMM.save_data(main_log,message)
    else:
        message = "CMM Cold Reset Command FAIL !\n{0}".format(output)
        show_step_result("CMM Cold Reset Command", flag="FAIL")
        CMM.save_data(main_log,message)
        RESET_OK = False
        return False
    time.sleep(10)
    start_time = datetime.datetime.now()
    while CMM.calc_time_interval(start_time, datetime.datetime.now()) < max_time:
        cmd = "{0} raw 0x06 0x01".format(IPMITOOL)
        status,output = CMM.retry_run_cmd(cmd)
        if status == 0:
            break
        time.sleep(1)
    else:
        if not Remote.ping_test(IP):
            temp_text = "Connected {0} FAIL !".format(IP)
        else:
            temp_text = "Connected {0} OK.".format(IP)
        message = "CMM status is still FAIL after {0} seconds, {1}".format(max_time,temp_text)
        CMM.show_message(message,timestamp=False,color="red")
        MAIN_LOG_list.append(message)
        CMM.save_data(main_log,message,timestamp=False)
        RESET_OK = False

def CollectBaseline(cmd,retry_count=3):
    status = 1
    output = "Collect baseline FAIL !"
    while retry_count > 0:
        status,output = CMM.run_cmd(cmd)
        if status == 0:
            break
        time.sleep(3)
        retry_count -= 1
    return status,output

def CollectOEMInfo(baseline=False):
    collect_baseline = True
    global OEM_TEMP
    OEM_TEMP = {}
    for power_id in range(POWER_NUM):
        cmd = "{0} {1} 0x0{2}".format(IPMITOOL, GET_POWER_OEM, power_id)
        if baseline:
            status,output = CollectBaseline(cmd)
            if status == 0:
                OEM_BASELINE["power_{0}".format(power_id)] = output
            else:
                collect_baseline = False
        else:
            status,output = CMM.retry_run_cmd(cmd)
            OEM_TEMP["power_{0}".format(power_id)] = output
        time.sleep(1)
    for fan_id in range(FAN_NUM):
        cmd = "{0} {1} 0x0{2}".format(IPMITOOL, GET_FAN_OEM, fan_id)
        if baseline:
            status,output = CollectBaseline(cmd)
            if status == 0:
                OEM_BASELINE["fan_{0}".format(fan_id)] = output
            else:
                collect_baseline = False
        else:
            status,output = CMM.retry_run_cmd(cmd)
            OEM_TEMP["fan_{0}".format(fan_id)] = output
        time.sleep(1)
    for switch_id in range(SWITCH_NUM):
        cmd = "{0} {1} 0x0{2}".format(IPMITOOL, GET_SWITCH_OEM, switch_id)
        if baseline:
            status,output = CollectBaseline(cmd)
            if status == 0:
                OEM_BASELINE["switch_{0}".format(switch_id)] = output
            else:
                collect_baseline = False
        else:
            status,output = CMM.retry_run_cmd(cmd)
            OEM_TEMP["switch_{0}".format(switch_id)] = output
        time.sleep(1)
    if baseline:
        return collect_baseline

def CollectAPIInfo(baseline=False,login_time=300):
    global CSRFToken
    global API_TEMP
    API_TEMP = {}
    collect_baseline = True
    LOG_FAIL = False
    start_time = datetime.datetime.now()
    while CMM.calc_time_interval(start_time, datetime.datetime.now()) < login_time:
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            message = "[curl] Login Web successfully."
            CMM.save_data(main_log, message)
            show_step_result("Login Web",flag="PASS")
            CSRFToken = output.strip()
            break
        time.sleep(10)
    else:
        message = "[curl] Login Web FAIL after {0} seconds !".format(login_time)
        CMM.save_data(main_log, message)
        CMM.show_message(message,timestamp=False,color="red")
        MAIN_LOG_list.append(message)
        LOG_FAIL = True
    if not LOG_FAIL:
        for psu_id in range(1,POWER_NUM+1):
            temp_dict = {}
            check_list = ["Vendor","isPSUOn","SN","psuPresent","Model","FanDuty","id","Present"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, psu_id, IP, GET_POWER_API)
            if baseline:
                status, output = CollectBaseline(cmd)
                if status == 0:
                    try:
                        temp = json.loads(output)
                    except Exception as e:
                        message = "[PSU{0}] {1}".format(psu_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(main_log,message,timestamp=False)
                        collect_baseline = False
                    else:
                        if temp.get("error"):
                            collect_baseline = False
                        else:
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                else:
                    collect_baseline = False
                API_BASELINE["psu_{0}".format(psu_id)] = temp_dict
            else:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = json.loads(output)
                    except Exception as e:
                        message = "[PSU{0}] {1}".format(psu_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(main_log, message, timestamp=False)
                    else:
                        if not temp.get("error"):
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                API_TEMP["psu_{0}".format(psu_id)] = temp_dict
            time.sleep(1)
        for fan_id in range(1,FAN_NUM+1):
            temp_dict = {}
            check_list = ["id","FanPresent","Present","FanStatus","Duty"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,fan_id,IP,GET_FAN_API)
            if baseline:
                status, output = CollectBaseline(cmd)
                if status == 0:
                    try:
                        temp = json.loads(output)
                    except Exception as e:
                        message = "[FAN{0}] {1}".format(fan_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(main_log, message, timestamp=False)
                        collect_baseline = False
                    else:
                        if isinstance(temp,list):
                            temp = temp[0]
                        if temp.get("error"):
                            collect_baseline = False
                        else:
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                else:
                    collect_baseline = False
                API_BASELINE["fan_{0}".format(fan_id)] = temp_dict
            else:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = json.loads(output)
                    except Exception as e:
                        message = "[FAN{0}] {1}".format(fan_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(main_log, message, timestamp=False)
                    else:
                        if isinstance(temp, list):
                            temp = temp[0]
                        if not temp.get("error"):
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                API_TEMP["fan_{0}".format(fan_id)] = temp_dict
            time.sleep(1)
        for switch_id in range(1,SWITCH_NUM+1):
            temp_dict = {}
            check_list = ["id","swPresent","Present","Status","Vendor","SwitchType","IP","Netmask","Gateway"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,switch_id,IP,GET_SWITCH_API)
            if baseline:
                status, output = CollectBaseline(cmd)
                if status == 0:
                    try:
                        temp = json.loads(output)
                    except Exception as e:
                        message = "[Switch{0}] {1}".format(switch_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(main_log, message, timestamp=False)
                        collect_baseline = False
                    else:
                        if temp.get("error"):
                            collect_baseline = False
                        else:
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                else:
                    collect_baseline = False
                API_BASELINE["switch_{0}".format(switch_id)] = temp_dict
            else:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = json.loads(output)
                    except Exception as e:
                        message = "[Switch{0}] {1}".format(switch_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(main_log, message, timestamp=False)
                    else:
                        if not temp.get("error"):
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                API_TEMP["switch_{0}".format(switch_id)] = temp_dict
            time.sleep(1)
    else:
        return False
    status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
    if status == 0:
        message = "[curl] Logout Web successfully."
        CMM.save_data(main_log, message)
        show_step_result("Logout Web",flag="PASS")
    else:
        message = "[curl] Logout Web FAIL !\n{0}".format(output)
        CMM.save_data(main_log, message)
        show_step_result("Logout Web",flag="FAIL")
    if baseline:
        return collect_baseline
    return True



class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log,self.banner(case_name),timestamp=False)

    def c_cold_reset(self):
        global CASE_PASS
        temp_text = "CMM Cold Reset"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        status = CollectAPIInfo(baseline=True)
        CMM.save_data(main_log,str(API_BASELINE),timestamp=False)
        if not status:
            CASE_PASS = False
            message = "Collect baseline FAIL !"
            CMM.save_data(main_log, message)
            MAIN_LOG_list.append(message)
            show_step_result("Collect baseline",flag="FAIL")
            return False
        else:
            show_step_result("Collect baseline",flag="PASS")
        start_time = datetime.datetime.now()
        while CMM.calc_time_interval(start_time, datetime.datetime.now()) < STRESS_TIME:
            cold_reset_time = CMMColdReset()
            if not RESET_OK:
                CASE_PASS = False
                break
            else:
                message = "Cold Reset Time: {0}s".format(cold_reset_time)
                RESET_TIME.append(int(cold_reset_time))
                CMM.show_message(message,timestamp=False,color="blue")
                CMM.save_data(main_log,message,timestamp=False)
            CollectAPIInfo()
            CMM.save_data(main_log,str(API_TEMP),timestamp=False)
            if API_BASELINE != API_TEMP:
                CASE_PASS = False
                message = "[API] The CMM info is changed !"
                CMM.show_message(message,timestamp=False,color="red")
                MAIN_LOG_list.append(message)
                CMM.save_data(main_log,message,timestamp=False)
                break
            else:
                message = "[API] Check CMM info OK."
                show_step_result("[API] Check CMM info",flag="PASS")
                CMM.save_data(main_log,message,timestamp=False)
        else:
            average_time = sum(RESET_TIME)/len(RESET_TIME)
            message = "Stress Time: {0}s, CMM Cold Reset PASS.".format(STRESS_TIME)
            show_step_result("CMM Cold Reset",flag="PASS")
            CMM.show_message("Stress Time: {0}s".format(STRESS_TIME),timestamp=False,color="blue")
            CMM.show_message("Average Reset Time: {0}s".format(average_time),timestamp=False,color="blue")
            CMM.save_data(main_log,message,timestamp=False)
            CMM.save_data(main_log,"{0}".format(RESET_TIME),timestamp=False)
            MAIN_LOG_list.append("Stress Time: {0}s".format(STRESS_TIME))
            MAIN_LOG_list.append("Average Reset Time: {0}s".format(average_time))


    def z_finish(self):
        CMM.save_data(MAIN_LOG,"{0} {1}".format("PASS:" if CASE_PASS else "FAIL:",module_name.replace("_"," ")))
        infos = map(lambda x: "INFO: {0}".format(x),MAIN_LOG_list)
        for info in infos:
            CMM.save_data(MAIN_LOG, info, timestamp=False)
        time.sleep(5)


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