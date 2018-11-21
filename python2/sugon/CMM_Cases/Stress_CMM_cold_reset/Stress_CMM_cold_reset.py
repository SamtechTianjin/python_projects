# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import unittest
import time,datetime
import re
import config
from common_libs import CMM,Remote,show_step_result,format_item

"""
第一次的信息作为baseline 
每个循环收集以下信息:
通过API得到信息: FAN, PSU, Switch
通过OEM得到信息: FW, sdr, sel
每一圈Cold Reset后对上述信息进行对比 如果出现不一致则退出压力测试
测试参数更改config.py文件
"""

# Collect arguments
CMM_IP = config.CMM_IP
CMM_username = config.CMM_username
CMM_password = config.CMM_password
Stress_time = config.Stress_time
Power_num = config.Power_num
Switch_num = config.Switch_num
Fan_num = config.Fan_num

# Global variable
Current_path = os.path.abspath(os.path.dirname(__file__))
Module_name = os.path.splitext(os.path.basename(__file__))[0]
Log_dir = os.path.join(Current_path,"LOG_{0}".format(Module_name))
Main_log = os.path.join(Log_dir,"{0}.log".format(Module_name))
SEL_log = os.path.join(Log_dir,"SEL.log")
Error_log = os.path.join(Log_dir,"Error.log")
CASE_PASS = True
CSRFToken = ""
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(CMM_IP,CMM_username,CMM_password)
RESET_OK = True
RESET_TIME = []
OEM_BASELINE = {}
API_BASELINE = {}
OEM_TEMP = {}
API_TEMP = {}
RESET_OEM = "raw 0x06 0x02"
GET_POWER_OEM = "raw 0x3a 0x51"
GET_FAN_OEM = "raw 0x3a 0x53"
GET_SWITCH_OEM = "raw 0x3a 0x5f"
GET_POWER_API = "/api/cmminfo/psus/"
GET_FAN_API = "/api/cmminfo/fans/"
GET_SWITCH_API = "/api/cmminfo/switches/"


@CMM.calc_runtime
def CMMColdReset(max_time=300):
    global RESET_OK
    message = "Cold Reset Command"
    cmd = "{0} {1}".format(IPMITOOL,RESET_OEM)
    status,output = CMM.retry_run_cmd(cmd)
    CMM.save_data(Main_log,"{0}\nreturncode: {1}\n{2}".format(cmd,status,output))
    if status == 0:
        show_step_result(message,flag="PASS")
        CMM.save_step_result(Main_log,message,flag="PASS")
    else:
        show_step_result(message, flag="FAIL")
        CMM.show_message("{0}".format(output),timestamp=False,color="red")
        CMM.save_step_result(Main_log,message,flag="FAIL")
        CMM.save_step_result(Error_log,message,flag="FAIL")
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
        if not Remote.ping_test(CMM_IP):
            temp_text = "Connected {0} FAIL !".format(CMM_IP)
        else:
            temp_text = "Connected {0} OK.".format(CMM_IP)
        message = "CMM status is still FAIL after {0} seconds, {1}".format(max_time,temp_text)
        CMM.show_message(message,timestamp=False,color="red")
        CMM.save_data(Main_log,message,timestamp=False)
        CMM.save_data(Error_log,message,timestamp=False)
        RESET_OK = False

def CollectFWInfo(baseline=False):
    global OEM_BASELINE
    global OEM_TEMP
    is_fail = False
    message = "Collect FW info"
    cmd = "{0} raw 0x06 0x01 2>/dev/null".format(IPMITOOL)
    status, output = CMM.retry_run_cmd(cmd)
    if status == 0:
        show_step_result(message,flag="PASS")
        CMM.save_step_result(Main_log,message,flag="PASS")
    else:
        show_step_result(message,flag="FAIL")
        CMM.save_step_result(Main_log,message,flag="FAIL")
        CMM.save_step_result(Error_log,message,flag="FAIL")
        is_fail = True
    if baseline:
        OEM_BASELINE["FW"] = output.strip()
    else:
        OEM_TEMP["FW"] = output.strip()
    if is_fail:
        return False
    return True

def CollectSDRInfo(baseline=False):
    global OEM_BASELINE
    global OEM_TEMP
    is_fail = False
    message = "Collect sdr info"
    sdr_infos = []
    cmd = "{0} sdr elist 2>/dev/null".format(IPMITOOL)
    status,output = CMM.retry_run_cmd(cmd)
    if status == 0:
        show_step_result(message,flag="PASS")
        CMM.save_step_result(Main_log,message,flag="PASS")
    else:
        show_step_result(message,flag="FAIL")
        CMM.save_step_result(Main_log,message,flag="FAIL")
        CMM.save_step_result(Error_log,message,flag="FAIL")
        is_fail = True
    for line in output.splitlines():
        sdr_info = line.strip().split()[0].strip()
        sdr_infos.append(sdr_info)
    sorted(sdr_infos)
    if baseline:
        OEM_BASELINE["sdr"] = sdr_infos
    else:
        OEM_TEMP["sdr"] = sdr_infos
    if is_fail:
        return False
    return True

def CollectAPIInfo(baseline=False,login_time=300):
    global CSRFToken
    global API_TEMP
    global API_BASELINE
    API_TEMP = {}
    collect_baseline = True
    LOG_FAIL = False
    start_time = datetime.datetime.now()
    output = ""
    while CMM.calc_time_interval(start_time, datetime.datetime.now()) < login_time:
        status, output = CMM.curl_login_logout(CMM_IP, flag="login", username=CMM_username, password=CMM_password)
        if status == 0:
            message = "Login Web"
            CMM.save_step_result(Main_log,message,flag="PASS")
            show_step_result(message,flag="PASS")
            CSRFToken = output.strip()
            break
        time.sleep(10)
    else:
        message = "[curl] Login Web FAIL after {0} seconds !\n{1}".format(login_time,output)
        CMM.save_data(Main_log, message,timestamp=False)
        CMM.save_data(Error_log,message,timestamp=False)
        CMM.show_message(message,timestamp=False,color="red")
        LOG_FAIL = True
    if not LOG_FAIL:
        for psu_id in range(1,Power_num+1):
            temp_dict = {}
            check_list = ["Vendor","isPSUOn","SN","psuPresent","Model","FanDuty","id","Present"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, psu_id, CMM_IP, GET_POWER_API)
            if baseline:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = eval(output)
                    except Exception as e:
                        message = "[PSU{0}] {1}".format(psu_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(Main_log,message,timestamp=False)
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
                        temp = eval(output)
                    except Exception as e:
                        message = "[PSU{0}] {1}".format(psu_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(Main_log, message, timestamp=False)
                    else:
                        if not temp.get("error"):
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                API_TEMP["psu_{0}".format(psu_id)] = temp_dict
            time.sleep(1)
        for fan_id in range(1,Fan_num+1):
            temp_dict = {}
            check_list = ["id","FanPresent","Present","FanStatus","Duty"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,fan_id,CMM_IP,GET_FAN_API)
            if baseline:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = eval(output)
                    except Exception as e:
                        message = "[FAN{0}] {1}".format(fan_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(Main_log, message, timestamp=False)
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
                        temp = eval(output)
                    except Exception as e:
                        message = "[FAN{0}] {1}".format(fan_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(Main_log, message, timestamp=False)
                    else:
                        if isinstance(temp, list):
                            temp = temp[0]
                        if not temp.get("error"):
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                API_TEMP["fan_{0}".format(fan_id)] = temp_dict
            time.sleep(1)
        for switch_id in range(1,Switch_num+1):
            temp_dict = {}
            check_list = ["id","swPresent","Present","Status","Vendor","SwitchType","IP","Netmask","Gateway"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,switch_id,CMM_IP,GET_SWITCH_API)
            if baseline:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = eval(output)
                    except Exception as e:
                        message = "[Switch{0}] {1}".format(switch_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(Main_log, message, timestamp=False)
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
                        temp = eval(output)
                    except Exception as e:
                        message = "[Switch{0}] {1}".format(switch_id,e)
                        CMM.show_message(message,timestamp=False,color="red")
                        CMM.save_data(Main_log, message, timestamp=False)
                    else:
                        if not temp.get("error"):
                            for item in check_list:
                                temp_dict[item] = temp.get(item)
                API_TEMP["switch_{0}".format(switch_id)] = temp_dict
            time.sleep(1)
    else:
        return False
    status, output = CMM.curl_login_logout(CMM_IP, flag="logout", username=CMM_username, password=CMM_password, csrf_token=CSRFToken)
    if status == 0:
        message = "Logout Web"
        CMM.save_step_result(Main_log,message,flag="PASS")
        show_step_result(message,flag="PASS")
    else:
        message = "[curl] Logout Web FAIL !\n{0}".format(output)
        CMM.save_data(Main_log, message,timestamp=False)
        CMM.save_data(Error_log,message,timestamp=False)
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
        case_name = "Case: " + Module_name.replace("_", " ")
        self.case_init(case_name, Log_dir)
        CMM.save_data(Main_log,self.banner(case_name),timestamp=False)

    def b_clear_sel(self):
        cmd = "{0} sel clear".format(IPMITOOL)
        message = "Clean SEL"
        status,output = CMM.run_cmd(cmd)
        CMM.save_data(Main_log,"{0}\nreturncode: {1}\n{2}".format(cmd,status,output))
        if status == 0:
            show_step_result(message,flag="PASS")
            CMM.save_step_result(Main_log,message,flag="PASS")
        else:
            show_step_result(message,flag="FAIL")
            CMM.save_step_result(Main_log,message,flag="FAIL")
            CMM.save_step_result(Error_log,message,flag="FAIL")

    def c_cold_reset(self):
        global CASE_PASS
        temp_text = "CMM Cold Reset"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        FW_status = CollectFWInfo(baseline=True)
        SDR_status = CollectSDRInfo(baseline=True)
        CMM_status = CollectAPIInfo(baseline=True)
        CMM.save_data(Main_log,"[API info]\n{0}".format(str(API_BASELINE)),timestamp=False)
        CMM.save_data(Main_log,"[OEM info]\n{0}".format(str(OEM_BASELINE)),timestamp=False)
        if not FW_status or not SDR_status or not FW_status:
            CASE_PASS = False
            message = "Collect baseline FAIL !"
            CMM.save_data(Main_log, message,timestamp=False)
            CMM.save_data(Error_log,message,timestamp=False)
            show_step_result("Collect baseline",flag="FAIL")
            return False
        else:
            show_step_result("Collect baseline",flag="PASS")
        start_time = datetime.datetime.now()
        while CMM.calc_time_interval(start_time, datetime.datetime.now()) < Stress_time:
            cold_reset_time = CMMColdReset()
            if not RESET_OK:
                CASE_PASS = False
                break
            else:
                message = "Cold Reset Time: {0}s\n".format(cold_reset_time)
                RESET_TIME.append(int(cold_reset_time))
                CMM.show_message(message,timestamp=False,color="blue")
                CMM.save_data(Main_log,message,timestamp=False)
            CollectFWInfo()
            CollectSDRInfo()
            CollectAPIInfo()
            CMM.save_data(Main_log,"[API info]\n{0}".format(str(API_TEMP)),timestamp=False)
            CMM.save_data(Main_log,"[OEM info]\n{0}".format(str(OEM_TEMP)),timestamp=False)
            API_fail = False
            OEM_fail = False
            if API_BASELINE != API_TEMP:
                CASE_PASS = False
                message = "[API] The CMM info is changed !"
                CMM.show_message(message,timestamp=False,color="red")
                CMM.save_data(Main_log,message,timestamp=False)
                CMM.save_data(Error_log,message,timestamp=False)
                temp_baselines = []
                temp_values = []
                for key in API_BASELINE:
                    temp_baseline = API_BASELINE.get(key)
                    temp_value = API_TEMP.get(key)
                    if temp_baseline != temp_value:
                        temp_baselines.append({key:temp_baseline})
                        temp_values.append({key:temp_value})
                baseline_text = "[baseline data]"
                for item in temp_baselines:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key,value)
                    baseline_text = "\n".join([baseline_text,info])
                loop_text = "[loop data]"
                for item in temp_values:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key,value)
                    loop_text = "\n".join([loop_text,info])
                CMM.show_message(baseline_text,timestamp=False)
                CMM.show_message(loop_text,timestamp=False)
                CMM.save_data(Main_log,baseline_text,timestamp=False)
                CMM.save_data(Main_log,loop_text,timestamp=False)
                CMM.save_data(Error_log,baseline_text,timestamp=False)
                CMM.save_data(Error_log,loop_text,timestamp=False)
                API_fail = True
            else:
                message = "[API] Check CMM info OK."
                show_step_result("[API] Check CMM info",flag="PASS")
                CMM.save_data(Main_log,message,timestamp=False)
            if OEM_BASELINE != OEM_TEMP:
                CASE_PASS = False
                message = "[OEM] The CMM info is changed !"
                temp_baselines = []
                temp_values = []
                for key in OEM_BASELINE:
                    temp_baseline = OEM_BASELINE.get(key)
                    temp_value = OEM_TEMP.get(key)
                    if temp_baseline != temp_value:
                        temp_baselines.append({key: temp_baseline})
                        temp_values.append({key: temp_value})
                CMM.show_message(message, timestamp=False, color="red")
                CMM.save_data(Main_log, message, timestamp=False)
                CMM.save_data(Error_log, message, timestamp=False)
                baseline_text = "[baseline data]"
                for item in temp_baselines:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key, value)
                    baseline_text = "\n".join([baseline_text, info])
                loop_text = "[loop data]"
                for item in temp_values:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key, value)
                    loop_text = "\n".join([loop_text, info])
                CMM.show_message(baseline_text, timestamp=False)
                CMM.show_message(loop_text, timestamp=False)
                CMM.save_data(Main_log,baseline_text,timestamp=False)
                CMM.save_data(Main_log,loop_text,timestamp=False)
                CMM.save_data(Error_log,baseline_text,timestamp=False)
                CMM.save_data(Error_log,loop_text,timestamp=False)
                OEM_fail = True
            else:
                message = "[OEM] Check CMM info OK."
                show_step_result("[OEM] Check CMM info",flag="PASS")
                CMM.save_data(Main_log,message,timestamp=False)
            if API_fail or OEM_fail:
                break
        else:
            average_time = sum(RESET_TIME)/len(RESET_TIME)
            message = "[Stress] CMM Cold Reset"
            show_step_result(message,flag="PASS")
            CMM.save_step_result(Main_log,message,flag="PASS")
            temp_text = "Stress Time: {0}s".format(Stress_time)
            CMM.show_message(temp_text,timestamp=False,color="blue")
            CMM.save_data(Main_log, temp_text, timestamp=False)
            temp_text = "Average Reset Time: {0}s".format(average_time)
            CMM.show_message(temp_text,timestamp=False,color="blue")
            CMM.save_data(Main_log, temp_text, timestamp=False)

    def h_collect_sel(self):
        cmd = "{0} sel elist &> {1}".format(IPMITOOL,SEL_log)
        message = "Collect SEL"
        status,output = CMM.run_cmd(cmd)
        CMM.save_data(Main_log,"{0}\nreturncode: {1}\n{2}".format(cmd,status,output))
        if status == 0:
            show_step_result(message,flag="PASS")
            CMM.save_step_result(Main_log,message,flag="PASS")
        else:
            show_step_result(message,flag="FAIL")
            CMM.save_step_result(Main_log,message,flag="FAIL")
            CMM.save_step_result(Error_log,message,flag="FAIL")


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



