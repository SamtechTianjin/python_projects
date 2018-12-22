# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time
import re
import json
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import LOG_DIR,MAIN_LOG
from libs.common import CMM,unicode_convert
from libs.console_show import format_item,show_step_result
import conf.config as config

module_name = os.path.splitext(os.path.basename(__file__))[0]
log_dir = os.path.join(LOG_DIR,module_name)
main_log = os.path.join(log_dir,"{0}.log".format(module_name))
SEL_log = os.path.join(log_dir,"SEL.log")
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD
PSU_NUM = config.PSU_NUM
SWITCH_NUM = config.SWITCH_NUM
FAN_NUM = config.FAN_NUM
NODE_NUM = config.NODE_NUM

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_FAN_API = "/api/cmminfo/fans/"
GET_SWITCH_API = "/api/cmminfo/switches/"
GET_PSU_API = "/api/cmminfo/psus"
GET_SINGLENODE_API = "/api/cmminfo/singlenode/"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)
Present_Fan = []
Present_Switch = []
Present_Psu = []
Present_Node = []

# 获得指定id的风扇信息--API  id从1开始
def GetFanInfoViaAPI(CSRFToken,id):
    fan_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_FAN_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("FAN {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[API] Get FAN{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            fan_info = json.loads(output.strip())
            if isinstance(fan_info,list):
                fan_info = fan_info[0]
        except Exception as e:
            temp = "[FAN{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
        else:
            if fan_info.get("error"):
                temp = "[API] Get FAN{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                fan_info = None
            else:
                fan_info = unicode_convert(fan_info)
    return {} if not fan_info else fan_info

# 获得指定id的Switch信息--API  id从1开始
def GetSwitchInfoViaAPI(CSRFToken,id):
    switch_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_SWITCH_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("Switch {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[API] Get Switch{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            switch_info = json.loads(output.strip())
            if isinstance(switch_info,list):
                switch_info = switch_info[0]
        except Exception as e:
            temp = "[Switch{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
        else:
            if switch_info.get("error"):
                temp = "[API] Get Switch{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                switch_info = None
            else:
                switch_info = unicode_convert(switch_info)
    return {} if not switch_info else switch_info

# 获得指定id的电源信息--API  id从1开始
def GetPSUInfoViaAPI(CSRFToken,id):
    PSU_info = None
    cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,id,IP,GET_PSU_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "{0}\n{1}\nreturncode: {2}\n{3}".format("PSU {0}".format(id),cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status != 0:
        temp = "[API] Get PSU{0} info FAIL !".format(id)
        MAIN_LOG_list.append(temp)
        CMM.show_message(temp,timestamp=False,color="red")
    else:
        try:
            PSU_info = json.loads(output.strip())
        except Exception as e:
            temp = "[PSU{0}] {1}".format(id,e)
            CMM.show_message(temp,timestamp=False,color="red")
        else:
            if PSU_info.get("error"):
                temp = "[API] Get PSU{0} info FAIL !".format(id)
                MAIN_LOG_list.append(temp)
                CMM.show_message(temp, timestamp=False, color="red")
                PSU_info = None
            else:
                PSU_info = unicode_convert(PSU_info)
    return {} if not PSU_info else PSU_info

def check_node_Present(node_id):
    OEM_id = node_id
    API_id = node_id + 1
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x03 0x00 0x00".format(IPMITOOL, hex(OEM_id))
    status, output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} Present\n{1}\nreturncode: {2}\n{3}".format(API_id, OEM_cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    OEM_Present = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_Present = temp_list[1]
    return OEM_Present

def checkAllModuleStatus():
    global Present_Fan
    global Present_Switch
    global Present_Psu
    global Present_Node
    is_FAIL = False
    restapi = "/api/cmminfo/allmodulestatus"
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, IP, restapi)
    status, output = CMM.retry_run_cmd(cmd)
    message = "[Dashboard] Check all module status\n{0}\nreturncode: {1}\n{2}".format(cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            is_FAIL = True
            temp_text = "[Exception] {0}".format(e)
            CMM.save_data(main_log,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="red")
            MAIN_LOG_list.append(temp_text)
        else:
            if json_data.get("error"):
                is_FAIL = True
                MAIN_LOG_list.append("{0}".format(output))
                CMM.show_message("{0}".format(output))
            else:
                FanPreNum = json_data.get("FanPreNum")
                FanTotalNum = json_data.get("FanTotalNum")
                SwitchPreNum = json_data.get("SwitchPreNum")
                SwitchTotalNum = json_data.get("SwitchTotalNum")
                PsuPreNum = json_data.get("PsuPreNum")
                PsuTotalNum = json_data.get("PsuTotalNum")
                NodePreNum = json_data.get("NodePreNum")
                NodeTotalNum = json_data.get("NodeTotalNum")
                # FAN
                for fan_id in range(1,FAN_NUM+1):
                    API_info = GetFanInfoViaAPI(CSRFToken, fan_id)
                    if API_info.get("FanPresent") == 1:
                        Present_Fan.append(fan_id)
                temp_text = "Check FAN number"
                if FanPreNum == len(Present_Fan) and FanTotalNum == FAN_NUM:
                    show_step_result(temp_text,"PASS")
                    CMM.save_step_result(main_log,temp_text,"PASS")
                else:
                    is_FAIL = True
                    temp = "Expect FAN number: {0} {1}".format(FAN_NUM,len(Present_Fan))
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp,timestamp=False,color="red")
                    temp = "Collect FAN number: {0} {1}".format(FanTotalNum,FanPreNum)
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp, timestamp=False, color="red")
                    show_step_result(temp_text,"FAIL")
                    CMM.save_step_result(main_log,temp_text,"FAIL")
                # Switch
                for switch_id in range(1,SWITCH_NUM+1):
                    API_info = GetSwitchInfoViaAPI(CSRFToken, switch_id)
                    if API_info.get("swPresent") == 1:
                        Present_Switch.append(switch_id)
                temp_text = "Check Switch number"
                if SwitchPreNum == len(Present_Switch) and SwitchTotalNum == SWITCH_NUM:
                    show_step_result(temp_text,"PASS")
                    CMM.save_step_result(main_log,temp_text,"PASS")
                else:
                    is_FAIL = True
                    temp = "Expect Switch number: {0} {1}".format(SWITCH_NUM,len(Present_Switch))
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp,timestamp=False,color="red")
                    temp = "Collect Switch number: {0} {1}".format(SwitchTotalNum,SwitchPreNum)
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp, timestamp=False, color="red")
                    show_step_result(temp_text,"FAIL")
                    CMM.save_step_result(main_log,temp_text,"FAIL")
                # Psu
                for psu_id in range(1,PSU_NUM+1):
                    API_info = GetPSUInfoViaAPI(CSRFToken, psu_id)
                    if API_info.get("psuPresent") == 1:
                        Present_Psu.append(psu_id)
                temp_text = "Check PSU number"
                if PsuPreNum == len(Present_Psu) and PsuTotalNum == PSU_NUM:
                    show_step_result(temp_text,"PASS")
                    CMM.save_step_result(main_log,temp_text,"PASS")
                else:
                    is_FAIL = True
                    temp = "Expect PSU number: {0} {1}".format(PSU_NUM,len(Present_Psu))
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp,timestamp=False,color="red")
                    temp = "Collect PSU number: {0} {1}".format(PsuTotalNum,PsuPreNum)
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp, timestamp=False, color="red")
                    show_step_result(temp_text,"FAIL")
                    CMM.save_step_result(main_log,temp_text,"FAIL")
                # Node
                for node_id in range(NODE_NUM):
                    status = check_node_Present(node_id)
                    if status == "01":
                        Present_Node.append(node_id+1)
                temp_text = "Check Node number"
                if NodePreNum == len(Present_Node) and NodeTotalNum == NODE_NUM:
                    show_step_result(temp_text,"PASS")
                    CMM.save_step_result(main_log,temp_text,"PASS")
                else:
                    is_FAIL = True
                    temp = "Expect Node number: {0} {1}".format(NODE_NUM,len(Present_Node))
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp,timestamp=False,color="red")
                    temp = "Collect Node number: {0} {1}".format(NodeTotalNum,NodePreNum)
                    MAIN_LOG_list.append(temp)
                    CMM.save_data(main_log,temp,timestamp=False)
                    CMM.show_message(temp, timestamp=False, color="red")
                    show_step_result(temp_text,"FAIL")
                    CMM.save_step_result(main_log,temp_text,"FAIL")
    else:
        is_FAIL = True
    return False if is_FAIL else True





class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log,self.banner(case_name),timestamp=False)

    def b_curl_login(self):
        global CASE_PASS
        global LOGIN_FAIL
        global CSRFToken
        message = "Login Web"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log,message,"PASS")
            CSRFToken = output.strip()
        else:
            LOGIN_FAIL = True
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
            MAIN_LOG_list.append("{0} FAIL !".format(message))

    def c_check_all_module_status(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check all module status via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        status = checkAllModuleStatus()
        if status:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log, message, flag="PASS")
        else:
            CASE_PASS = False
            show_step_result(message, flag="FAIL")
            CMM.save_step_result(main_log, message, flag="FAIL")







    def y_curl_logout(self):
        if LOGIN_FAIL:
            return False
        message = "Logout Web"
        CMM.show_message(format_item(message),color="green",timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
        if status == 0:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")
        else:
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")

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





