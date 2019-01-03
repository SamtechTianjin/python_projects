# -*- coding:utf-8 -*-

import os
import sys
import unittest
import time,datetime
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
SEL_log = os.path.join(log_dir,"SEL.log")
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD
STRESS_TIME = config.COLD_RESET_TIME
PSU_NUM = config.PSU_NUM
SWITCH_NUM = config.SWITCH_NUM
FAN_NUM = config.FAN_NUM
NODE_NUM = config.NODE_NUM

# Global variable
CSRFToken = ""
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)
RESET_OK = True
RESET_TIME = []
OEM_BASELINE = {}
API_BASELINE = {}
OEM_TEMP = {}
API_TEMP = {}
GET_PSU_OEM = "raw 0x3a 0x51"
GET_FAN_OEM = "raw 0x3a 0x53"
GET_SWITCH_OEM = "raw 0x3a 0x5f"
RESET_OEM = "raw 0x06 0x02"
GET_PSU_API = "/api/cmminfo/psus/"
GET_FAN_API = "/api/cmminfo/fans/"
GET_SWITCH_API = "/api/cmminfo/switches/"
GET_SINGLENODE_API = "/api/cmminfo/singlenode/"



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

def CollectFWInfo(baseline=False):
    global OEM_BASELINE
    global OEM_TEMP
    is_fail = False
    message = "Collect FW info"
    cmd = "{0} raw 0x06 0x01 2>/dev/null".format(IPMITOOL)
    status, output = CMM.retry_run_cmd(cmd)
    if status == 0:
        show_step_result(message,flag="PASS")
        CMM.save_step_result(main_log,message,flag="PASS")
    else:
        show_step_result(message,flag="FAIL")
        CMM.save_step_result(main_log,message,flag="FAIL")
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
        CMM.save_step_result(main_log,message,flag="PASS")
    else:
        show_step_result(message,flag="FAIL")
        CMM.save_step_result(main_log,message,flag="FAIL")
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
    LOGIN_FAIL = False
    output = ""
    start_time = datetime.datetime.now()
    """ Retry login after CMM reset """
    while CMM.calc_time_interval(start_time, datetime.datetime.now()) < login_time:
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            message = "Login Web"
            CMM.save_step_result(main_log,message,flag="PASS")
            show_step_result(message,flag="PASS")
            CSRFToken = output.strip()
            break
        time.sleep(10)
    else:
        message = "[curl] Login Web FAIL after {0} seconds !\n{1}".format(login_time,output)
        CMM.save_data(main_log, message,timestamp=False)
        CMM.show_message(message,timestamp=False,color="red")
        MAIN_LOG_list.append(message)
        LOGIN_FAIL = True
    if not LOGIN_FAIL:
        """ API检测PSU信息 """
        for psu_id in range(1,PSU_NUM+1):
            temp_dict = {}
            # check_list = ["Vendor","isPSUOn","SN","psuPresent","Model","FanDuty","id","Present"]
            check_list = ["Vendor","isPSUOn","SN","psuPresent","Model","id","Present"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, psu_id, IP, GET_PSU_API)
            if baseline:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = eval(output)
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
                        temp = eval(output)
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
        """ API检测FAN信息 """
        for fan_id in range(1,FAN_NUM+1):
            temp_dict = {}
            # check_list = ["id","FanPresent","Present","FanStatus","Duty"]
            check_list = ["id","FanPresent","Present","FanStatus"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,fan_id,IP,GET_FAN_API)
            if baseline:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = eval(output)
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
                        temp = eval(output)
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
        """ API检测Switch信息 """
        for switch_id in range(1,SWITCH_NUM+1):
            temp_dict = {}
            check_list = ["id","swPresent","Present","Status","Vendor","SwitchType","IP","Netmask","Gateway"]
            cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,switch_id,IP,GET_SWITCH_API)
            if baseline:
                status, output = CMM.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        temp = eval(output)
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
                        temp = eval(output)
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
        """ API检测Node信息 """
        for node_id in range(NODE_NUM):
            API_id = node_id + 1
            temp_dict = {}
            check_list = {
                "present": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':3,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API),
                "PwrState": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':1,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API),
                "UID": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':7,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API),
                "LAN1_IPv4Addr": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,1,3,IP,GET_SINGLENODE_API),
                "LAN8_IPv4Addr": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,8,3,IP,GET_SINGLENODE_API),
                "LAN1_IPv4Src": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,1,4,IP,GET_SINGLENODE_API),
                "LAN8_IPv4Src": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,8,4,IP,GET_SINGLENODE_API),
                "LAN1_MACAddr": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 5, IP, GET_SINGLENODE_API),
                "LAN8_MACAddr": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 5, IP, GET_SINGLENODE_API),
                "LAN1_IPv4SubMask": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 6, IP, GET_SINGLENODE_API),
                "LAN8_IPv4SubMask": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 6, IP, GET_SINGLENODE_API),
                "LAN1_IPv4DefGateway": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 12, IP, GET_SINGLENODE_API),
                "LAN8_IPv4DefGateway": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 12, IP, GET_SINGLENODE_API),
                "LAN1_VlanID": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 20, IP, GET_SINGLENODE_API),
                "LAN8_VlanID": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 20, IP, GET_SINGLENODE_API),
                "LAN1_IPv6Enable": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 195, IP, GET_SINGLENODE_API),
                "LAN8_IPv6Enable": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 195, IP, GET_SINGLENODE_API),
                "LAN1_IPv6Src": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 196, IP, GET_SINGLENODE_API),
                "LAN8_IPv6Src": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 196, IP, GET_SINGLENODE_API),
                "LAN1_IPv6Addr": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 197, IP, GET_SINGLENODE_API),
                "LAN8_IPv6Addr": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 197, IP, GET_SINGLENODE_API),
                "LAN1_IPv6Gateway": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 199, IP, GET_SINGLENODE_API),
                "LAN8_IPv6Gateway": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 199, IP, GET_SINGLENODE_API),
                "LAN1_NCSIPortNum": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 1, 204, IP, GET_SINGLENODE_API),
                "LAN8_NCSIPortNum": "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, 8, 204, IP, GET_SINGLENODE_API),
            }
            if baseline:
                for name,cmd in check_list.iteritems():
                    status, output = CMM.retry_run_cmd(cmd)
                    if status == 0:
                        try:
                            temp = eval(output)
                        except Exception as e:
                            message = "[Node{0}] {1}".format(API_id, e)
                            CMM.show_message(message, timestamp=False, color="red")
                            CMM.save_data(main_log, message, timestamp=False)
                            collect_baseline = False
                        else:
                            if temp.get("error"):
                                collect_baseline = False
                            else:
                                temp_dict[name] = temp
                    else:
                        collect_baseline = False
                    time.sleep(1)
                API_BASELINE["Node_{0}".format(API_id)] = temp_dict
            else:
                for name, cmd in check_list.iteritems():
                    status, output = CMM.retry_run_cmd(cmd)
                    if status == 0:
                        try:
                            temp = eval(output)
                        except Exception as e:
                            message = "[Node{0}] {1}".format(API_id, e)
                            CMM.show_message(message, timestamp=False, color="red")
                            CMM.save_data(main_log, message, timestamp=False)
                        else:
                            if not temp.get("error"):
                                temp_dict[name] = temp
                    time.sleep(1)
                API_TEMP["Node_{0}".format(API_id)] = temp_dict
            time.sleep(3)
    else:
        return False
    status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD, csrf_token=CSRFToken)
    if status == 0:
        message = "Logout Web"
        CMM.save_step_result(main_log,message,flag="PASS")
        show_step_result(message,flag="PASS")
    else:
        message = "[curl] Logout Web FAIL !\n{0}".format(output)
        CMM.save_data(main_log, message, timestamp=False)
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

    """
    def b_clear_sel(self):
        cmd = "{0} sel clear".format(IPMITOOL)
        message = "Clean SEL"
        status,output = CMM.run_cmd(cmd)
        CMM.save_data(main_log,"{0}\nreturncode: {1}\n{2}".format(cmd,status,output))
        if status == 0:
            show_step_result(message,flag="PASS")
            CMM.save_step_result(main_log,message,flag="PASS")
        else:
            show_step_result(message,flag="FAIL")
            CMM.save_step_result(main_log,message,flag="FAIL")
    """

    def c_cold_reset(self):
        global CASE_PASS
        temp_text = "CMM Cold Reset"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        FW_status = CollectFWInfo(baseline=True)
        SDR_status = CollectSDRInfo(baseline=True)
        CMM_status = CollectAPIInfo(baseline=True)
        CMM.save_data(main_log,"[API info]\n{0}".format(str(API_BASELINE)),timestamp=False)
        CMM.save_data(main_log,"[OEM info]\n{0}".format(str(OEM_BASELINE)),timestamp=False)
        if not FW_status or not SDR_status or not CMM_status:
            CASE_PASS = False
            message = "Collect baseline FAIL !"
            CMM.save_data(main_log, message,timestamp=False)
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
                message = "Cold Reset Time: {0}s\n".format(cold_reset_time)
                RESET_TIME.append(int(cold_reset_time))
                CMM.show_message(message,timestamp=False,color="blue")
                CMM.save_data(main_log,message,timestamp=False)
            CollectFWInfo()
            CollectSDRInfo()
            CollectAPIInfo()
            CMM.save_data(main_log,"[API info]\n{0}".format(str(API_TEMP)),timestamp=False)
            CMM.save_data(main_log,"[OEM info]\n{0}".format(str(OEM_TEMP)),timestamp=False)
            API_fail = False
            OEM_fail = False
            if API_BASELINE != API_TEMP:
                CASE_PASS = False
                message = "[API] The CMM info is changed !"
                CMM.show_message(message,timestamp=False,color="red")
                MAIN_LOG_list.append(message)
                CMM.save_data(main_log,message,timestamp=False)
                # temp_list = CMM.compare_dict(API_BASELINE,API_TEMP)
                # MAIN_LOG_list.extend(temp_list)
                baselineList,loopdataList = CMM.compare_dict(API_BASELINE,API_TEMP)
                MAIN_LOG_list.append("[Baseline]")
                MAIN_LOG_list.extend(baselineList)
                MAIN_LOG_list.append("[LoopData]")
                MAIN_LOG_list.extend(loopdataList)
                temp_baselines = []
                temp_values = []
                for key in API_BASELINE:
                    temp_baseline = API_BASELINE.get(key)
                    temp_value = API_TEMP.get(key)
                    if temp_baseline != temp_value:
                        temp_baselines.append({key:temp_baseline})
                        temp_values.append({key:temp_value})
                baseline_text = "[Baseline]"
                for item in temp_baselines:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key,value)
                    baseline_text = " ".join([baseline_text,info])
                loop_text = "[LoopData]"
                for item in temp_values:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key,value)
                    loop_text = " ".join([loop_text,info])
                CMM.show_message(baseline_text,timestamp=False)
                # MAIN_LOG_list.append(baseline_text)
                CMM.show_message(loop_text,timestamp=False)
                # MAIN_LOG_list.append(loop_text)
                CMM.save_data(main_log,baseline_text,timestamp=False)
                CMM.save_data(main_log,loop_text,timestamp=False)
                API_fail = True
            else:
                message = "[API] Check CMM info OK."
                show_step_result("[API] Check CMM info",flag="PASS")
                CMM.save_data(main_log,message,timestamp=False)
            if OEM_BASELINE != OEM_TEMP:
                CASE_PASS = False
                message = "[OEM] The CMM info is changed !"
                CMM.show_message(message, timestamp=False, color="red")
                MAIN_LOG_list.append(message)
                CMM.save_data(main_log, message, timestamp=False)
                temp_baselines = []
                temp_values = []
                for key in OEM_BASELINE:
                    temp_baseline = OEM_BASELINE.get(key)
                    temp_value = OEM_TEMP.get(key)
                    if temp_baseline != temp_value:
                        temp_baselines.append({key: temp_baseline})
                        temp_values.append({key: temp_value})
                baseline_text = "[Baseline]"
                for item in temp_baselines:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key, value)
                    baseline_text = " ".join([baseline_text, info])
                loop_text = "[LoopData]"
                for item in temp_values:
                    key = item.keys()[0]
                    value = item.get(key)
                    info = "{0}: {1}".format(key, value)
                    loop_text = " ".join([loop_text, info])
                CMM.show_message(baseline_text, timestamp=False)
                MAIN_LOG_list.append(baseline_text)
                CMM.show_message(loop_text, timestamp=False)
                MAIN_LOG_list.append(loop_text)
                CMM.save_data(main_log, baseline_text, timestamp=False)
                CMM.save_data(main_log, loop_text, timestamp=False)
                OEM_fail = True
            else:
                message = "[OEM] Check CMM info OK."
                show_step_result("[OEM] Check CMM info",flag="PASS")
                CMM.save_data(main_log,message,timestamp=False)
            if API_fail or OEM_fail:
                break
        else:
            average_time = sum(RESET_TIME)/len(RESET_TIME)
            message = "[Stress] CMM Cold Reset"
            show_step_result(message,flag="PASS")
            CMM.save_step_result(main_log,message,flag="PASS")
            temp_text = "Stress Time: {0}s".format(STRESS_TIME)
            CMM.show_message(temp_text,timestamp=False,color="blue")
            CMM.save_data(main_log, temp_text, timestamp=False)
            temp_text = "Average Reset Time: {0}s".format(average_time)
            CMM.show_message(temp_text,timestamp=False,color="blue")
            CMM.save_data(main_log, temp_text, timestamp=False)
            MAIN_LOG_list.append("- Stress Time: {0}s".format(STRESS_TIME))
            MAIN_LOG_list.append("- Average Reset Time: {0}s".format(average_time))

    """
    def h_collect_sel(self):
        cmd = "{0} sel elist &> {1}".format(IPMITOOL,SEL_log)
        message = "Collect SEL"
        status,output = CMM.run_cmd(cmd)
        CMM.save_data(main_log,"{0}\nreturncode: {1}\n{2}".format(cmd,status,output))
        if status == 0:
            show_step_result(message,flag="PASS")
            CMM.save_step_result(main_log,message,flag="PASS")
        else:
            show_step_result(message,flag="FAIL")
            CMM.save_step_result(main_log,message,flag="FAIL")
    """

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