# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time
import json
import re
lis = re.split(r'[/\\]', os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM") + 1])
sys.path.append(path)
from conf.common_config import LOG_DIR, MAIN_LOG
from libs.common import CMM, unicode_convert
from libs.console_show import format_item, show_step_result
import conf.config as config

module_name = os.path.splitext(os.path.basename(__file__))[0]
log_dir = os.path.join(LOG_DIR, module_name)
main_log = os.path.join(log_dir, "{0}.log".format(module_name))
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD
NODE_NUM = config.NODE_NUM
CPU_NUM = config.CPU_NUM
CHANNEL_NUM = config.CHANNEL_NUM
DIMM_NUM_PER_CHANNEL = config.DIMM_NUM_PER_CHANNEL

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP, USERNAME, PASSWORD)
SINGLE_NODE_OEM = "raw 0x3a 0x7c"
SINGLE_NODE_API = "/api/cmminfo/singlenode"
Present_Node = []
NODE_INFO_DICT = {}


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

def getNodeAssetPcieViaAPI(node_id):
    API_id = node_id + 1
    data = []
    restapi = "/api/noderepo/pcie"
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'nodeid':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[Node{0}] Get pcie asset info\n{1}\nreturncode: {2}\n{3}".format(API_id,cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="red")
            data = False
        else:
            if isinstance(json_data,dict) and json_data.get("error"):
                temp_text = "[Node{0}] {1}".format(API_id,json_data)
                MAIN_LOG_list.append(temp_text)
                CMM.show_message(temp_text,timestamp=False,color="red")
                data = False
            else:
                data = json_data
    return data

def getNodeCpuHealthViaAPI(node_id,index):
    # index和node_id 从0开始
    API_id = node_id + 1
    data = {}
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'nodeid':%s,'parameter':12,'paramdata1':2,'paramdata2':%s,'paramdata3':0,'paramdata4':0}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,index,IP,SINGLE_NODE_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[Node{0}] Get cpu{1} health state\n{2}\nreturncode: {3}\n{4}".format(API_id,index,cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="red")
            data = False
        else:
            if json_data.get("error"):
                temp_text = "[Node{0} CPU{1}] {2}".format(API_id,index,json_data)
                MAIN_LOG_list.append(temp_text)
                CMM.show_message(temp_text,timestamp=False,color="red")
                data = False
            else:
                data = json_data
    return data

def getNodeMemHealthViaAPI(node_id,channel_index,dimm_index):
    # node_id channel_index dimm_index 从0开始
    API_id = node_id + 1
    data = {}
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'nodeid':%s,'parameter':12,'paramdata1':3,'paramdata2':%s,'paramdata3':%s,'paramdata4':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,node_id,channel_index,dimm_index,IP,SINGLE_NODE_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[Node{0}] Get channel{1} dimm{2} health state\n{3}\nreturncode: {4}\n{5}".format(API_id,channel_index,dimm_index,cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="red")
            data = False
        else:
            if json_data.get("error"):
                temp_text = "[Node{0} Channel{1} Dimm {2}] {3}".format(API_id,channel_index,dimm_index,json_data)
                MAIN_LOG_list.append(temp_text)
                CMM.show_message(temp_text,timestamp=False,color="red")
                data = False
            else:
                data = json_data
    return data

def getNodePcieHealthViaAPI(node_id,index):
    # index和node_id 从0开始
    API_id = node_id + 1
    data = {}
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'nodeid':%s,'parameter':12,'paramdata1':9,'paramdata2':%s,'paramdata3':0,'paramdata4':0}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,index,IP,SINGLE_NODE_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[Node{0}] Get pcie{1} health state\n{2}\nreturncode: {3}\n{4}".format(API_id,index,cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log,temp_text,timestamp=False)
            CMM.show_message(temp_text,timestamp=False,color="red")
            data = False
        else:
            if json_data.get("error"):
                temp_text = "[Node{0} PCIE{1}] {2}".format(API_id,index,json_data)
                MAIN_LOG_list.append(temp_text)
                CMM.show_message(temp_text,timestamp=False,color="red")
                data = False
            else:
                data = json_data
    return data

def getNodeCpuHealthViaOEM(node_id,index):
    API_id = node_id + 1
    OEM_id = node_id
    cmd = "{0} {1} {2} 0x0c 0x02 {3}".format(IPMITOOL, SINGLE_NODE_OEM, hex(OEM_id), index)
    status, output = CMM.retry_run_cmd(cmd)
    message = "OEM Node{0} CPU{4} health state\n{1}\nreturncode: {2}\n{3}".format(API_id, cmd, status, output, index)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        temp_list = output.split()
    else:
        temp_list = []
        text = "[Node{0} CPU{1}] {2}".format(API_id,index,output)
        MAIN_LOG_list.append(text)
        CMM.show_message(text,timestamp=False,color="red")
    return temp_list

def getNodeMemHealthViaOEM(node_id,channel_index,dimm_index):
    API_id = node_id + 1
    OEM_id = node_id
    cmd = "{0} {1} {2} 0x0c 0x03 {2} {3} {4}".format(IPMITOOL,SINGLE_NODE_OEM,hex(OEM_id),hex(channel_index),hex(dimm_index))
    status, output = CMM.retry_run_cmd(cmd)
    message = "OEM Node{0} channel{1} dimm{2} health state\n{3}\nreturncode: {4}\n{5}".format(API_id, channel_index, dimm_index, cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        temp_list = output.split()
    else:
        temp_list = []
        text = "[Node{0} Channel{1} Dimm{2}] {3}".format(API_id,channel_index,dimm_index,output)
        MAIN_LOG_list.append(text)
        CMM.show_message(text,timestamp=False,color="red")
    return temp_list

def getNodePcieHealthViaOEM(node_id,index):
    API_id = node_id + 1
    OEM_id = node_id
    cmd = "{0} {1} {2} 0x0c 0x09 {3}".format(IPMITOOL, SINGLE_NODE_OEM, hex(OEM_id), index)
    status, output = CMM.retry_run_cmd(cmd)
    message = "OEM Node{0} PCIE{4} health state\n{1}\nreturncode: {2}\n{3}".format(API_id, cmd, status, output, index)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        temp_list = output.split()
    else:
        temp_list = []
        text = "[Node{0} PCIE{1}] {2}".format(API_id,index,output)
        MAIN_LOG_list.append(text)
        CMM.show_message(text,timestamp=False,color="red")
    return temp_list

""" 处理OEM command获得CPU Health信息 """
def parseCPUNodeId(temp_list):
    try:
        API_id = int(temp_list[0],16)+1
    except:
        API_id = "Unknown"
    return API_id

def parseCPUPresent(temp_list):
    try:
        cpuPresent = chr(temp_list[1])
    except:
        cpuPresent = "Unknown"
    return cpuPresent

def parseCPUCritLv(temp_list):
    try:
        temp = int(temp_list[2],16)
    except:
        temp = "Unknown"
    return temp

def parseCPULocation(temp_list):
    data = ""
    try:
        for temp in temp_list[3:11]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parseCPUTempFlag(temp_list):
    try:
        TempFlag = int(temp_list[11],16)
    except:
        TempFlag = "Unknown"
    return TempFlag

def parseCPUCaterr(temp_list):
    try:
        temp = int(temp_list[18],16)
    except:
        temp = "Unknown"
    return temp

def parseCPUConfErr(temp_list):
    try:
        temp = int(temp_list[19],16)
    except:
        temp = "Unknown"
    return temp

def parseCPUTrermaltrip(temp_list):
    try:
        temp = int(temp_list[20],16)
    except:
        temp = "Unknown"
    return temp

def parseCPUProchot(temp_list):
    try:
        temp = int(temp_list[21],16)
    except:
        temp = "Unknown"
    return temp

""" 处理OEM command获得DIMM Health信息 """
def parseMEMLocation(temp_list):
    data = ""
    try:
        for temp in temp_list[3:27]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parseMEMCritLv(temp_list):
    try:
        temp = int(temp_list[2],16)
    except:
        temp = "Unknown"
    return temp

def parseMEMTempFlag(temp_list):
    try:
        temp = int(temp_list[27],16)
    except:
        temp = "Unknown"
    return temp

def parseMEMMRC(temp_list):
    try:
        temp = int(temp_list[32],16)
    except:
        temp = "Unknown"
    return temp

def parseMEMECC(temp_list):
    try:
        temp = int(temp_list[35],16)
    except:
        temp = "Unknown"
    return temp

def parseMEMUnECC(temp_list):
    try:
        temp = int(temp_list[40],16)
    except:
        temp = "Unknown"
    return temp

def parseMEMParity(temp_list):
    try:
        temp = int(temp_list[41],16)
    except:
        temp = "Unknown"
    return temp

""" 处理OEM command获得PCIE Health信息 """
def parsePCIELocation(temp_list):
    data = ""
    try:
        for temp in temp_list[3:19]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parsePCIECritLv(temp_list):
    try:
        temp = int(temp_list[2],16)
    except:
        temp = "Unknown"
    return temp

def parsePCIETempFlag(temp_list):
    try:
        temp = int(temp_list[26],16)
    except:
        temp = "Unknown"
    return temp

def parsePCIEEventCode(temp_list):
    try:
        temp1 = int(temp_list[28],16)
        temp2 = int(temp_list[29],16)
        temp = 256*temp2+temp1
    except:
        temp = "Unknown"
    return temp





class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log, self.banner(case_name), timestamp=False)

    def b_curl_login(self):
        global CASE_PASS
        global LOGIN_FAIL
        global CSRFToken
        message = "Login Web"
        CMM.show_message(format_item(message), color="green", timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="login", username=USERNAME, password=PASSWORD)
        if status == 0:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log, message, "PASS")
            CSRFToken = output.strip()
        else:
            LOGIN_FAIL = True
            CASE_PASS = False
            show_step_result(message, "FAIL")
            CMM.save_step_result(main_log, message, "FAIL")
            MAIN_LOG_list.append("{0} FAIL !".format(message))

    def c_check_node_present_via_ipmi(self):
        global Present_Node
        global NODE_INFO_DICT
        global CASE_PASS
        is_FAIL = False
        temp_text = "- Check Node present via IPMI -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        for node_id in range(NODE_NUM):
            NODE_INFO_DICT["Node{0}".format(node_id + 1)] = {}
            temp = check_node_Present(node_id)
            if temp == "01":
                Present_Node.append(node_id+1)
                CMM.show_message("Node{0} is present".format(node_id+1),timestamp=False)
                NODE_INFO_DICT["Node{0}".format(node_id + 1)]["Present"] = "Y"
            elif temp == "00":
                CMM.show_message("Node{0} is not present".format(node_id+1),timestamp=False)
                NODE_INFO_DICT["Node{0}".format(node_id + 1)]["Present"] = "N"
            else:
                is_FAIL = True
                NODE_INFO_DICT["Node{0}".format(node_id + 1)]["Present"] = "Unknown"
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def d_check_cpu_health_state(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        is_FAIL = False
        temp_text = "- Check cpu health state -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        compare_list = ["CPULocation","CPUCritLv","CPUTempFlag","CPUCaterr","CPUConfErr","CPUTrermaltrip","CPUProchot"]
        for node_id in range(NODE_NUM):
            API_id = node_id+1
            is_fail = False
            if int(node_id+1) not in Present_Node:
                continue
            for index in range(CPU_NUM):
                API_data = getNodeCpuHealthViaAPI(node_id,index)
                API_CPULocation,API_CPUCritLv,API_CPUTempFlag,API_CPUCaterr,API_CPUConfErr,API_CPUTrermaltrip,\
                API_CPUProchot = [API_data.get(item) for item in compare_list]
                OEM_data = getNodeCpuHealthViaOEM(node_id,index)
                if OEM_data:
                    OEM_CPULocation = parseCPULocation(OEM_data)
                    OEM_CPUCritLv = parseCPUCritLv(OEM_data)
                    OEM_CPUTempFlag = parseCPUTempFlag(OEM_data)
                    OEM_CPUCaterr = parseCPUCaterr(OEM_data)
                    OEM_CPUConfErr = parseCPUConfErr(OEM_data)
                    OEM_CPUTrermaltrip = parseCPUTrermaltrip(OEM_data)
                    OEM_CPUProchot = parseCPUProchot(OEM_data)
                    if OEM_CPULocation != API_CPULocation:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPULocation: {2}".format(API_id, index, API_CPULocation)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPULocation: {2}".format(API_id, index, OEM_CPULocation)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CPUCritLv != API_CPUCritLv:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPUCritLv: {2}".format(API_id, index, API_CPUCritLv)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPUCritLv: {2}".format(API_id, index, OEM_CPUCritLv)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CPUTempFlag != API_CPUTempFlag:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPUTempFlag: {2}".format(API_id, index, API_CPUTempFlag)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPUTempFlag: {2}".format(API_id, index, OEM_CPUTempFlag)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CPUCaterr != API_CPUCaterr:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPUCaterr: {2}".format(API_id, index, API_CPUCaterr)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPUCaterr: {2}".format(API_id, index, OEM_CPUCaterr)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CPUConfErr != API_CPUConfErr:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPUConfErr: {2}".format(API_id, index, API_CPUConfErr)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPUConfErr: {2}".format(API_id, index, OEM_CPUConfErr)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CPUTrermaltrip != API_CPUTrermaltrip:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPUTrermaltrip: {2}".format(API_id, index, API_CPUTrermaltrip)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPUTrermaltrip: {2}".format(API_id, index, OEM_CPUTrermaltrip)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CPUProchot != API_CPUProchot:
                        is_fail = True
                        text = "[Node{0}] API CPU{1} CPUProchot: {2}".format(API_id, index, API_CPUProchot)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM CPU{1} CPUProchot: {2}".format(API_id, index, OEM_CPUProchot)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                else:
                    is_fail = True
            text = "[Node{0}] Check cpu health state".format(API_id)
            if is_fail:
                is_FAIL = True
                show_step_result(text,"FAIL")
                CMM.save_step_result(main_log,text,"FAIL")
            else:
                show_step_result(text,"PASS")
                CMM.save_step_result(main_log,text,"PASS")
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def e_check_dimm_health_state(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        is_FAIL = False
        temp_text = "- Check dimm health state -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        compare_list = ["MEMLocation","MEMCritLv","MEMTempFlag","MEMMRC","MEMECC","MEMUnECC","MEMParity"]
        for node_id in range(NODE_NUM):
            API_id = node_id+1
            is_fail = False
            if int(node_id+1) not in Present_Node:
                continue
            for channel_index in range(CHANNEL_NUM):
                for dimm_index in range(DIMM_NUM_PER_CHANNEL):
                    API_data = getNodeMemHealthViaAPI(node_id,channel_index,dimm_index)
                    API_MEMLocation,API_MEMCritLv,API_MEMTempFlag,API_MEMMRC,API_MEMECC,API_MEMUnECC\
                        ,API_MEMParity = [API_data.get(item) for item in compare_list]
                    OEM_data = getNodeMemHealthViaOEM(node_id,channel_index,dimm_index)
                    if OEM_data:
                        OEM_MEMLocation = parseMEMLocation(OEM_data)
                        OEM_MEMCritLv = parseMEMCritLv(OEM_data)
                        OEM_MEMTempFlag = parseMEMTempFlag(OEM_data)
                        OEM_MEMMRC = parseMEMMRC(OEM_data)
                        OEM_MEMECC = parseMEMECC(OEM_data)
                        OEM_MEMUnECC = parseMEMUnECC(OEM_data)
                        OEM_MEMParity = parseMEMParity(OEM_data)
                        if API_MEMLocation != OEM_MEMLocation:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMLocation: {3}".format(API_id, channel_index,dimm_index,API_MEMLocation)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMLocation: {2}".format(API_id, channel_index,dimm_index,OEM_MEMLocation)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_MEMCritLv != OEM_MEMCritLv:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMCritLv: {3}".format(API_id, channel_index,dimm_index,API_MEMCritLv)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMCritLv: {2}".format(API_id, channel_index,dimm_index,OEM_MEMCritLv)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_MEMTempFlag != OEM_MEMTempFlag:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMTempFlag: {3}".format(API_id, channel_index,dimm_index,API_MEMTempFlag)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMTempFlag: {2}".format(API_id, channel_index,dimm_index,OEM_MEMTempFlag)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_MEMMRC != OEM_MEMMRC:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMMRC: {3}".format(API_id, channel_index,dimm_index,API_MEMMRC)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMMRC: {2}".format(API_id, channel_index,dimm_index,OEM_MEMMRC)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_MEMECC != OEM_MEMECC:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMECC: {3}".format(API_id, channel_index,dimm_index,API_MEMECC)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMECC: {2}".format(API_id, channel_index,dimm_index,OEM_MEMECC)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_MEMUnECC != OEM_MEMUnECC:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMUnECC: {3}".format(API_id, channel_index,dimm_index,API_MEMUnECC)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMUnECC: {2}".format(API_id, channel_index,dimm_index,OEM_MEMUnECC)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_MEMParity != OEM_MEMParity:
                            is_fail = True
                            text = "[Node{0}] API Channel{1} Dimm{2} MEMParity: {3}".format(API_id, channel_index,dimm_index,API_MEMParity)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM Channel{1} Dimm{2} MEMParity: {2}".format(API_id, channel_index,dimm_index,OEM_MEMParity)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                    else:
                        is_fail = True
            text = "[Node{0}] Check dimm health state".format(API_id)
            if is_fail:
                is_FAIL = True
                show_step_result(text,"FAIL")
                CMM.save_step_result(main_log,text,"FAIL")
            else:
                show_step_result(text,"PASS")
                CMM.save_step_result(main_log,text,"PASS")
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def f_check_pcie_health_state(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        is_FAIL = False
        temp_text = "- Check pcie health state -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        compare_list = ["PCIELocation", "PCIECritLv", "PCIETempFlag", "PCIEEventCode"]
        for node_id in range(NODE_NUM):
            API_id = node_id+1
            is_fail = False
            if int(node_id+1) not in Present_Node:
                continue
            # 检测PCIE资产信息 获得在位的PCIE设备
            pcieAssetInfo = getNodeAssetPcieViaAPI(node_id)
            if pcieAssetInfo:
                pcie_ids = []
                for temp_dict in pcieAssetInfo:
                    if temp_dict.has_key("pcieid"):
                        pcie_id = int(temp_dict.get("pcieid"))-1
                        pcie_ids.append(pcie_id)
                # 对比在位的PCIE设备信息
                for index in pcie_ids:
                    API_data = getNodePcieHealthViaAPI(node_id,index)
                    API_PCIELocation,API_PCIECritLv,API_PCIETempFlag,API_PCIEEventCode = \
                        [API_data.get(item) for item in compare_list]
                    OEM_data = getNodePcieHealthViaOEM(node_id,index)
                    if OEM_data:
                        OEM_PCIELocation = parsePCIELocation(OEM_data)
                        OEM_PCIECritLv = parsePCIECritLv(OEM_data)
                        OEM_PCIETempFlag = parsePCIETempFlag(OEM_data)
                        OEM_PCIEEventCode = parsePCIEEventCode(OEM_data)
                        if API_PCIELocation != OEM_PCIELocation:
                            is_fail = True
                            text = "[Node{0}] API PCIE{1} PCIELocation: {2}".format(API_id, index,API_PCIELocation)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM PCIE{1} PCIELocation: {2}".format(API_id, index,OEM_PCIELocation)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_PCIECritLv != OEM_PCIECritLv:
                            is_fail = True
                            text = "[Node{0}] API PCIE{1} PCIECritLv: {2}".format(API_id, index,API_PCIECritLv)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM PCIE{1} PCIECritLv: {2}".format(API_id, index,OEM_PCIECritLv)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_PCIETempFlag != OEM_PCIETempFlag:
                            is_fail = True
                            text = "[Node{0}] API PCIE{1} PCIETempFlag: {2}".format(API_id, index,API_PCIETempFlag)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM PCIE{1} PCIETempFlag: {2}".format(API_id, index,OEM_PCIETempFlag)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                        elif API_PCIEEventCode != OEM_PCIEEventCode:
                            is_fail = True
                            text = "[Node{0}] API PCIE{1} PCIEEventCode: {2}".format(API_id, index,API_PCIEEventCode)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                            text = "[Node{0}] OEM PCIE{1} PCIEEventCode: {2}".format(API_id, index,OEM_PCIEEventCode)
                            CMM.show_message(text, timestamp=False, color="red")
                            MAIN_LOG_list.append(text)
                    else:
                        is_fail = True
            text = "[Node{0}] Check pcie health state".format(API_id)
            if is_fail:
                is_FAIL = True
                show_step_result(text,"FAIL")
                CMM.save_step_result(main_log,text,"FAIL")
            else:
                show_step_result(text,"PASS")
                CMM.save_step_result(main_log,text,"PASS")
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def y_curl_logout(self):
        if LOGIN_FAIL:
            return False
        message = "Logout Web"
        CMM.show_message(format_item(message), color="green", timestamp=False)
        status, output = CMM.curl_login_logout(IP, flag="logout", username=USERNAME, password=PASSWORD,
                                               csrf_token=CSRFToken)
        if status == 0:
            show_step_result(message, "PASS")
            CMM.save_step_result(main_log, message, "PASS")
        else:
            show_step_result(message, "FAIL")
            CMM.save_step_result(main_log, message, "FAIL")

    def z_finish(self):
        CMM.save_data(MAIN_LOG, "{0} {1}".format("PASS:" if CASE_PASS else "FAIL:", module_name.replace("_", " ")))
        infos = map(lambda x: "INFO: {0}".format(x), MAIN_LOG_list)
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