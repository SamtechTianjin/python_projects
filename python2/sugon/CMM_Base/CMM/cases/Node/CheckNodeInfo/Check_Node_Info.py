# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time,datetime
import json
import re
import random
import threading
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
MAIN_LOG_list = list()
CASE_PASS = True

# Collect arguments
IP = config.IP
USERNAME = config.USERNAME
PASSWORD = config.PASSWORD
NODE_NUM = config.NODE_NUM

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_SINGLENODE_API = "/api/cmminfo/singlenode/"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

LAN_check_dict = {
    "IPv4Addr": "3",
    "IPv4Src": "4",
    "MACAddr": "5",
    "IPv4SubMask": "6",
    "IPv4DefGateway": "12",
    "VlanID": "20",
    "IPv6Enable": "195",
    "IPv6Src": "196",
    "IPv6Addr": "197",
    "IPv6Gateway": "199",
    "NCSIPortNum": "204",
}

Present_Node = []
OEM_data = {}
API_data = {}
RANDOM_BASE = random.randrange(100, 200)
Convert_Wait_Time = 120

Global_power_dict = {}
LOCK = threading.Lock()

"""
API接口返回值:
PwrState,Present,UID,PwrConsumption
IPv4Src,IPv4Addr,IPv4SubMask,IPv4DefGateway,MACAddr,VlanID,IPv6Enable,IPv6Src,IPv6Addr,IPv6Gateway,NCSIPortNum
BmcVersion,BiosVersion,FruSN
"""

def result_operation(flag, temp_text):
    if flag.upper() == "PASS":
        show_step_result(temp_text, "PASS")
        CMM.save_step_result(main_log, temp_text, flag="PASS")
    else:
        show_step_result(temp_text, "FAIL")
        CMM.save_step_result(main_log, temp_text, flag="FAIL")

def check_node_Present(node_id):
    global Present_Node
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x03 0x00 0x00".format(IPMITOOL,hex(OEM_id))
    status,output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} Present\n{1}\nreturncode: {2}\n{3}".format(int(node_id+1),OEM_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    OEM_Present = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_Present = temp_list[1]
    if not OEM_data.has_key(node_name):
        OEM_data[node_name] = {}
    OEM_data[node_name]["Present"] = OEM_Present
    time.sleep(1)
    API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':3,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API)
    status,output = CMM.retry_run_cmd(API_cmd)
    message = "API Node{0} Present\n{1}\nreturncode: {2}\n{3}".format(int(node_id)+1,API_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    API_Present = "Unknown"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Node{0}] {1}".format(API_id, e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            API_Present = json_data.get("Present")
    if not API_data.has_key(node_name):
        API_data[node_name] = {}
    API_data[node_name]["Present"] = API_Present
    time.sleep(1)
    return {"OEM_Present":OEM_Present,"API_Present":API_Present}

def compare_node_Present(present_dict,node_id):
    CMM.save_data(main_log, "Compare Node Present", timestamp=False)
    global Present_Node
    node = "[Node{0}]".format(node_id+1)
    is_FAIL = False
    OEM_temp = present_dict.get("OEM_Present")
    API_temp = present_dict.get("API_Present")
    if OEM_temp == "01" and API_temp == "Present":
        Present_Node.append(node_id)
    elif OEM_temp == "00" and API_temp == "N/A":
        pass
    else:
        is_FAIL = True
    if is_FAIL:
        message = "OEM Present: {0}\nAPI Present: {1}".format(OEM_temp,API_temp)
        CMM.show_message(message, timestamp=False, color="red")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append("{0} OEM Present: {1}".format(node,OEM_temp))
        MAIN_LOG_list.append("{0} API Present: {1}".format(node,API_temp))
    return False if is_FAIL else True

def check_node_PwrState(node_id):
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x01 0x00 0x00".format(IPMITOOL,hex(OEM_id))
    status,output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} PwrState\n{1}\nreturncode: {2}\n{3}".format(int(node_id+1),OEM_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    OEM_PwrState = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_PwrState = temp_list[1]
    if not OEM_data.has_key(node_name):
        OEM_data[node_name] = {}
    OEM_data[node_name]["PwrState"] = OEM_PwrState
    time.sleep(1)
    API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':1,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API)
    status,output = CMM.retry_run_cmd(API_cmd)
    message = "API Node{0} PwrState\n{1}\nreturncode: {2}\n{3}".format(int(node_id)+1,API_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    API_PwrState = "Unknown"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Node{0}] {1}".format(API_id, e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            API_PwrState = json_data.get("PwrState")
    if not API_data.has_key(node_name):
        API_data[node_name] = {}
    API_data[node_name]["PwrState"] = API_PwrState
    time.sleep(1)
    return {"OEM_PwrState":OEM_PwrState,"API_PwrState":API_PwrState}

def compare_node_PwrState(pwrstate_dict,node_id):
    CMM.save_data(main_log, "Compare Node PwrState", timestamp=False)
    is_FAIL = False
    node = "[Node{0}]".format(node_id + 1)
    OEM_temp = pwrstate_dict.get("OEM_PwrState")
    API_temp = pwrstate_dict.get("API_PwrState")
    if OEM_temp == "01" and API_temp == "Power On":
        pass
    elif OEM_temp == "00" and API_temp == "Power Off":
        pass
    else:
        is_FAIL = True
    if is_FAIL:
        message = "OEM PwrState: {0}\nAPI PwrState: {1}".format(OEM_temp,API_temp)
        CMM.show_message(message, timestamp=False, color="red")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append("{0} OEM PwrState: {1}".format(node,OEM_temp))
        MAIN_LOG_list.append("{0} API PwrState: {1}".format(node,API_temp))
    return False if is_FAIL else True

def check_node_UID(node_id):
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x07 0x00 0x00".format(IPMITOOL,hex(OEM_id))
    status,output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} UID\n{1}\nreturncode: {2}\n{3}".format(int(node_id+1),OEM_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    OEM_UID = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_UID = temp_list[1]
    if not OEM_data.has_key(node_name):
        OEM_data[node_name] = {}
    OEM_data[node_name]["UID"] = OEM_UID
    time.sleep(1)
    API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':7,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API)
    status,output = CMM.retry_run_cmd(API_cmd)
    message = "API Node{0} UID\n{1}\nreturncode: {2}\n{3}".format(int(node_id)+1,API_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    API_UID = "Unknown"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Node{0}] {1}".format(API_id, e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            API_UID = json_data.get("UID")
    if not API_data.has_key(node_name):
        API_data[node_name] = {}
    API_data[node_name]["UID"] = API_UID
    time.sleep(1)
    return {"OEM_UID":OEM_UID,"API_UID":API_UID}

def compare_node_UID(uid_dict,node_id):
    CMM.save_data(main_log, "Compare Node UID", timestamp=False)
    is_FAIL = False
    node = "[Node{0}]".format(node_id + 1)
    OEM_temp = uid_dict.get("OEM_UID")
    API_temp = uid_dict.get("API_UID")
    if OEM_temp == "01" and API_temp == "Light On":
        pass
    elif OEM_temp == "00" and API_temp == "Light Off":
        pass
    else:
        is_FAIL = True
    if is_FAIL:
        message = "OEM UID: {0}\nAPI UID: {1}".format(OEM_temp, API_temp)
        CMM.show_message(message, timestamp=False, color="red")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append("{0} OEM UID: {1}".format(node,OEM_temp))
        MAIN_LOG_list.append("{0} API UID: {1}".format(node,API_temp))
    return False if is_FAIL else True

def check_node_PwrConsumption(node_id):
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    OEM_cmd = "{0} raw 0x3a 0x7c {1} 0x08 0x00 0x00".format(IPMITOOL,hex(OEM_id))
    status,output = CMM.retry_run_cmd(OEM_cmd)
    message = "OEM Node{0} PwrConsumption\n{1}\nreturncode: {2}\n{3}".format(int(node_id+1),OEM_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    OEM_PwrConsumption = "Unknown"
    if status == 0:
        temp_list = output.split()
        OEM_PwrConsumption = " ".join(temp_list[1:])
    if not OEM_data.has_key(node_name):
        OEM_data[node_name] = {}
    OEM_data[node_name]["PwrConsumption"] = OEM_PwrConsumption
    API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':8,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,"0","0",IP,GET_SINGLENODE_API)
    status,output = CMM.retry_run_cmd(API_cmd)
    message = "API Node{0} PwrConsumption\n{1}\nreturncode: {2}\n{3}".format(int(node_id)+1,API_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    API_PwrConsumption = "Unknown"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Node{0}] {1}".format(API_id, e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            API_PwrConsumption = json_data.get("PwrConsumption")
    if not API_data.has_key(node_name):
        API_data[node_name] = {}
    API_data[node_name]["PwrConsumption"] = API_PwrConsumption
    time.sleep(1)
    return {"OEM_PwrConsumption":OEM_PwrConsumption,"API_PwrConsumption":API_PwrConsumption}

def compare_node_PwrConsumption(pwrconsumption_dict,node_id):
    CMM.save_data(main_log, "Compare Node PwrConsumption", timestamp=False)
    is_FAIL = False
    node = "[Node{0}]".format(node_id + 1)
    pass_interval = 10
    OEM_temp = pwrconsumption_dict.get("OEM_PwrConsumption")
    API_temp = pwrconsumption_dict.get("API_PwrConsumption")
    oem = CMM.convert_to_decimal_multi(OEM_temp.split(),prior="L")
    if isinstance(oem,bool)or API_temp == "Unknown":
        is_FAIL = True
    elif abs(int(oem)-int(API_temp))>pass_interval:
        is_FAIL = True
    if is_FAIL:
        message = "OEM PwrConsumption: {0}\nAPI PwrConsumption: {1}".format(OEM_temp, API_temp)
        CMM.show_message(message, timestamp=False, color="red")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append("{0} OEM PwrConsumption: {1}".format(node,OEM_temp))
        MAIN_LOG_list.append("{0} API PwrConsumption: {1}".format(node,API_temp))
    return False if is_FAIL else True

def check_node_FW(node_id):
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    temp_cmd = "{0} raw 0x3a 0x7c {1} 0x06".format(IPMITOOL,hex(OEM_id))
    FW_dict = {}
    for index,item in enumerate(["BmcVersion","BiosVersion","CPLDVersion"]):
        OEM_cmd = "{0} {1} 0x00".format(temp_cmd,hex(index))
        if index == 2:
            continue
        status,output = CMM.retry_run_cmd(OEM_cmd)
        message = "OEM Node{0} {1}\n{2}\nreturncode: {3}\n{4}".format(int(node_id+1),item,OEM_cmd,status,output)
        CMM.save_data(main_log,message,timestamp=False)
        temp = "Unknown"
        if status == 0:
            temp_list = output.split()
            if index == 0:
                temp = " ".join(temp_list[1:])
            else:
                mid_list = []
                for i in temp_list[1:]:
                    if i == "00":
                        break
                    mid_list.append(i)
                temp = " ".join(mid_list)
        if not OEM_data.has_key(node_name):
            OEM_data[node_name] = {}
        OEM_data[node_name][item] = temp
        FW_dict["OEM_{0}".format(item)] = temp
        time.sleep(1)
        API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':6,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,index,"0",IP,GET_SINGLENODE_API)
        status,output = CMM.retry_run_cmd(API_cmd)
        message = "API Node{0} {1}\n{2}\nreturncode: {3}\n{4}".format(int(node_id)+1,item,API_cmd,status,output)
        CMM.save_data(main_log,message,timestamp=False)
        temp = "Unknown"
        if status == 0:
            try:
                json_data = json.loads(output)
            except Exception as e:
                message = "[Node{0}] {1}".format(API_id, e)
                CMM.save_data(main_log, message, timestamp=False)
                CMM.show_message(message, timestamp=False, color="red")
            else:
                temp = json_data.get(item)
        if not API_data.has_key(node_name):
            API_data[node_name] = {}
        API_data[node_name][item] = temp
        FW_dict["API_{0}".format(item)] = temp
        time.sleep(1)
    return FW_dict

def compare_node_FW(FW_dict,node_id):
    CMM.save_data(main_log, "Compare Node FW", timestamp=False)
    is_FAIL = False
    node = "[Node{0}]".format(node_id + 1)
    base_text = "Check node FW {0}"
    for index,item in enumerate(["BmcVersion","BiosVersion","CPLDVersion"]):
        temp_text = base_text.format(item)
        OEM_temp = FW_dict.get("OEM_{0}".format(item))
        API_temp = FW_dict.get("API_{0}".format(item))
        oem = ""
        if index == 0:
            """ eg: '03 61 b5' >>> '3.61' """
            temp_list = OEM_temp.split()
            oem = "{0}.{1}".format(int(temp_list[0]),int(temp_list[1]))
        elif index == 1:
            for i in OEM_temp.split():
                text = chr(int(i,16))
                oem += text
            if oem != API_temp:
                is_FAIL = True
                message = "OEM {0}: {1}\nAPI {2}: {3}".format(item, OEM_temp, item, API_temp)
                CMM.show_message(message, timestamp=False, color="red")
        elif index == 2:
            API_temp = ""
        if oem == API_temp and API_temp != "Unknown":
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, flag="PASS")
        elif re.match(r'{0}'.format(oem),API_temp) and index == 0 and API_temp != "Unknown":
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, flag="PASS")
        else:
            is_FAIL = True
            message = "OEM {0}: {1}\nAPI {2}: {3}".format(item, OEM_temp, item, API_temp)
            CMM.show_message(message, timestamp=False, color="red")
            CMM.save_data(main_log, message, timestamp=False)
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, flag="FAIL")
            MAIN_LOG_list.append("{0} OEM {1}: {2}".format(node,item,OEM_temp))
            MAIN_LOG_list.append("{0} API {1}: {2}".format(node,item,API_temp))
    return False if is_FAIL else True

def check_node_FRU(node_id):
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    OEM_FRU = {}
    API_FRU = {}
    temp_cmd = "{0} raw 0x3a 0x7c {1} 0x0a".format(IPMITOOL,hex(OEM_id))
    for index,item in enumerate(["Chassis","Board","Product"]):
        temp_cmd2 = "{0} {1}".format(temp_cmd,hex(index))
        if index == 0:
            pass
        elif index == 1:
            pass
        elif index == 2:
            for index2,item2 in enumerate(["Manufacturer","Name","PN","SN","Assert_Tag"]):
                temp_item = "{0}_{1}".format(item,item2)
                OEM_cmd = "{0} {1}".format(temp_cmd2,hex(index2))
                if index2 != 3:
                    continue
                status, output = CMM.retry_run_cmd(OEM_cmd)
                message = "OEM Node{0} {1} {2}\n{3}\nreturncode: {4}\n{5}".format(int(node_id) + 1, item,item2, OEM_cmd, status, output)
                CMM.save_data(main_log, message, timestamp=False)
                temp = "Unknown"
                if status == 0:
                    temp_list = output.split()
                    if index2 == 3:
                        mid_list = []
                        for i in temp_list[1:]:
                            if i == "00":
                                break
                            mid_list.append(i)
                        temp = " ".join(mid_list)
                    else:continue   # TODO: "Manufacturer","Name","PN","Assert_Tag"
                if not OEM_data.has_key(node_name):
                    OEM_data[node_name] = {}
                OEM_data[node_name][temp_item] = temp
                OEM_FRU[temp_item] = temp
                time.sleep(1)
                API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':10,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, index, index2, IP, GET_SINGLENODE_API)
                status, output = CMM.retry_run_cmd(API_cmd)
                message = "API Node{0} {1} {2}\n{3}\nreturncode: {4}\n{5}".format(int(node_id) + 1,item, item2, API_cmd, status, output)
                CMM.save_data(main_log, message, timestamp=False)
                temp = "Unknown"
                if status == 0:
                    try:
                        json_data = json.loads(output)
                    except Exception as e:
                        message = "[Node{0}] {1}".format(API_id, e)
                        CMM.save_data(main_log, message, timestamp=False)
                        CMM.show_message(message, timestamp=False, color="red")
                    else:
                        if index == 2 and index2 ==3:
                            temp = json_data.get("FruSN")
                if not API_data.has_key(node_name):
                    API_data[node_name] = {}
                API_data[node_name][temp_item] = temp
                API_FRU[temp_item] = temp
                time.sleep(1)
    return {"OEM_FRU":OEM_FRU,"API_FRU":API_FRU}

def compare_node_FRU(OEM_dict,API_dict,node_id):
    CMM.save_data(main_log, "Compare Node FRU", timestamp=False)
    is_FAIL = False
    node = "[Node{0}]".format(node_id + 1)
    base_text = "Check node FRU {0}"
    for item in OEM_dict:
        temp_text = base_text.format(item)
        if item == "Product_SN":
            OEM_temp = CMM.hex2str(OEM_dict.get(item))
            API_temp = API_dict.get(item)
        else:
            OEM_temp = ""
            API_temp = ""
        if OEM_temp == API_temp and API_temp != "Unknown":
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, flag="PASS")
        else:
            is_FAIL = True
            message = "OEM {0}: {1}\nAPI {2}: {3}".format(item, OEM_temp, item, API_temp)
            CMM.show_message(message, timestamp=False, color="red")
            CMM.save_data(main_log,message,timestamp=False)
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, flag="FAIL")
            MAIN_LOG_list.append("{0} OEM {1}: {2}".format(node,item,OEM_temp))
            MAIN_LOG_list.append("{0} API {1}: {2}".format(node,item,API_temp))
    return False if is_FAIL else True

def check_node_LAN(node_id):
    global API_data
    global OEM_data
    OEM_id = node_id
    API_id = node_id + 1
    node_name = "Node{0}".format(API_id)
    OEM_LAN = {"LAN1":{},"LAN8":{}}
    API_LAN = {"LAN1":{},"LAN8":{}}
    temp_cmd = "{0} raw 0x3a 0x7c {1} 0x0b".format(IPMITOOL,hex(OEM_id))
    for channel_num in [1,8]:
        for item,value in LAN_check_dict.iteritems():
            OEM_cmd = "{0} {1} {2}".format(temp_cmd,hex(channel_num),hex(int(value)))
            status,output = CMM.retry_run_cmd(OEM_cmd)
            message = "OEM Node{0} LAN{1} {2}\n{3}\nreturncode: {4}\n{5}".format(int(node_id) + 1, channel_num, item,OEM_cmd, status, output)
            CMM.save_data(main_log,message,timestamp=False)
            temp = "Unknown"
            if status == 0:
                temp_list = output.split()
                temp = " ".join(temp_list[1:])
            if not OEM_data.has_key(node_name):
                OEM_data[node_name] = {}
            OEM_LAN["LAN{0}".format(channel_num)][item] = temp
            OEM_data[node_name]["LAN{0}_{1}".format(channel_num,item)] = temp
            time.sleep(1)
            API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'nodeid':%s,'parameter':11,'paramdata1':%s,'paramdata2':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,channel_num,int(value),IP,GET_SINGLENODE_API)
            status,output = CMM.retry_run_cmd(API_cmd)
            message = "API Node{0} LAN{1} {2}\n{3}\nreturncode: {4}\n{5}".format(int(node_id)+1,channel_num,item,API_cmd,status,output)
            CMM.save_data(main_log,message,timestamp=False)
            temp = "Unknown"
            if status == 0:
                try:
                    json_data = json.loads(output)
                except Exception as e:
                    message = "[Node{0}] {1}".format(int(node_id)+1,e)
                    CMM.save_data(main_log,message,timestamp=False)
                    CMM.show_message(message,timestamp=False,color="red")
                else:
                    temp = json_data.get(item)
            if not API_data.has_key(node_name):
                API_data[node_name] = {}
            API_LAN["LAN{0}".format(channel_num)][item] = temp
            API_data[node_name]["LAN{0}_{1}".format(channel_num,item)] = temp
            time.sleep(1)
    CMM.save_data(main_log,"{0}\n{1}".format("OEM node {0}".format(API_id),OEM_LAN),timestamp=False)
    CMM.save_data(main_log,"{0}\n{1}".format("API node {0}".format(API_id),API_LAN),timestamp=False)
    return {"OEM_LAN":OEM_LAN,"API_LAN":API_LAN}

def compare_node_LAN(OEM_dict,API_dict,LAN_num,node_id):
    CMM.save_data(main_log,"Compare Node LAN",timestamp=False)
    OEM_flag = "[{0} OEM]".format(LAN_num)
    API_flag = "[{0} API]".format(LAN_num)
    is_FAIL = False
    node = "[Node{0}]".format(node_id + 1)
    for item in LAN_check_dict:
        is_fail = False
        OEM_temp = OEM_dict.get(item)
        API_temp = API_dict.get(item)
        if item == "IPv4Addr" or item == "IPv4SubMask" or item == "IPv4DefGateway":
            oem = CMM.convert_to_IP(OEM_temp.split(),vers=4)
            if oem == API_temp and oem != "Unknown":
                pass
            else:
                is_fail = True
        elif item == "IPv4Src" or item == "IPv6Src":
            if node_id in Present_Node:
                if OEM_temp == "01" and API_temp == "Static":
                    pass
                elif OEM_temp == "02" and API_temp == "DHCP":
                    pass
                else:
                    is_fail = True
        elif item == "MACAddr":
            oem = OEM_temp.replace(" ",".")
            if oem.upper() == API_temp.upper() and oem != "Unknown":
                pass
            else:
                is_fail = True
        # TODO: Vlan ID check
        elif item == "VlanID":
            pass
        elif item == "IPv6Enable":
            if OEM_temp == "00" and API_temp == "Disable":
                pass
            elif OEM_temp == "01" and API_temp == "Enable":
                pass
            else:
                is_fail = True
        elif item == "IPv6Addr" or item == "IPv6Gateway":
            oem = OEM_temp.replace("0","").replace(" ","")
            api = API_temp.replace(":","").replace(" ","")
            if oem == api and oem != "Unknown":
                pass
            else:
                is_fail = True
        elif item == "NCSIPortNum":
            oem = CMM.convert_to_decimal(OEM_temp)
            if str(oem) == str(API_temp) and oem != "Unknown":
                pass
            else:
                is_fail = True
        temp_text = "[{0}] Check {1}".format(LAN_num,item)
        if is_fail:
            is_FAIL = True
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,flag="FAIL")
            message = "{0} {1}\n{2} {3}".format(OEM_flag,"{0}: {1}".format(item,OEM_temp),API_flag,"{0}: {1}".format(item,API_temp))
            CMM.show_message(message,timestamp=False,color="red")
            MAIN_LOG_list.append("{0} {1} {2}".format(node,OEM_flag,"{0}: {1}".format(item,OEM_temp)))
            MAIN_LOG_list.append("{0} {1} {2}".format(node,API_flag,"{0}: {1}".format(item,API_temp)))
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,flag="PASS")
    return False if is_FAIL else True

def check_node_num_via_API():
    global CASE_PASS
    is_fail = False
    restapi = "/api/cmminfo/nodenum"
    API_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'NodeTotalNum':0,'NodePresentNum':0}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,restapi)
    status,output = CMM.retry_run_cmd(API_cmd)
    message = "API Node number\n{0}\nreturncode: {1}\n{2}".format(API_cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    API_NodeTotalNum,API_NodePresentNum = "Unknown","Unknown"
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Check node num] {0}".format(e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            API_NodeTotalNum = json_data.get("NodeTotalNum")
            API_NodePresentNum = json_data.get("NodePresentNum")
    temp_text = "Check node total number"
    if API_NodeTotalNum == NODE_NUM:
        show_step_result(temp_text,"PASS")
        CMM.save_step_result(main_log,temp_text,flag="PASS")
    else:
        is_fail = True
        show_step_result(temp_text,"FAIL")
        CMM.save_step_result(main_log,temp_text,flag="FAIL")
        MAIN_LOG_list.append("NodeTotalNum: {0}".format(API_NodeTotalNum))
    temp_text = "Check node present number"
    if API_NodePresentNum == len(Present_Node):
        show_step_result(temp_text,"PASS")
        CMM.save_step_result(main_log,temp_text,flag="PASS")
    else:
        is_fail = True
        show_step_result(temp_text,"FAIL")
        CMM.save_step_result(main_log,temp_text,flag="FAIL")
        MAIN_LOG_list.append("NodePresentNum: {0}".format(API_NodePresentNum))
    return False if is_fail else True

def control_node_power_via_API(node_id,flag="Power On"):
    API_id = node_id + 1
    restapi = "/api/cmminfo/setnodepower/"
    API_poweroff_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'cmd':0}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, IP, restapi)
    API_poweron_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'cmd':1}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, IP, restapi)
    API_powercycle_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'cmd':2}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, IP, restapi)
    if flag == "Power Off":
        API_cmd = API_poweroff_cmd
    elif flag == "Power Cycle":
        API_cmd = API_powercycle_cmd
    else:
        API_cmd = API_poweron_cmd
    status, output = CMM.retry_run_cmd(API_cmd)
    message = "API Node{0} {1}\n{2}\nreturncode: {3}\n{4}".format(API_id, flag, API_cmd,status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Node{0}] {1}".format(API_id, e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            if json_data.get("id") == API_id:
                return True
    return False

def set_node_power_via_API(node_id,retry_count=3,interval=20):
    API_id = node_id + 1
    def loop_check_power_status(node_id=node_id,retry_count=retry_count,interval=interval,flag="Power On"):
        message = "[Node{1}] {0}".format(flag,API_id)
        while retry_count > 0:
            control_node_power_via_API(node_id, flag)
            time.sleep(interval)
            temp_dict = check_node_PwrState(node_id)
            power_status = temp_dict.get("API_PwrState")
            if power_status == flag:
                break
            retry_count -= 1
        else:
            temp_text = "[Node{1}] {0} FAIL !".format(flag,API_id)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log,temp_text,timestamp=False)
            show_step_result(message,"FAIL")
            return False
        show_step_result(message,"PASS")
        CMM.save_step_result(main_log,message,flag="PASS")
        return True
    # 确保Node Power为Power On状态
    set_ok = loop_check_power_status(flag="Power On")
    if not set_ok:
        return False
    # 1. Power off
    set_ok = loop_check_power_status(flag="Power Off",retry_count=1)
    if not set_ok:
        return False
    # 2. Power on
    set_ok = loop_check_power_status(flag="Power On",retry_count=1)
    if not set_ok:
        return False
    # 3. Power cycle
    wait_time = 60
    status = control_node_power_via_API(node_id,flag="Power Cycle")
    fail_message = "[Node{0}] Power Cycle FAIL !".format(API_id)
    if not status:
        MAIN_LOG_list.append(fail_message)
        CMM.save_data(main_log,fail_message,timestamp=False)
        show_step_result("[Node{0}] Power Cycle".format(API_id),"FAIL")
        return False
    # Wait power off
    start_time = datetime.datetime.now()
    while True:
        end_time = datetime.datetime.now()
        if CMM.calc_time_interval(start_time,end_time) > wait_time:
            temp_text = "[Node{0} Power Cycle] Power Off exceeds {1}s".format(API_id,wait_time)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log, temp_text, timestamp=False)
            show_step_result("[Node{0}] Power Cycle".format(API_id), "FAIL")
            return False
        temp_dict = check_node_PwrState(node_id)
        power_status = temp_dict.get("API_PwrState")
        if power_status == "Power Off":
            break
    # Wait power on
    start_time = datetime.datetime.now()
    while True:
        end_time = datetime.datetime.now()
        if CMM.calc_time_interval(start_time,end_time) > wait_time:
            temp_text = "[Node{0} Power Cycle] Power On exceeds {1}s".format(API_id,wait_time)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log, temp_text, timestamp=False)
            show_step_result("[Node{0}] Power Cycle".format(API_id), "FAIL")
            return False
        temp_dict = check_node_PwrState(node_id)
        power_status = temp_dict.get("API_PwrState")
        if power_status == "Power On":
            break
    show_step_result("[Node{0}] Power Cycle".format(API_id),"PASS")
    return True

def controll_node_uid_via_API(node_id,flag="ON"):
    API_id = node_id + 1
    restapi = "/api/cmminfo/setnodeidled/"
    API_lighton_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'cmd':1}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, IP, restapi)
    API_lightoff_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'cmd':2}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, API_id, IP, restapi)
    if flag.upper() == "OFF":
        API_cmd = API_lightoff_cmd
    else:
        API_cmd = API_lighton_cmd
    status, output = CMM.retry_run_cmd(API_cmd)
    message = "API Node{0} Light{1}\n{2}\nreturncode: {3}\n{4}".format(API_id, flag, API_cmd,status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            message = "[Node{0}] {1}".format(API_id, e)
            CMM.save_data(main_log, message, timestamp=False)
            CMM.show_message(message, timestamp=False, color="red")
        else:
            if json_data.get("id") == API_id:
                return True
    return False

def set_node_uid_via_API(node_id):
    # 执行命令后的等待时间 命令执行间隔时间
    waitTime = 3
    API_id = node_id + 1
    # 初始化Node状态为Light Off
    status = controll_node_uid_via_API(node_id,flag="OFF")
    time.sleep(waitTime)
    temp_text = "[Node{0}] Init UID LED Light Off".format(API_id)
    if status:
        UID_status = check_node_UID(node_id).get("API_UID")
        if UID_status != "Light Off":
            MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,flag="FAIL")
            return False
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,flag="PASS")
    else:
        MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
        show_step_result(temp_text, "FAIL")
        CMM.save_step_result(main_log, temp_text, flag="FAIL")
        return False
    time.sleep(waitTime)
    # Node Light On
    status = controll_node_uid_via_API(node_id,flag="ON")
    time.sleep(waitTime)
    temp_text = "[Node{0}] Set UID LED Light On".format(API_id)
    if status:
        UID_status = check_node_UID(node_id).get("API_UID")
        if UID_status != "Light On":
            MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,flag="FAIL")
            return False
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,flag="PASS")
    else:
        MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
        show_step_result(temp_text, "FAIL")
        CMM.save_step_result(main_log, temp_text, flag="FAIL")
        return False
    time.sleep(waitTime)
    # Node Light Off
    status = controll_node_uid_via_API(node_id,flag="OFF")
    time.sleep(waitTime)
    temp_text = "[Node{0}] Set UID LED Light Off".format(API_id)
    if status:
        UID_status = check_node_UID(node_id).get("API_UID")
        if UID_status != "Light Off":
            MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,flag="FAIL")
            return False
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,flag="PASS")
    else:
        MAIN_LOG_list.append("{0} FAIL !".format(temp_text))
        show_step_result(temp_text, "FAIL")
        CMM.save_step_result(main_log, temp_text, flag="FAIL")
        return False
    return True

def set_node_ipv4_via_API(node_id):
    API_id = node_id + 1
    restapi = "/api/cmminfo/setnodeipv4"
    is_fail = False
    set_Netmask = "255.255.255.0"
    set_VlanID = RANDOM_BASE + node_id
    set_LAN1_IP = "192.168.100.{0}".format(RANDOM_BASE+node_id)
    set_LAN1_Gateway = "192.168.100.254"
    set_LAN8_IP = "192.168.101.{0}".format(RANDOM_BASE+node_id)
    set_LAN8_Gateway = "192.168.101.254"
    DHCP_IP = "0.0.0.0"
    DHCP_Netmask = "0.0.0.0"
    DHCP_Gateway = "0.0.0.0"
    DHCP_VlanID = 0
    API_LAN1_Static_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':1,'address':'%s','netmask':'%s','gateway':'%s','VlanID':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,1,set_LAN1_IP,set_Netmask,set_LAN1_Gateway,set_VlanID,IP,restapi)
    API_LAN1_DHCP_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':2,'address':'%s','netmask':'%s','gateway':'%s','VlanID':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,1,DHCP_IP,DHCP_Netmask,DHCP_Gateway,DHCP_VlanID,IP,restapi)
    API_LAN8_Static_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':1,'address':'%s','netmask':'%s','gateway':'%s','VlanID':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,8,set_LAN8_IP,set_Netmask,set_LAN8_Gateway,set_VlanID,IP,restapi)
    API_LAN8_DHCP_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':2,'address':'%s','netmask':'%s','gateway':'%s','VlanID':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,8,DHCP_IP,DHCP_Netmask,DHCP_Gateway,DHCP_VlanID,IP,restapi)
    def collect_ipv4_info():
        LAN_info = []
        temp_dict = check_node_LAN(node_id)
        for l in ["LAN1","LAN8"]:
            ip = temp_dict.get("API_LAN").get(l).get("IPv4Addr")
            netmask = temp_dict.get("API_LAN").get(l).get("IPv4SubMask")
            gateway = temp_dict.get("API_LAN").get(l).get("IPv4DefGateway")
            vlanid = temp_dict.get("API_LAN").get(l).get("VlanID")
            ipsrc = temp_dict.get("API_LAN").get(l).get("IPv4Src")
            LAN_info.append([ipsrc,ip,netmask,gateway,vlanid])
        return LAN_info
    # Set LAN1 Static IP
    status1,output1 = CMM.retry_run_cmd(API_LAN1_Static_cmd)
    message1 = "API Node{0} LAN1 Static IP\n{1}\nreturncode: {2}\n{3}".format(API_id,API_LAN1_Static_cmd,status1,output1)
    CMM.save_data(main_log,message1,timestamp=False)
    temp_text1 = "[Node{0}] Set LAN1 Static IP".format(API_id)
    time.sleep(1)
    # Set LAN8 Static IP
    status8, output8 = CMM.retry_run_cmd(API_LAN8_Static_cmd)
    message8 = "API Node{0} LAN8 Static IP\n{1}\nreturncode: {2}\n{3}".format(API_id, API_LAN8_Static_cmd, status8,output8)
    CMM.save_data(main_log, message8, timestamp=False)
    temp_text8 = "[Node{0}] Set LAN8 Static IP".format(API_id)
    time.sleep(Convert_Wait_Time)
    temp_list = collect_ipv4_info()
    CMM.save_data(main_log,"[IPV4] Check LAN Static info\n{0}".format(temp_list),timestamp=False)
    if temp_list[0] != ["Static", set_LAN1_IP, set_Netmask, set_LAN1_Gateway, set_VlanID]:
        is_fail = True
        result_operation("FAIL", temp_text1)
        MAIN_LOG_list.append("[Node{0}] Set LAN1 Static:".format(API_id))
        MAIN_LOG_list.append("Set value: {0}".format(["Static", set_LAN1_IP, set_Netmask, set_LAN1_Gateway, set_VlanID]))
        MAIN_LOG_list.append("Get value: {0}".format(temp_list[0]))
    else:
        result_operation("PASS", temp_text1)
    time.sleep(0.5)
    if temp_list[1] != ["Static", set_LAN8_IP, set_Netmask, set_LAN8_Gateway, set_VlanID]:
        is_fail = True
        result_operation("FAIL", temp_text8)
        MAIN_LOG_list.append("[Node{0}] Set LAN8 Static:".format(API_id))
        MAIN_LOG_list.append("Set value: {0}".format(["Static", set_LAN8_IP, set_Netmask, set_LAN8_Gateway, set_VlanID]))
        MAIN_LOG_list.append("Get value: {0}".format(temp_list[1]))
    else:
        result_operation("PASS", temp_text8)
    time.sleep(1)
    # Restore LAN1|LAN8 DHCP IP, 只检测ipsrc是否变为DHCP
    status1,output1 = CMM.retry_run_cmd(API_LAN1_DHCP_cmd)
    message1 = "API Node{0} LAN1 DHCP IP\n{1}\nreturncode: {2}\n{3}".format(API_id,API_LAN1_DHCP_cmd,status1,output1)
    CMM.save_data(main_log,message1,timestamp=False)
    temp_text1 = "[Node{0}] Restore LAN1 DHCP IP".format(API_id)
    time.sleep(1)
    status8,output8 = CMM.retry_run_cmd(API_LAN8_DHCP_cmd)
    message8 = "API Node{0} LAN8 DHCP IP\n{1}\nreturncode: {2}\n{3}".format(API_id,API_LAN8_DHCP_cmd,status8,output8)
    CMM.save_data(main_log,message8,timestamp=False)
    temp_text8 = "[Node{0}] Restore LAN8 DHCP IP".format(API_id)
    time.sleep(Convert_Wait_Time)
    temp_list = collect_ipv4_info()
    CMM.save_data(main_log, "[IPV4] Check LAN DHCP info\n{0}".format(temp_list), timestamp=False)
    if temp_list[0][0] != "DHCP":
        is_fail = True
        result_operation("FAIL", temp_text1)
        MAIN_LOG_list.append("Restore LAN1 DHCP: {0}".format(temp_list[0]))
    else:
        result_operation("PASS", temp_text1)
    time.sleep(0.5)
    if temp_list[1][0] != "DHCP":
        is_fail = True
        result_operation("FAIL", temp_text8)
        MAIN_LOG_list.append("Restore LAN8 DHCP: {0}".format(temp_list[1]))
    else:
        result_operation("PASS", temp_text8)
    return False if is_fail else True

def set_node_ipv6_via_API(node_id):
    API_id = node_id + 1
    restapi = "/api/cmminfo/setnodeipv6"
    is_fail = False
    set_prefixlen = 112
    set_LAN1_IP = "fe80::abcd:ff{0}".format(hex(RANDOM_BASE+node_id).split("0x")[-1])
    set_LAN1_Gateway = "fe80::abcd:fffe"
    set_LAN8_IP = "fe80::dcba:ff{0}".format(hex(RANDOM_BASE+node_id).split("0x")[-1])
    set_LAN8_Gateway = "fe80::dcba:fffe"
    DHCP_IP = "::"
    DHCP_Gateway = "::"
    API_LAN1_Static_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':1,'address':'%s','prefixlen':'%s','gateway':'%s'}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,1,set_LAN1_IP,set_prefixlen,set_LAN1_Gateway,IP,restapi)
    API_LAN1_DHCP_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':2,'address':'%s','prefixlen':'%s','gateway':'%s'}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,1,DHCP_IP,set_prefixlen,DHCP_Gateway,IP,restapi)
    API_LAN8_Static_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':1,'address':'%s','prefixlen':'%s','gateway':'%s'}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,8,set_LAN8_IP,set_prefixlen,set_LAN8_Gateway,IP,restapi)
    API_LAN8_DHCP_cmd = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'id':%s,'bmcchannel':%s,'ipsrc':2,'address':'%s','prefixlen':'%s','gateway':'%s'}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,8,DHCP_IP,set_prefixlen,DHCP_Gateway,IP,restapi)
    def collect_ipv6_info():
        LAN_info = []
        temp_dict = check_node_LAN(node_id)
        for l in ["LAN1","LAN8"]:
            ip = temp_dict.get("API_LAN").get(l).get("IPv6Addr")
            gateway = temp_dict.get("API_LAN").get(l).get("IPv6Gateway")
            ipsrc = temp_dict.get("API_LAN").get(l).get("IPv6Src")
            LAN_info.append([ipsrc,ip,gateway])
        return LAN_info
    # Set LAN1 Static IP
    status1,output1 = CMM.retry_run_cmd(API_LAN1_Static_cmd)
    message1 = "API Node{0} LAN1 Static IPV6\n{1}\nreturncode: {2}\n{3}".format(API_id,API_LAN1_Static_cmd,status1,output1)
    CMM.save_data(main_log,message1,timestamp=False)
    temp_text1 = "[Node{0}] Set LAN1 Static IPV6".format(API_id)
    time.sleep(1)
    # Set LAN8 Static IP
    status8, output8 = CMM.retry_run_cmd(API_LAN8_Static_cmd)
    message8 = "API Node{0} LAN8 Static IPV6\n{1}\nreturncode: {2}\n{3}".format(API_id, API_LAN8_Static_cmd, status8,output8)
    CMM.save_data(main_log, message8, timestamp=False)
    temp_text8 = "[Node{0}] Set LAN8 Static IPV6".format(API_id)
    time.sleep(Convert_Wait_Time)
    temp_list = collect_ipv6_info()
    CMM.save_data(main_log, "[IPV6] Check LAN Static info\n{0}".format(temp_list), timestamp=False)
    if temp_list[0] != ["Static", set_LAN1_IP, set_LAN1_Gateway]:
        is_fail = True
        result_operation("FAIL", temp_text1)
        MAIN_LOG_list.append("[Node{0}] Set LAN1 Static:".format(API_id))
        MAIN_LOG_list.append("Set value: {0}".format(["Static", set_LAN1_IP, set_LAN1_Gateway]))
        MAIN_LOG_list.append("Get value: {0}".format(temp_list[0]))
    else:
        result_operation("PASS", temp_text1)
    time.sleep(0.5)
    if temp_list[1] != ["Static", set_LAN8_IP, set_LAN8_Gateway]:
        is_fail = True
        result_operation("FAIL", temp_text8)
        MAIN_LOG_list.append("[Node{0}] Set LAN8 Static:".format(API_id))
        MAIN_LOG_list.append("Set value: {0}".format(["Static", set_LAN8_IP, set_LAN8_Gateway]))
        MAIN_LOG_list.append("Get value: {0}".format(temp_list[1]))
    else:
        result_operation("PASS", temp_text8)
    time.sleep(1)
    # Restore LAN1|LAN8 DHCP IP, 只检测ipsrc是否变为DHCP
    status1,output1 = CMM.retry_run_cmd(API_LAN1_DHCP_cmd)
    message1 = "API Node{0} LAN1 DHCP IPV6\n{1}\nreturncode: {2}\n{3}".format(API_id,API_LAN1_DHCP_cmd,status1,output1)
    CMM.save_data(main_log,message1,timestamp=False)
    temp_text1 = "[Node{0}] Restore LAN1 DHCP IPV6".format(API_id)
    time.sleep(1)
    status8,output8 = CMM.retry_run_cmd(API_LAN8_DHCP_cmd)
    message8 = "API Node{0} LAN8 DHCP IPV6\n{1}\nreturncode: {2}\n{3}".format(API_id,API_LAN8_DHCP_cmd,status8,output8)
    CMM.save_data(main_log,message8,timestamp=False)
    temp_text8 = "[Node{0}] Restore LAN8 DHCP IPV6".format(API_id)
    time.sleep(Convert_Wait_Time)
    temp_list = collect_ipv6_info()
    CMM.save_data(main_log, "[IPV6] Check LAN DHCP info\n{0}".format(temp_list), timestamp=False)
    if temp_list[0][0] != "DHCP":
        is_fail = True
        result_operation("FAIL", temp_text1)
        MAIN_LOG_list.append("Restore LAN1 DHCP: {0}".format(temp_list[0]))
    else:
        result_operation("PASS", temp_text1)
    time.sleep(0.5)
    if temp_list[1][0] != "DHCP":
        is_fail = True
        result_operation("FAIL", temp_text8)
        MAIN_LOG_list.append("Restore LAN8 DHCP: {0}".format(temp_list[1]))
    else:
        result_operation("PASS", temp_text8)
    return False if is_fail else True

def stagger_node_power_via_API():
    restapi = "/api/cmminfo/stagger_node_power"
    poweron_cmd_API = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'offon':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, 1, IP, restapi)
    poweroff_cmd_API = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'offon':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, 0, IP, restapi)
    is_FAIL = False
    # Init node power: All node power on
    is_fail = False
    temp_text = "[Init] Set all node power on"
    status,output = CMM.retry_run_cmd(poweron_cmd_API)
    message = "[Init] Set all node power on\n{0}\nreturncode: {1}\n{2}".format(poweron_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    time.sleep(5)
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        power_state = check_node_PwrState(node_id).get("API_PwrState")
        message = "[Node{0}] Power state: {1}".format(node_id+1,power_state)
        CMM.show_message(message,timestamp=False)
        if power_state != "Power On":
            is_fail = True
        time.sleep(1)
    if is_fail:
        is_FAIL = True
        result_operation("FAIL",temp_text)
    else:
        result_operation("PASS",temp_text)
    # Set all node power off
    is_fail = False
    time.sleep(5)
    temp_text = "Set all node power off"
    status,output = CMM.retry_run_cmd(poweroff_cmd_API)
    message = "Set all node power off\n{0}\nreturncode: {1}\n{2}".format(poweroff_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    time.sleep(5)
    try:
        json_data = json.loads(output)
    except Exception as e:
        is_fail = True
        CMM.show_message("{0}".format(e),timestamp=False,color="red")
    else:
        if json_data.get("error"):
            is_fail = True
            CMM.show_message("{0}".format(output),timestamp=False,color="red")
            MAIN_LOG_list.append("{0}".format(output))
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        power_state = check_node_PwrState(node_id).get("API_PwrState")
        message = "[Node{0}] Power state: {1}".format(node_id+1,power_state)
        CMM.show_message(message,timestamp=False)
        if power_state != "Power Off":
            is_fail = True
        time.sleep(1)
    if is_fail:
        is_FAIL = True
        result_operation("FAIL",temp_text)
    else:
        result_operation("PASS",temp_text)
    # Set all node power on
    is_fail = False
    time.sleep(5)
    temp_text = "Set all node power on"
    status,output = CMM.retry_run_cmd(poweron_cmd_API)
    message = "Set all node power on\n{0}\nreturncode: {1}\n{2}".format(poweron_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    time.sleep(5)
    try:
        json_data = json.loads(output)
    except Exception as e:
        is_fail = True
        CMM.show_message("{0}".format(e),timestamp=False,color="red")
    else:
        if json_data.get("error"):
            is_fail = True
            CMM.show_message("{0}".format(output), timestamp=False, color="red")
            MAIN_LOG_list.append("{0}".format(output))
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        power_state = check_node_PwrState(node_id).get("API_PwrState")
        message = "[Node{0}] Power state: {1}".format(node_id+1,power_state)
        CMM.show_message(message,timestamp=False)
        if power_state != "Power On":
            is_fail = True
        time.sleep(1)
    if is_fail:
        is_FAIL = True
        result_operation("FAIL",temp_text)
    else:
        result_operation("PASS",temp_text)
    return False if is_FAIL else True

def thread_check_power_cycle(node_id,timeout):
    global Global_power_dict
    API_id = node_id + 1
    # Wait power off
    start_time = datetime.datetime.now()
    while True:
        end_time = datetime.datetime.now()
        if CMM.calc_time_interval(start_time, end_time) > timeout/2:
            LOCK.acquire()
            temp_text = "[Node{0} Power Cycle] Power Off exceeds {1}s".format(API_id, timeout/2)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log, temp_text, timestamp=False)
            Global_power_dict["node{0}_poweroff".format(API_id)] = "FAIL"
            LOCK.release()
            break
        temp_dict = check_node_PwrState(node_id)
        power_status = temp_dict.get("API_PwrState")
        if power_status == "Power Off":
            LOCK.acquire()
            Global_power_dict["node{0}_poweroff".format(API_id)] = "PASS"
            LOCK.release()
            break
    # Wait power on
    start_time = datetime.datetime.now()
    while True:
        end_time = datetime.datetime.now()
        if CMM.calc_time_interval(start_time, end_time) > timeout/2:
            LOCK.acquire()
            temp_text = "[Node{0} Power Cycle] Power On exceeds {1}s".format(API_id, timeout/2)
            MAIN_LOG_list.append(temp_text)
            CMM.save_data(main_log, temp_text, timestamp=False)
            Global_power_dict["node{0}_poweron".format(API_id)] = "FAIL"
            LOCK.release()
            break
        temp_dict = check_node_PwrState(node_id)
        power_status = temp_dict.get("API_PwrState")
        if power_status == "Power On":
            LOCK.acquire()
            Global_power_dict["node{0}_poweron".format(API_id)] = "PASS"
            LOCK.release()
            break

def set_all_node_power_via_API():
    restapi = "/api/cmminfo/setallnodepower"
    poweroff_cmd_API = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'cmd':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, 0, IP, restapi)
    poweron_cmd_API = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'cmd':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, 1, IP, restapi)
    powercycle_cmd_API = "curl -X POST -H \"Content-Type:application/json\" -H \"X-CSRFTOKEN:%s\" -d \"{'cmd':%s}\" http://%s%s -b cookie 2>/dev/null" % (CSRFToken, 2, IP, restapi)
    is_FAIL = False
    # Init node power: All node power on
    is_fail = False
    temp_text = "[Init] Set all node power on"
    status,output = CMM.retry_run_cmd(poweron_cmd_API)
    message = "[Init] Set all node power on\n{0}\nreturncode: {1}\n{2}".format(poweron_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    time.sleep(10)
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        power_state = check_node_PwrState(node_id).get("API_PwrState")
        message = "[Node{0}] Power state: {1}".format(node_id+1,power_state)
        CMM.show_message(message,timestamp=False)
        if power_state != "Power On":
            is_fail = True
        time.sleep(1)
    if is_fail:
        result_operation("FAIL",temp_text)
        is_FAIL = True
    else:
        result_operation("PASS",temp_text)
    # Set all node power off
    is_fail = False
    time.sleep(5)
    temp_text = "Set all node power off"
    status,output = CMM.retry_run_cmd(poweroff_cmd_API)
    message = "Set all node power off\n{0}\nreturncode: {1}\n{2}".format(poweroff_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    time.sleep(10)
    try:
        json_data = json.loads(output)
    except Exception as e:
        is_fail = True
        CMM.show_message("{0}".format(e),timestamp=False,color="red")
    else:
        if json_data.get("error"):
            is_fail = True
            CMM.show_message("{0}".format(output),timestamp=False,color="red")
            MAIN_LOG_list.append("{0}".format(output))
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        power_state = check_node_PwrState(node_id).get("API_PwrState")
        message = "[Node{0}] Power state: {1}".format(node_id+1,power_state)
        CMM.show_message(message,timestamp=False)
        if power_state != "Power Off":
            is_fail = True
        time.sleep(1)
    if is_fail:
        result_operation("FAIL",temp_text)
        is_FAIL = True
    else:
        result_operation("PASS",temp_text)
    # Set all node power on
    is_fail = False
    time.sleep(5)
    temp_text = "Set all node power on"
    status,output = CMM.retry_run_cmd(poweron_cmd_API)
    message = "Set all node power on\n{0}\nreturncode: {1}\n{2}".format(poweron_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    time.sleep(10)
    try:
        json_data = json.loads(output)
    except Exception as e:
        is_fail = True
        CMM.show_message("{0}".format(e),timestamp=False,color="red")
    else:
        if json_data.get("error"):
            is_fail = True
            CMM.show_message("{0}".format(output), timestamp=False, color="red")
            MAIN_LOG_list.append("{0}".format(output))
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        power_state = check_node_PwrState(node_id).get("API_PwrState")
        message = "[Node{0}] Power state: {1}".format(node_id+1,power_state)
        CMM.show_message(message,timestamp=False)
        if power_state != "Power On":
            is_fail = True
        time.sleep(1)
    if is_fail:
        result_operation("FAIL",temp_text)
        is_FAIL = True
    else:
        result_operation("PASS",temp_text)
    # Set all node power cycle
    is_fail = False
    timeout = 30 * NODE_NUM
    time.sleep(5)
    temp_text = "Set all node power cycle"
    status,output = CMM.retry_run_cmd(powercycle_cmd_API)
    message = "Set all node power cycle\n{0}\nreturncode: {1}\n{2}".format(powercycle_cmd_API, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    threads = []
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        t = threading.Thread(target=thread_check_power_cycle,args=(node_id,timeout))
        threads.append(t)
        t.setDaemon(True)
        t.start()
    for t in threads:
        t.join(timeout)
    for node_id in range(NODE_NUM):
        if node_id not in Present_Node:
            continue
        API_id = node_id + 1
        temp_key = "node{0}_poweroff".format(API_id)
        if Global_power_dict.get(temp_key) == "PASS":
            result_operation("PASS", temp_key)
        else:
            is_fail = True
            result_operation("FAIL", temp_key)
        temp_key = "node{0}_poweron".format(API_id)
        if Global_power_dict.get(temp_key) == "PASS":
            result_operation("PASS", temp_key)
        else:
            is_fail = True
            result_operation("FAIL", temp_key)
    if is_fail:
        result_operation("FAIL",temp_text)
        is_FAIL = True
    else:
        result_operation("PASS",temp_text)
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

    def c_check_node_Present(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node Present -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            message = "[Node{0}] Check node Present".format(node_id+1)
            present_dict = check_node_Present(node_id)
            status = compare_node_Present(present_dict,node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def d_check_node_PwrState(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node PwrState -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Check node PwrState".format(int(node_id)+1)
            pwrstate_dict = check_node_PwrState(node_id)
            status = compare_node_PwrState(pwrstate_dict,node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def e_check_node_UID(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node UID -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Check node UID".format(int(node_id)+1)
            uid_dict = check_node_UID(node_id)
            status = compare_node_UID(uid_dict,node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def f_check_node_PwrConsumption(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node PwrConsumption -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Check node PwrConsumption".format(int(node_id)+1)
            pwrconsumption_dict = check_node_PwrConsumption(node_id)
            status = compare_node_PwrConsumption(pwrconsumption_dict,node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def g_check_node_LAN(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node LAN -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            CMM.show_message("Node {0}".format(int(node_id) + 1), timestamp=False, color="blue")
            temp_data = check_node_LAN(node_id)
            temp_oem_dict = temp_data["OEM_LAN"]["LAN1"]
            temp_api_dict = temp_data["API_LAN"]["LAN1"]
            LAN1_status = compare_node_LAN(temp_oem_dict,temp_api_dict,"LAN1",node_id)
            temp_oem_dict = temp_data["OEM_LAN"]["LAN8"]
            temp_api_dict = temp_data["API_LAN"]["LAN8"]
            LAN8_status = compare_node_LAN(temp_oem_dict,temp_api_dict,"LAN8",node_id)
            message = "[Node{0}] Check node LAN".format(int(node_id)+1)
            if not LAN1_status or not LAN8_status:
                CASE_PASS = False
                CMM.save_step_result(main_log,message,flag="FAIL")
                show_step_result(message,"FAIL")
            else:
                CMM.save_step_result(main_log,message,flag="PASS")
                show_step_result(message,"PASS")

    def h_check_node_FW(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node FW -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Check node FW".format(node_id+1)
            FW_dict = check_node_FW(node_id)
            status = compare_node_FW(FW_dict,node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def i_check_node_FRU(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Check node FRU -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Check node FRU".format(node_id+1)
            temp_data = check_node_FRU(node_id)
            OEM_dict = temp_data.get("OEM_FRU")
            API_dict = temp_data.get("API_FRU")
            status = compare_node_FRU(OEM_dict,API_dict,node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def j_save_node_info(self):
        CMM.save_data(MAIN_LOG,"OEM_NODE_INFO:{0}".format(OEM_data),timestamp=False)
        CMM.save_data(MAIN_LOG,"API_NODE_INFO:{0}".format(API_data),timestamp=False)

    # def k_check_node_num_via_API(self):
    #     if LOGIN_FAIL:
    #         return False
    #     global CASE_PASS
    #     temp_text = "- Check node number via API -"
    #     CMM.show_message(format_item(temp_text),color="green",timestamp=False)
    #     CMM.save_data(main_log,temp_text,timestamp=False)
    #     MAIN_LOG_list.append(temp_text)
    #     status = check_node_num_via_API()
    #     message = temp_text.strip("- ")
    #     if status:
    #         show_step_result(message, flag="PASS")
    #         CMM.save_step_result(main_log, message, flag="PASS")
    #     else:
    #         CASE_PASS = False
    #         show_step_result(message, flag="FAIL")
    #         CMM.save_step_result(main_log, message, flag="FAIL")

    def o_set_node_uid_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set node UID LED via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Set node UID LED".format(node_id+1)
            status = set_node_uid_via_API(node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    # 放在Node测试的最后一步
    def w_set_node_power_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set node power state via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Set node power state".format(node_id + 1)
            status = set_node_power_via_API(node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)
    
    def q_set_node_ipv4_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set node ipv4 Static IP via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Set node ipv4 Static IP".format(node_id+1)
            status = set_node_ipv4_via_API(node_id)
            if status:
                show_step_result(message,flag="PASS")
                CMM.save_step_result(main_log,message,flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message,flag="FAIL")
                CMM.save_step_result(main_log,message,flag="FAIL")
            time.sleep(1)

    def r_set_node_ipv6_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set node ipv6 Static IP via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        for node_id in range(NODE_NUM):
            if node_id not in Present_Node:
                continue
            message = "[Node{0}] Set node ipv6 Static IP".format(node_id + 1)
            status = set_node_ipv6_via_API(node_id)
            if status:
                show_step_result(message, flag="PASS")
                CMM.save_step_result(main_log, message, flag="PASS")
            else:
                CASE_PASS = False
                show_step_result(message, flag="FAIL")
                CMM.save_step_result(main_log, message, flag="FAIL")
            time.sleep(1)

    def s_stagger_node_power_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Stagger node power via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        status = stagger_node_power_via_API()
        if status:
            show_step_result(message, flag="PASS")
            CMM.save_step_result(main_log, message, flag="PASS")
        else:
            CASE_PASS = False
            show_step_result(message, flag="FAIL")
            CMM.save_step_result(main_log, message, flag="FAIL")

    def t_set_all_node_power_via_API(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        temp_text = "- Set all node power via API -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        status = set_all_node_power_via_API()
        temp = json.dumps(Global_power_dict,indent=4)
        print(temp)
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