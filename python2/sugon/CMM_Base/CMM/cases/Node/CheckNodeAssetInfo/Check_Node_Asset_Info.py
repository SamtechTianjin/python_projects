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
from libs.vendorList import vendorList as Vendor_DICT
from libs.pcieDeviceClassList import pcieDeviceClassList as PCIE_Device_Class_DICT
from libs.dimmInfoDict import DIMM_INFO_DICT as DIMM_INFO_DICT
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

def getNodeAssetCpusViaAPI(node_id):
    API_id = node_id + 1
    data = []
    restapi = "/api/noderepo/cpus"
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'nodeid':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[Node{0}] Get cpu asset info\n{1}\nreturncode: {2}\n{3}".format(API_id,cmd,status,output)
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

def getNodeAssetMemViaAPI(node_id):
    API_id = node_id + 1
    data = []
    restapi = "/api/noderepo/mems"
    cmd = "curl -X POST -H \"X-CSRFTOKEN:%s\" -H \"Content-Type:application/json\" -d \"{'nodeid':%s}\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,API_id,IP,restapi)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[Node{0}] Get mem asset info\n{1}\nreturncode: {2}\n{3}".format(API_id,cmd,status,output)
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

def getNodeAssetCpusViaOEM(node_id):
    API_id = node_id + 1
    OEM_id = node_id
    data = []
    for index in range(CPU_NUM):
        cmd = "{0} {1} {2} 0x0e 0x02 {3}".format(IPMITOOL,SINGLE_NODE_OEM,hex(OEM_id),index)
        status, output = CMM.retry_run_cmd(cmd)
        message = "OEM Node{0} CPU{4}\n{1}\nreturncode: {2}\n{3}".format(API_id,cmd,status,output,index+1)
        CMM.save_data(main_log, message, timestamp=False)
        if status == 0:
            temp_list = output.split()
        else:
            temp_list = []
        data.append(temp_list)
    return data

def getNodeAssetPcieViaOEM(node_id,index):
    API_id = node_id + 1
    OEM_id = node_id
    cmd = "{0} {1} {2} 0x0e 0x09 {3}".format(IPMITOOL, SINGLE_NODE_OEM, hex(OEM_id), index)
    status, output = CMM.retry_run_cmd(cmd)
    message = "OEM Node{0} PCIE{4}\n{1}\nreturncode: {2}\n{3}".format(API_id, cmd, status, output, index + 1)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        temp_list = output.split()
    else:
        temp_list = []
    return temp_list

def getNodeAssetMemViaOEM(node_id):
    API_id = node_id + 1
    OEM_id = node_id
    data = []
    for cpu_index in range(CPU_NUM):
        for channel_index in range(CHANNEL_NUM):
            for dimm_index in range(DIMM_NUM_PER_CHANNEL):
                cmd = "{0} {1} {2} 0x0e 0x03 {3} {4} {5}".format(IPMITOOL,SINGLE_NODE_OEM,hex(OEM_id),hex(cpu_index),hex(channel_index),hex(dimm_index))
                status, output = CMM.retry_run_cmd(cmd)
                message = "OEM Node{0} cpu{1} channel{2} dimm{3}\n{4}\nreturncode: {5}\n{6}".format(API_id,cpu_index,channel_index,dimm_index,cmd,status,output)
                CMM.save_data(main_log, message, timestamp=False)
                if status == 0:
                    temp_list = output.split()
                else:
                    temp_list = []
                data.append(temp_list)
    return data

""" 处理OEM command获得CPU资产信息 """
def parseCPUNodeId(temp_list):
    try:
        temp = temp_list[0]
        API_id = int(temp,16)+1
    except:
        API_id = "Unknown"
    return API_id

def parseCPUBIOSSetFlags(temp_list):
    try:
        temp = temp_list[1]
        if temp == "00":
            flag = False
        elif temp == "01":
            flag = True
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parseCPUPresent(temp_list):
    try:
        temp = temp_list[2]
        flag = int(temp,16)
    except:
        flag = "Unknown"
    return flag

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

def parseCPUSocketRiserType(temp_list):
    data = []
    try:
        for temp in temp_list[17:20]:
            if temp == "00":
                t = "4+4+4+4"
            elif temp == "01":
                t = "4+4+8"
            elif temp == "02":
                t = "8+4+4"
            elif temp == "03":
                t = "8+8"
            elif temp == "04":
                t = "16"
            elif temp == "05":
                t = "4+8+4"
            else:
                t = ""
            data.append(t)
    except:
        data = ["Unknown"]*3
    return data

def parseCPUBrandName(temp_list):
    data = ""
    try:
        for temp in temp_list[23:87]:
            if temp == "00":
                break
            string = chr(int(temp, 16))
            data += string
    except:
        data = "Unknown"
    return data

def parseCPUUPIFreq(temp_list):
    data = []
    try:
        for temp in temp_list[87:90]:
            if temp == "01":
                Freq = "6.4GT/s"
            elif temp == "02":
                Freq = "7.2GT/s"
            elif temp == "03":
                Freq = "8.0GT/s"
            elif temp == "04":
                Freq = "9.6GT/s"
            elif temp == "05":
                Freq = "10.4GT/s"
            else:
                Freq = ""
            data.append(Freq)
    except:
        data = ["Unknown"]*3
    return data

def parseCPUUPIWidth(temp_list):
    data = []
    try:
        for temp in [temp_list[90],temp_list[91],temp_list[92]]:
            if temp == "00":
                # width = "unknown"
                width = ""
            elif temp == "01":
                width = "Q3Q2Q1Q0"
            elif temp == "02":
                width = "Q1Q0"
            elif temp == "07":
                width = "Q3Q2"
            else:
                width = ""
            data.append(width)
    except:
        data = ["Unknown"] * 3
    return data

""" 处理OEM command获得PCIE资产信息 """
def parsePCIENodeId(temp_list):
    try:
        temp = temp_list[0]
        API_id = int(temp,16)+1
    except:
        API_id = "Unknown"
    return API_id

def parsePCIEBIOSSetFlags(temp_list):
    try:
        temp = temp_list[1]
        if temp == "00":
            flag = False
        elif temp == "01":
            flag = True
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parsePCIEPresent(temp_list):
    try:
        temp = temp_list[2]
        flag = int(temp,16)
    except:
        flag = "Unknown"
    return flag

def parsePCIECPUNo(temp_list):
    try:
        CPUNo = "CPU{0}".format(int(temp_list[3],16))
    except:
        CPUNo = "Unknown"
    return CPUNo

def parsePCIELocation(temp_list):
    data = ""
    try:
        for temp in temp_list[4:20]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parsePCIEParentBusDeviceFunction(temp_list):
    try:
        bdf = temp_list[21:24]
    except:
        bdf = ["Unknown"]*3
    return bdf

def parsePCIEBusDeviceFunction(temp_list):
    try:
        bdf = temp_list[24:27]
    except:
        bdf = ["Unknown"]*3
    return bdf

def parsePCIECurSpeed(temp_list):
    try:
        temp = temp_list[38]
        if temp == "00":
            CurSpeed = "unknown"
        elif temp == "01":
            CurSpeed = "2.5GT/s"
        elif temp == "02":
            CurSpeed = "5.0GT/s"
        elif temp == "03":
            CurSpeed = "8.0GT/s"
        else:
            CurSpeed = ""
    except:
        CurSpeed = "Unknown"
    return CurSpeed

def parsePCIENegoLinkWidth(temp_list):
    try:
        temp = temp_list[39]
        if temp == "00":
            NegoLinkWidth = "unknown"
        elif temp == "01":
            NegoLinkWidth = "x1"
        elif temp == "02":
            NegoLinkWidth = "x2"
        elif temp == "04":
            NegoLinkWidth = "x4"
        elif temp == "08":
            NegoLinkWidth = "x8"
        elif temp == "10":
            NegoLinkWidth = "x16"
        else:
            NegoLinkWidth = ""
    except:
        NegoLinkWidth = "Unknown"
    return NegoLinkWidth

def parsePCIEBrandName(temp_list):
    data = ""
    try:
        for temp in temp_list[40:]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parsePCIEClass(temp_list):
    try:
        baseClass = temp_list[31]
        subClass = temp_list[32]
        if baseClass in PCIE_Device_Class_DICT:
            if baseClass == "0e":
                data = PCIE_Device_Class_DICT.get("0e")
            else:
                data = PCIE_Device_Class_DICT[baseClass].get(subClass,PCIE_Device_Class_DICT[baseClass].get("other"))
        else:
            data = PCIE_Device_Class_DICT.get("other")
    except:
        data = "Unknown"
    return data

def parsePCIEVendor(temp_list):
    try:
        temp1 = temp_list[28].upper() if re.search(r'[a-z]',temp_list[28]) else temp_list[28]
        temp2 = temp_list[27].upper() if re.search(r'[a-z]',temp_list[27]) else temp_list[27]
        temp = "0x{0}{1}".format(temp1,temp2)
        data = Vendor_DICT.get(temp,"Unknown")
    except:
        data = "Unknown"
    return data

""" 处理OEM command获得DIMM资产信息 """
def parseMEMNodeId(temp_list):
    try:
        temp = temp_list[0]
        API_id = int(temp,16)+1
    except:
        API_id = "Unknown"
    return API_id

def parseMEMBIOSSetFlags(temp_list):
    try:
        temp = temp_list[1]
        if temp == "00":
            flag = False
        elif temp == "01":
            flag = True
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parseMEMPresent(temp_list):
    try:
        temp = temp_list[2]
        flag = int(temp,16)
    except:
        flag = "Unknown"
    return flag

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

def parseMEMSerialNumber(temp_list):
    try:
        string = ""
        for temp in temp_list[82:90]:
            if temp == "00":
                break
            string += temp
        data = string.upper()
    except:
        data = "Unknown"
    return data

def parseMEMDimmType(temp_list):
    try:
        temp = temp_list[27]
        if temp == "00":
            flag = ""
        elif temp == "01":
            flag = "DDR"
        elif temp == "02":
            flag = "DDR2"
        elif temp == "03":
            flag = "DDR3"
        elif temp == "04":
            flag = "DDR4"
        elif temp == "05":
            flag = "DDR-T"
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parseMEMWorkFreq(temp_list):
    try:
        dimmType = parseMEMDimmType(temp_list)
        temp = temp_list[30]
        index = int(temp,16)
        if dimmType == "DDR3" or dimmType == "DDR4":
            flag = DIMM_INFO_DICT[str(index)][dimmType]
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parseMEMPartNumber(temp_list):
    data = ""
    try:
        for temp in temp_list[50:82]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parseMEMType(temp_list):
    try:
        temp = temp_list[28]
        if temp == "01":
            flag = "VOLATILE"
        elif temp == "02":
            flag = "AEP"
        elif temp == "03":
            flag = "NVDIMM"
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parseMEMManufacture(temp_list):
    data = ""
    try:
        for temp in temp_list[34:50]:
            if temp == "00":
                break
            string = chr(int(temp,16))
            data += string
    except:
        data = "Unknown"
    return data

def parseMEMFrequency(temp_list):
    try:
        dimmType = parseMEMDimmType(temp_list)
        temp = temp_list[29]
        index = int(temp,16)
        if dimmType == "DDR3" or dimmType == "DDR4":
            flag = DIMM_INFO_DICT[str(index)][dimmType]
        else:
            flag = ""
    except:
        flag = "Unknown"
    return flag

def parseMEMSize(temp_list):
    try:
        unit_temp = temp_list[31]
        size_temp1 = temp_list[32]
        size_temp2 = temp_list[33]
        if unit_temp == "01":
            unit = "MB"
        elif unit_temp == "02":
            unit = "GB"
        elif unit_temp == "03":
            unit = "TB"
        else:
            unit = ""
        size = int(size_temp2,16)*256 + int(size_temp1,16)
        data = "{0} {1}".format(size,unit)
        if data.strip() == "0":
            data = ""
    except:
        data = "Unknown"
    return data





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

    def d_check_cpu_asset(self):
        global CASE_PASS
        global NODE_INFO_DICT
        if LOGIN_FAIL:
            return False
        is_FAIL = False
        temp_text = "- Check cpu asset info -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        compare_list = ["cpuPresent","Location","BrandName","UPIFreq","UPIWidth"]
        for node_id in range(NODE_NUM):
            is_fail = False
            if int(node_id+1) not in Present_Node:
                continue
            data = getNodeAssetCpusViaAPI(node_id)
            if data == False:
                is_fail = True
            elif int(node_id+1) in Present_Node and not data:
                is_fail = True
                text = "[Node{0}] API CPU data is null !".format(node_id+1)
                MAIN_LOG_list.append(text)
                CMM.show_message(text,timestamp=False,color="red")
                CMM.save_data(main_log,text,timestamp=False)
            API_temp = [] if data == False else data
            NODE_INFO_DICT["Node{0}".format(node_id + 1)]["CPU"] = API_temp
            OEM_data = getNodeAssetCpusViaOEM(node_id)
            if len(API_temp) == len(OEM_data):
                for index,temp_list in enumerate(OEM_data):
                    cpuid = index+1
                    for temp_dict in API_temp:
                        if temp_dict.get("cpuid") == cpuid:
                            API_cpuPresent,API_Location,API_BrandName,API_UPIFreq,API_UPIWidth = \
                                [temp_dict.get(k,None) for k in compare_list]
                            OEM_cpuPresent = parseCPUPresent(temp_list)
                            OEM_Location = parseCPULocation(temp_list)
                            OEM_BrandName = parseCPUBrandName(temp_list)
                            OEM_UPIFreq = parseCPUUPIFreq(temp_list)
                            OEM_UPIWidth = parseCPUUPIWidth(temp_list)
                            if OEM_cpuPresent != API_cpuPresent:
                                is_fail = True
                                text = "[Node{0}] API CPU{1} cpuPresent: {2}".format(int(node_id+1),cpuid,API_cpuPresent)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM CPU{1} cpuPresent: {2}".format(int(node_id+1),cpuid,OEM_cpuPresent)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif OEM_Location != API_Location:
                                is_fail = True
                                text = "[Node{0}] API CPU{1} Location: {2}".format(int(node_id+1),cpuid, API_Location)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM CPU{1} Location: {2}".format(int(node_id+1),cpuid, OEM_Location)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif OEM_BrandName != API_BrandName:
                                is_fail = True
                                text = "[Node{0}] API CPU{1} BrandName: {2}".format(int(node_id+1),cpuid, API_BrandName)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM CPU{1} BrandName: {2}".format(int(node_id+1),cpuid, OEM_BrandName)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif OEM_UPIFreq != [API_UPIFreq]*3:
                                is_fail = True
                                text = "[Node{0}] API CPU{1} UPIFreq: {2}".format(int(node_id+1),cpuid, API_UPIFreq)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM CPU{1} UPIFreq: {2}".format(int(node_id+1),cpuid, OEM_UPIFreq)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif "/".join(OEM_UPIWidth) != API_UPIWidth:
                                is_fail = True
                                text = "[Node{0}] API CPU{1} UPIWidth: {2}".format(int(node_id+1),cpuid, API_UPIWidth)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM CPU{1} UPIWidth: {2}".format(int(node_id+1),cpuid, OEM_UPIWidth)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            break
                    else:
                        is_fail = True
                        text = "[Node{0} CPU{1} API] Not found data !".format(int(node_id+1),cpuid)
                        CMM.show_message(text,timestamp=False,color="red")
                        CMM.save_data(main_log,text,timestamp=False)
                        MAIN_LOG_list.append(text)
            else:
                is_fail =True
                text = "[Node{0}] Not match cpu number !".format(node_id+1)
                CMM.show_message(text, timestamp=False, color="red")
                CMM.save_data(main_log, text, timestamp=False)
                MAIN_LOG_list.append(text)
            text = "[Node{0}] Check cpu asset info".format(node_id+1)
            if is_fail:
                is_FAIL = True
                CMM.save_step_result(main_log,text,"FAIL")
                show_step_result(text,"FAIL")
            else:
                CMM.save_step_result(main_log,text,"PASS")
                show_step_result(text,"PASS")
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def f_check_pcie_asset(self):
        global CASE_PASS
        if LOGIN_FAIL:
            return False
        is_FAIL = False
        temp_text = "- Check pcie asset info -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        compare_list = ["pciePresent","BrandName","Class","Vendor","Location","NegoLinkWidth","CurSpeed","pcieid"]
        for node_id in range(NODE_NUM):
            is_fail = False
            if int(node_id+1) not in Present_Node:
                continue
            data = getNodeAssetPcieViaAPI(node_id)
            API_temp = [] if data == False else data
            NODE_INFO_DICT["Node{0}".format(node_id + 1)]["PCIE"] = API_temp
            if data == False:
                is_fail = True
            elif len(data) == 0:
                pass
            else:
                for API_dict in data:
                    API_pciePresent,API_BrandName,API_Class,API_Vendor,API_Location,API_NegoLinkWidth,\
                    API_CurSpeed,API_pcieid = [API_dict.get(k) for k in compare_list]
                    temp_list = getNodeAssetPcieViaOEM(node_id,API_pcieid-1)
                    OEM_pciePresent = parsePCIEPresent(temp_list)
                    OEM_BrandName = parsePCIEBrandName(temp_list)
                    OEM_Class = parsePCIEClass(temp_list)
                    OEM_Vendor = parsePCIEVendor(temp_list)
                    OEM_Location = parsePCIELocation(temp_list)
                    OEM_NegoLinkWidth = parsePCIENegoLinkWidth(temp_list)
                    OEM_CurSpeed = parsePCIECurSpeed(temp_list)
                    if OEM_pciePresent != API_pciePresent:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} pciePresent: {2}".format(int(node_id + 1), API_pcieid, API_pciePresent)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} pciePresent: {2}".format(int(node_id + 1), API_pcieid, OEM_pciePresent)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_BrandName != API_BrandName:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} BrandName: {2}".format(int(node_id + 1), API_pcieid, API_BrandName)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} BrandName: {2}".format(int(node_id + 1), API_pcieid, OEM_BrandName)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_Class != API_Class:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} Class: {2}".format(int(node_id + 1), API_pcieid, API_Class)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} Class: {2}".format(int(node_id + 1), API_pcieid, OEM_Class)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_Vendor != API_Vendor:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} Vendor: {2}".format(int(node_id + 1), API_pcieid, API_Vendor)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} Vendor: {2}".format(int(node_id + 1), API_pcieid, OEM_Vendor)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_Location != API_Location:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} Location: {2}".format(int(node_id + 1), API_pcieid, API_Location)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} Location: {2}".format(int(node_id + 1), API_pcieid, OEM_Location)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_NegoLinkWidth != API_NegoLinkWidth:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} NegoLinkWidth: {2}".format(int(node_id + 1), API_pcieid, API_NegoLinkWidth)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} NegoLinkWidth: {2}".format(int(node_id + 1), API_pcieid, OEM_NegoLinkWidth)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                    elif OEM_CurSpeed != API_CurSpeed:
                        is_fail = True
                        text = "[Node{0}] API PCIE{1} CurSpeed: {2}".format(int(node_id + 1), API_pcieid, API_CurSpeed)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
                        text = "[Node{0}] OEM PCIE{1} CurSpeed: {2}".format(int(node_id + 1), API_pcieid, OEM_CurSpeed)
                        CMM.show_message(text, timestamp=False, color="red")
                        MAIN_LOG_list.append(text)
            text = "[Node{0}] Check pcie asset info".format(node_id+1)
            if is_fail:
                is_FAIL = True
                CMM.save_step_result(main_log,text,"FAIL")
                show_step_result(text,"FAIL")
            else:
                CMM.save_step_result(main_log,text,"PASS")
                show_step_result(text,"PASS")
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def g_check_mem_asset(self):
        global CASE_PASS
        global NODE_INFO_DICT
        if LOGIN_FAIL:
            return False
        is_FAIL = False
        temp_text = "- Check mem asset info -"
        CMM.show_message(format_item(temp_text),color="green",timestamp=False)
        CMM.save_data(main_log,temp_text,timestamp=False)
        MAIN_LOG_list.append(temp_text)
        message = temp_text.strip(" -")
        compare_list = ["SerialNumber","memPresent","DimmType","nodeid","WorkFreq","Location",
                        "PartNumber","Type","Manufacture","Frequency","Size"]
        for node_id in range(NODE_NUM):
            is_fail = False
            if int(node_id+1) not in Present_Node:
                continue
            data = getNodeAssetMemViaAPI(node_id)
            if data == False:
                is_fail = True
            elif int(node_id+1) in Present_Node and not data:
                is_fail = True
                text = "[Node{0}] API Mem data is null !".format(node_id+1)
                MAIN_LOG_list.append(text)
                CMM.show_message(text,timestamp=False,color="red")
                CMM.save_data(main_log,text,timestamp=False)
            API_temp = [] if data == False else data
            NODE_INFO_DICT["Node{0}".format(node_id + 1)]["MEM"] = API_temp
            OEM_data = getNodeAssetMemViaOEM(node_id)
            if len(API_temp) == len(OEM_data):
                for index,temp_list in enumerate(OEM_data):
                    memid = index+1
                    for temp_dict in API_temp:
                        if temp_dict.get("memid") == memid:
                            API_SerialNumber,API_memPresent,API_DimmType,API_nodeid,API_WorkFreq,\
                            API_Location,API_PartNumber,API_Type,API_Manufacture,API_Frequency,API_Size = \
                                [temp_dict.get(k,None) for k in compare_list]
                            print("="*50)
                            OEM_SerialNumber = parseMEMSerialNumber(temp_list)
                            print("SN:",OEM_SerialNumber)
                            OEM_memPresent = parseMEMPresent(temp_list)
                            print("Present:",OEM_memPresent)
                            OEM_DimmType = parseMEMDimmType(temp_list)
                            print("DimmType:",OEM_DimmType)
                            OEM_nodeid = parseMEMNodeId(temp_list)
                            print("nodeid:",OEM_nodeid)
                            OEM_WorkFreq = parseMEMWorkFreq(temp_list)
                            print("WorkFreq:",OEM_WorkFreq)
                            OEM_Location = parseMEMLocation(temp_list)
                            print("Location:",OEM_Location)
                            OEM_PartNumber = parseMEMPartNumber(temp_list)
                            print("PN:",OEM_PartNumber)
                            OEM_Type = parseMEMType(temp_list)
                            print("TYPE:",OEM_Type)
                            OEM_Manufacture = parseMEMManufacture(temp_list)
                            print("Manufacture:",OEM_Manufacture)
                            OEM_Frequency = parseMEMFrequency(temp_list)
                            print("Frequence:",OEM_Frequency)
                            OEM_Size = parseMEMSize(temp_list)
                            print("Size:",OEM_Size)
                            if API_SerialNumber != OEM_SerialNumber:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} SerialNumber: {2}".format(int(node_id+1),memid,API_SerialNumber)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} SerialNumber: {2}".format(int(node_id+1),memid,OEM_SerialNumber)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif API_memPresent != OEM_memPresent:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} memPresent: {2}".format(int(node_id+1),memid,API_memPresent)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} memPresent: {2}".format(int(node_id+1),memid,OEM_memPresent)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif API_DimmType != OEM_DimmType:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} DimmType: {2}".format(int(node_id+1),memid,API_DimmType)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} DimmType: {2}".format(int(node_id+1),memid,OEM_DimmType)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif API_nodeid != OEM_nodeid:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} nodeid: {2}".format(int(node_id+1),memid,API_nodeid)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} nodeid: {2}".format(int(node_id+1),memid,OEM_nodeid)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif API_WorkFreq != OEM_WorkFreq:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} WorkFreq: {2}".format(int(node_id+1),memid,API_WorkFreq)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} WorkFreq: {2}".format(int(node_id+1),memid,OEM_WorkFreq)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif API_Location != OEM_Location:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} Location: {2}".format(int(node_id+1),memid,API_Location)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} Location: {2}".format(int(node_id+1),memid,OEM_Location)
                                CMM.show_message(text,timestamp=False,color="red")
                                MAIN_LOG_list.append(text)
                            elif API_PartNumber != OEM_PartNumber:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} PartNumber: {2}".format(int(node_id + 1), memid,API_PartNumber)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} PartNumber: {2}".format(int(node_id + 1), memid,OEM_PartNumber)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif API_Type != OEM_Type:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} Type: {2}".format(int(node_id + 1), memid,API_Type)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} Type: {2}".format(int(node_id + 1), memid,OEM_Type)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif API_Manufacture != OEM_Manufacture:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} Manufacture: {2}".format(int(node_id + 1), memid,API_Manufacture)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} Manufacture: {2}".format(int(node_id + 1), memid,OEM_Manufacture)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif API_Frequency != OEM_Frequency:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} Frequency: {2}".format(int(node_id + 1), memid,API_Frequency)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} Frequency: {2}".format(int(node_id + 1), memid,OEM_Frequency)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            elif API_Size != OEM_Size:
                                is_fail = True
                                text = "[Node{0}] API MEM{1} Size: {2}".format(int(node_id + 1), memid,API_Size)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                                text = "[Node{0}] OEM MEM{1} Size: {2}".format(int(node_id + 1), memid,OEM_Size)
                                CMM.show_message(text, timestamp=False, color="red")
                                MAIN_LOG_list.append(text)
                            break
                    else:
                        is_fail = True
                        text = "[Node{0} MEM{1} API] Not found data !".format(int(node_id + 1), memid)
                        CMM.show_message(text, timestamp=False, color="red")
                        CMM.save_data(main_log, text, timestamp=False)
                        MAIN_LOG_list.append(text)
            else:
                is_fail =True
                text = "[Node{0}] Not match MEM number !".format(node_id+1)
                CMM.show_message(text, timestamp=False, color="red")
                CMM.save_data(main_log, text, timestamp=False)
                MAIN_LOG_list.append(text)
            text = "[Node{0}] Check mem asset info".format(node_id+1)
            if is_fail:
                is_FAIL = True
                CMM.save_step_result(main_log,text,"FAIL")
                show_step_result(text,"FAIL")
            else:
                CMM.save_step_result(main_log,text,"PASS")
                show_step_result(text,"PASS")
        if is_FAIL:
            CASE_PASS = False
            show_step_result(message,"FAIL")
            CMM.save_step_result(main_log,message,"FAIL")
        else:
            show_step_result(message,"PASS")
            CMM.save_step_result(main_log,message,"PASS")

    def x_print_node_asset_info(self):
        if LOGIN_FAIL:
            return False
        temp_text = "- Print node asset info -"
        CMM.show_message(format_item(temp_text), color="green", timestamp=False)
        CMM.save_data(main_log, temp_text, timestamp=False)
        CMM.save_data(MAIN_LOG,"Node_Asset_INFO: {0}".format(NODE_INFO_DICT),timestamp=False)
        data = json.dumps(NODE_INFO_DICT,indent=4)
        print(data)
        CMM.save_data(main_log,data,timestamp=False)

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