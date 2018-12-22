# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time
import json
import re
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

# Global variable
LOGIN_FAIL = False
CSRFToken = ""
GET_FRU_API = "/api/cmminfo/fru/"
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

"""
API接口返回值
[ { "device": { "id": 0, "name": "CMM_FRU" }, "common_header": { "version": 1, "internal_use_area_start_offset": 1, "chassis_info_area_start_offset": 2, "board_info_area_start_offset": 7, "product_info_area_start_offset": 14, "multi_record_area_start_offset": 0 }, "chassis": { "version": 1, "length": 5, "type": "Unspecified", "part_number": "00000000", "serial_number": "6100381500539262", "custom_fields": "AM0" }, "board": { "version": 1, "length": 7, "language": 0, "date": "Thu Nov  1 23:17:00 2018", "manufacturer": "Sugon", "product_name": "TC4600", "serial_number": "1612345678987654", "part_number": "80000123", "fru_file_id": "1", "custom_fields": "AM1" }, "product": { "version": 1, "length": 8, "language": 0, "manufacturer": "Sugon", "product_name": "TC4600", "part_number": "88888888", "product_version": "0123", "serial_number": "1601010101010101", "asset_tag": "00001", "fru_file_id": "2", "custom_fields": "AM2" } } ]
"""



def getCMMFruInfoViaAPI():
    is_fail = False
    fru_info = {}
    cmd = "curl -X GET -H \"X-CSRFTOKEN:%s\" http://%s%s -b cookie 2>/dev/null" %(CSRFToken,IP,GET_FRU_API)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[API] Get FRU info\n{0}\nreturncode: {1}\n{2}".format(cmd,status,output)
    CMM.save_data(main_log,message,timestamp=False)
    if status == 0:
        try:
            json_data = json.loads(output)
        except Exception as e:
            is_fail = True
            message = "[Exception] {0}".format(e)
            MAIN_LOG_list.append(message)
            CMM.show_message(message,timestamp=False,color="red")
            CMM.save_data(main_log,message,timestamp=False)
        else:
            if isinstance(json_data,dict):
                if json_data.get("error"):
                    is_fail = True
            else:
                fru_info = json_data
                CMM.save_data(MAIN_LOG,"FRU_INFO: {0}".format(fru_info),timestamp=False)
    else:
        is_fail = True
    return {} if is_fail else fru_info

def parseAPIData(jsonData):
    tempData = {}
    is_FAIL = False
    try:
        tempData["device_id"] = jsonData["device"]["id"]
        tempData["chassis_type"] = jsonData["chassis"]["type"]
        tempData["chassis_part_number"] = jsonData["chassis"]["part_number"]
        tempData["chassis_serial"] = jsonData["chassis"]["serial_number"]
        tempData["chassis_extra"] = jsonData["chassis"]["custom_fields"]
        tempData["board_manufacturer"] = jsonData["board"]["manufacturer"]
        tempData["board_product"] = jsonData["board"]["product_name"]
        tempData["board_serial"] = jsonData["board"]["serial_number"]
        tempData["board_part_number"] = jsonData["board"]["part_number"]
        tempData["board_extra"] = jsonData["board"]["custom_fields"]
        tempData["product_manufacturer"] = jsonData["product"]["manufacturer"]
        tempData["product_name"] = jsonData["product"]["product_name"]
        tempData["product_part_number"] = jsonData["product"]["part_number"]
        tempData["product_version"] = jsonData["product"]["product_version"]
        tempData["product_serial"] = jsonData["product"]["serial_number"]
        tempData["product_asset_tag"] = jsonData["product"]["asset_tag"]
        tempData["product_extra"] = jsonData["product"]["custom_fields"]
    except:
        is_FAIL = True

    return {} if is_FAIL else tempData

def getCMMFruInfoViaOEM():
    compareList = []
    is_fail = False
    fruInfo = {}
    cmd = "{0} fru".format(IPMITOOL)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[OEM] Get FRU Info\n{0}\nreturncode: {1}\n{2}".format(cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        for line in output.splitlines():
            if re.search(r'FRU Device Description',line,re.IGNORECASE):
                try:
                    device_id = line.split(":", 1)[-1].strip().split("ID")[-1].strip(" )")
                except:
                    device_id = "Unknown"
                fruInfo["device_id"] = device_id
            elif re.search(r'Chassis Type',line,re.IGNORECASE):
                chassis_type = line.split(":", 1)[-1].strip()
                fruInfo["chassis_type"] = chassis_type
            elif re.search(r'Chassis Part Number',line,re.IGNORECASE):
                chassis_part_number = line.split(":", 1)[-1].strip()
                fruInfo["chassis_part_number"] = chassis_part_number
            elif re.search(r'Chassis Serial',line,re.IGNORECASE):
                chassis_serial = line.split(":", 1)[-1].strip()
                fruInfo["chassis_serial"] = chassis_serial
            elif re.search(r'Chassis Extra',line,re.IGNORECASE):
                chassis_extra = line.split(":", 1)[-1].strip()
                fruInfo["chassis_extra"] = chassis_extra
            elif re.search(r'Board Mfg',line,re.IGNORECASE):
                board_manufacturer = line.split(":", 1)[-1].strip()
                fruInfo["board_manufacturer"] = board_manufacturer
            elif re.search(r'Board Product', line, re.IGNORECASE):
                board_product = line.split(":", 1)[-1].strip()
                fruInfo["board_product"] = board_product
            elif re.search(r'Board Serial', line, re.IGNORECASE):
                board_serial = line.split(":", 1)[-1].strip()
                fruInfo["board_serial"] = board_serial
            elif re.search(r'Board Part Number', line, re.IGNORECASE):
                board_part_number = line.split(":", 1)[-1].strip()
                fruInfo["board_part_number"] = board_part_number
            elif re.search(r'Board Extra', line, re.IGNORECASE):
                board_extra = line.split(":", 1)[-1].strip()
                fruInfo["board_extra"] = board_extra
            elif re.search(r'Product Manufacturer', line, re.IGNORECASE):
                product_manufacturer = line.split(":", 1)[-1].strip()
                fruInfo["product_manufacturer"] = product_manufacturer
            elif re.search(r'Product Name', line, re.IGNORECASE):
                product_name = line.split(":", 1)[-1].strip()
                fruInfo["product_name"] = product_name
            elif re.search(r'Product Part Number', line, re.IGNORECASE):
                product_part_number = line.split(":", 1)[-1].strip()
                fruInfo["product_part_number"] = product_part_number
            elif re.search(r'Product Version', line, re.IGNORECASE):
                product_version = line.split(":", 1)[-1].strip()
                fruInfo["product_version"] = product_version
            elif re.search(r'Product Serial', line, re.IGNORECASE):
                product_serial = line.split(":", 1)[-1].strip()
                fruInfo["product_serial"] = product_serial
            elif re.search(r'Product Asset Tag', line, re.IGNORECASE):
                product_asset_tag = line.split(":", 1)[-1].strip()
                fruInfo["product_asset_tag"] = product_asset_tag
            elif re.search(r'Product Extra', line, re.IGNORECASE):
                product_extra = line.split(":", 1)[-1].strip()
                fruInfo["product_extra"] = product_extra
    else:
        is_fail = True
    return {} if is_fail else fruInfo




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

    def c_compare_fru_info(self):
        if LOGIN_FAIL:
            return False
        global CASE_PASS
        message = "- Compare FRU info -"
        CMM.show_message(format_item(message),timestamp=False,color="green")
        CMM.save_data(main_log, message, timestamp=False)
        temp_text = message.strip(" -")
        is_FAIL = False
        compareList = ["device_id", "chassis_type", "chassis_part_number", "chassis_serial", "chassis_extra",
                       "board_manufacturer", "board_product", "board_serial", "board_part_number", "board_extra",
                       "product_manufacturer", "product_name", "product_part_number", "product_version",
                       "product_serial", "product_asset_tag", "product_extra"]
        tempData = getCMMFruInfoViaAPI()
        if tempData:
            OEM_data = getCMMFruInfoViaOEM()
            API_data = tempData[0]
            API_data = parseAPIData(API_data)
            if API_data:
                for item in compareList:
                    apiValue = API_data.get(item)
                    oemValue = OEM_data.get(item)
                    if item == "device_id":
                        apiValue = str(apiValue)
                    if apiValue != oemValue:
                        is_FAIL = True
                        text = "[API] {0}: {1}".format(item, apiValue)
                        MAIN_LOG_list.append(text)
                        CMM.show_message(text, timestamp=False, color="red")
                        text = "[OEM] {0}: {1}".format(item, oemValue)
                        MAIN_LOG_list.append(text)
                        CMM.show_message(text, timestamp=False, color="red")
            else:
                is_FAIL = True
        else:
            is_FAIL = True
        if is_FAIL:
            CASE_PASS = False
            show_step_result(temp_text, "FAIL")
            CMM.save_step_result(main_log, temp_text, "FAIL")
        else:
            show_step_result(temp_text,"PASS")
            CMM.save_step_result(main_log,temp_text,"PASS")

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