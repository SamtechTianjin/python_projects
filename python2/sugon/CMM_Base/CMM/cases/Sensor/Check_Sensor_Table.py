# -*- coding:utf-8 -*-
__author__ = "Sam"

import os
import sys
import unittest
import time
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
IPMITOOL = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(IP,USERNAME,PASSWORD)

"""
IPMI命令返回值
SW1_Power        | 11.000     | Watts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
SystemTotalPower | 68.000     | Watts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU1_Pout        | 0.000      | Watts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU2_Pout        | 0.000      | Watts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU3_Pout        | 176.000    | Watts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU4_Pout        | 148.000    | Watts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU1_Vout        | 0.000      | Volts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU2_Vout        | 0.000      | Volts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU3_Vout        | 12.000     | Volts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU4_Vout        | 12.000     | Volts      | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU1_Iout        | 0.000      | Amps       | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU2_Iout        | 0.000      | Amps       | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU3_Iout        | 35.000     | Amps       | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU4_Iout        | 33.000     | Amps       | ok    | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     | 0.000     
PSU1_Present     | 0x0        | discrete   | 0x0180| na        | na        | na        | na        | na        | na        
PSU2_Present     | 0x0        | discrete   | 0x0180| na        | na        | na        | na        | na        | na        
PSU3_Present     | 0x0        | discrete   | 0x0280| na        | na        | na        | na        | na        | na        
PSU4_Present     | 0x0        | discrete   | 0x0280| na        | na        | na        | na        | na        | na        
PSU1_Status      | 0x0        | discrete   | 0x0080| na        | na        | na        | na        | na        | na        
PSU2_Status      | 0x0        | discrete   | 0x0080| na        | na        | na        | na        | na        | na        
PSU3_Status      | 0x0        | discrete   | 0x0180| na        | na        | na        | na        | na        | na        
PSU4_Status      | 0x0        | discrete   | 0x0180| na        | na        | na        | na        | na        | na        
FAN1_RPM         | 9800.000   | RPM        | ok    | 1500.000  | 1500.000  | 1500.000  | 20000.000 | 20000.000 | 20000.000 
FAN2_RPM         | 9800.000   | RPM        | ok    | 1500.000  | 1500.000  | 1500.000  | 20000.000 | 20000.000 | 20000.000 
FAN3_RPM         | 9800.000   | RPM        | ok    | 1500.000  | 1500.000  | 1500.000  | 20000.000 | 20000.000 | 20000.000 
FAN4_RPM         | 9800.000   | RPM        | ok    | 1500.000  | 1500.000  | 1500.000  | 20000.000 | 20000.000 | 20000.000 
FAN5_RPM         | 9800.000   | RPM        | ok    | 1500.000  | 1500.000  | 1500.000  | 20000.000 | 20000.000 | 20000.000 
"""



def getSensorTableViaOEM():
    is_fail = False
    sensorTable = []
    cmd = "{0} sensor list".format(IPMITOOL)
    status,output = CMM.retry_run_cmd(cmd)
    message = "[OEM] Get Sensor Table Info\n{0}\nreturncode: {1}\n{2}".format(cmd, status, output)
    CMM.save_data(main_log, message, timestamp=False)
    if status == 0:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            else:
                # tempList = line.split("|")
                # lineList = map(lambda x : x.strip(), tempList)
                # sensorTable.append(lineList)
                sensorTable.append(line)
    else:
        is_fail = True
    return [] if is_fail else sensorTable




class CMMTest(unittest.TestCase,CMM):

    def setUp(self):
        print("\n")

    def tearDown(self):
        time.sleep(1)

    def a_init(self):
        case_name = "Case: " + module_name.replace("_", " ")
        self.case_init(case_name, log_dir)
        CMM.save_data(main_log,self.banner(case_name),timestamp=False)

    def c_check_sensor_table(self):
        global CASE_PASS
        message = "- Collect sensor table info -"
        CMM.show_message(format_item(message),timestamp=False,color="green")
        CMM.save_data(main_log, message, timestamp=False)
        MAIN_LOG_list.append(message)
        temp_text = message.strip(" -")
        is_FAIL = False
        OEM_data = getSensorTableViaOEM()
        if OEM_data:
            CMM.save_data(MAIN_LOG,"OEM_Sensor_Table_INFO: {0}".format(OEM_data),timestamp=False)
        else:
            is_FAIL = True
        if is_FAIL:
            CASE_PASS = False
            show_step_result(temp_text,"FAIL")
            CMM.save_step_result(main_log,temp_text,"FAIL")
        else:
            show_step_result(temp_text, "PASS")
            CMM.save_step_result(main_log, temp_text, "PASS")

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