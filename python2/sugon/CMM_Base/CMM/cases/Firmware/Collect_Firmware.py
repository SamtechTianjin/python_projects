# -*- coding:utf-8 -*-
__author__ = "Sam"

import os,sys
import re

lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import TMP_DIR
from libs.common import Remote

IP = "10.0.22.99"
USERNAME = "testteam"
PASSWORD = "111111"
LOCAL_PATH = TMP_DIR
CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))
PARAMIKO_LOG = os.path.join(CURRENT_PATH,"paramiko.log")

def pingTest():
    return Remote.ping_test(IP)

def getFirmwareName():
    name = "Unknown"
    cmd = "ls -l {0}".format(REMOTE_PATH)
    status,output = Remote.ssh_run_cmd(cmd,IP,USERNAME,PASSWORD)
    if status == 0:
        vers = 0
        for line in output.splitlines():
            if re.search(r'total\s+\d+',line):
                continue
            m = re.search(r'CMMSprint\d+_rom\.ima',line)
            if m:
                FW_file = m.group()
                mm = re.search(r'\d+',FW_file)
                if mm:
                    temp_vers = int(mm.group())
                    if temp_vers > vers:
                        vers = temp_vers
        if vers != 0:
            name = "CMMSprint{0}_rom.ima".format(vers)
    return name

def cleanOldFirmware(flag):
    for item in os.listdir(TMP_DIR):
        filename = os.path.join(TMP_DIR, item)
        if item.endswith("ima"):
            if flag == "CMM":
                os.remove(filename)
            else:
                pass

def downloadFirmware(filename):
    if filename == "Unknown":
        return False
    remote_path = os.path.join(REMOTE_PATH,filename)
    local_path = os.path.join(LOCAL_PATH,filename)
    status = Remote.download_file(remote_path, local_path, IP, USERNAME, PASSWORD)
    return status

def collectFirmware(remote_path="/home/CMMBuild/KLS/Release",flag="CMM"):
    global REMOTE_PATH
    REMOTE_PATH = remote_path
    cleanOldFirmware(flag)
    filename = getFirmwareName()
    status = downloadFirmware(filename)
    if os.path.exists(PARAMIKO_LOG):
        os.remove(PARAMIKO_LOG)
    if status:
        return True
    else:
        return False

if __name__ == '__main__':
    if len(sys.argv) == 2:
        flag = "CMM"
    elif len(sys.argv) == 3:
        flag = sys.argv[2]
    else:
        if os.path.exists(PARAMIKO_LOG):
            os.remove(PARAMIKO_LOG)
        sys.exit(1)
    REMOTE_PATH = sys.argv[1]
    cleanOldFirmware(flag)
    filename = getFirmwareName()
    status = downloadFirmware(filename)
    if os.path.exists(PARAMIKO_LOG):
        os.remove(PARAMIKO_LOG)
    if status:
        sys.exit(0)
    else:
        sys.exit(2)


