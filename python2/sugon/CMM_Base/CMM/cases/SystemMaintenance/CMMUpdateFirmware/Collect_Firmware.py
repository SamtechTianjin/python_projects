# -*- coding:utf-8 -*-
__author__ = "Sam"

import os,sys
import re
import shutil
lis = re.split(r'[/\\]',os.path.abspath(__file__))
path = os.sep.join(lis[0:lis.index("CMM")+1])
sys.path.append(path)
from conf.common_config import TMP_DIR,IMAGE_DIR
from conf.config import IMAGE_SERVER_IP,IMAGE_SERVER_USERNAME,IMAGE_SERVER_PASSWORD,TEMP_PATH
from libs.common import Remote


REMOTE_PATH = ""
IP = IMAGE_SERVER_IP
USERNAME = IMAGE_SERVER_USERNAME
PASSWORD = IMAGE_SERVER_PASSWORD
LOCAL_PATH = IMAGE_DIR
CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))
PARAMIKO_LOG = os.path.join(CURRENT_PATH,"paramiko.log")

def pingTest():
    return Remote.ping_test(IP)

def getFirmwareName():
    global REMOTE_PATH
    endPath = "Project/SugonBase/development/Build/output/"
    name = "Unknown"
    cmd = "ls -lt {0}".format(TEMP_PATH)    # 以时间排序 获取最新的镜像
    status,output = Remote.ssh_run_cmd(cmd,IP,USERNAME,PASSWORD)
    if status == 0:
        for line in output.splitlines():
            m = re.search(r'\d{4}(-\d{2}){5}',line)
            if m:
                datePath = m.group()
                REMOTE_PATH = os.path.join(TEMP_PATH,datePath,endPath)
                cmd = "ls {0}".format(REMOTE_PATH)
                status, output = Remote.ssh_run_cmd(cmd, IP, USERNAME, PASSWORD)
                if status == 0:
                    for item in output.split():
                        m = re.search(r'.*\.ima',item)
                        if m:
                            name = m.group()
                            break
                break
    """
    # 获得CMMSprint*_rom.ima镜像文件
    REMOTE_PATH = "/home/CMMBuild/KLS/Release"
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
    """
    return name

def cleanOldFirmware(flag="CMM"):
    for item in os.listdir(TMP_DIR):
        filename = os.path.join(TMP_DIR, item)
        if item.endswith("ima") and item.startswith(flag):
            os.remove(filename)

def downloadFirmware(filename):
    if filename == "Unknown":
        return False
    remote_path = os.path.join(REMOTE_PATH,filename)
    local_path = os.path.join(LOCAL_PATH,filename)
    status = Remote.download_file(remote_path, local_path, IP, USERNAME, PASSWORD)
    return status

def collectFirmware(flag="CMM"):
    if not pingTest():
        return False
    cleanOldFirmware(flag)
    filename = getFirmwareName()
    status = downloadFirmware(filename)
    if os.path.exists(PARAMIKO_LOG):
        os.remove(PARAMIKO_LOG)
    if status:
        downloadFile = os.path.join(LOCAL_PATH,filename)
        newFile = os.path.join(TMP_DIR,"{0}.ima".format(flag))
        shutil.copy(downloadFile,newFile)
        # 确保Firmware文件已经存在
        if os.path.exists(newFile):
            return True
    return False

if __name__ == '__main__':
    if len(sys.argv) == 2:
        flag = sys.argv[1]
    else:
        flag = "CMM"
    if not pingTest():
        sys.exit(1)
    cleanOldFirmware(flag)
    filename = getFirmwareName()
    status = downloadFirmware(filename)
    if os.path.exists(PARAMIKO_LOG):
        os.remove(PARAMIKO_LOG)
    if status:
        sys.exit(0)
    else:
        sys.exit(2)


