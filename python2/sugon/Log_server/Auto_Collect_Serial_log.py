# -*- coding:utf-8 -*-

import os,sys
import subprocess
import signal
import time
import re
import commands


"""
通过tcpdump监控${Monitor_Time}秒 处理数据一次
"""
Monitor_Time = 30
Interval = 3
Monitor_IP = "10.0.21.63"
Monitor_Port = "9999"
Temp_File = "/tmp/Serial_Log.txt"
Log_Path = sys.argv[1]
Current_Path = os.path.abspath(os.path.dirname(__file__))
# 脚本路径 例如: /var/www/html/Platform/Log/lib/shell/run.sh
Script_Path = os.path.join(Current_Path,"run.sh")


def Get_NIC_Port_Name():
    name = None
    cmd = "ifconfig -a | grep -B 1 %s | head -n 1 | awk -F: '{print $1}'" %(Monitor_IP)
    child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output,error = child.communicate()
    if output.strip():
        name = output.strip()
    return name

def Get_Monitor_Command():
    name = Get_NIC_Port_Name()
    if name:
        cmd = "tcpdump -i {0} udp port {1} -e &> {2}".format(name,Monitor_Port,Temp_File)
        if os.getuid() != 0:
            cmd = "sudo {0}".format(cmd)
        return cmd

def Kill_Process(name="tcpdump",retry_count=5):
    cmd = "killall {0}".format(name)
    if os.getuid() != 0:
        cmd = "sudo {0}".format(cmd)
    while retry_count > 0:
        ret = os.popen("ps -ef | grep {0} | grep -v grep".format(name))
        if ret.read().strip():
            os.system(cmd)
        else:
            break
        time.sleep(1)
        retry_count -= 1

def Parse_File_Data():
    unique_list = []
    with open(Temp_File,"r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("tcpdump"): continue
            elif line.startswith("listening"): continue
            elif not line: continue
            if re.match(r'(\d{2}:){2}\d{2}',line):
                temp_list = line.split()
                ip_port = temp_list[13]
                mac_address = temp_list[1]
                ip = re.match(r'(\d+\.){3}\d+',ip_port).group()
                port = ip_port.split(".")[-1]
                temp = {
                    "MAC": mac_address,
                    "IP": ip,
                    "PORT": port
                }
                if temp in unique_list:
                    continue
                unique_list.append(temp)
    return unique_list

def Get_Filename_Via_Screen():
    # 返回使用screen监控的信息
    filenames = []
    cmd = "screen -ls"
    # Beijing
    child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output,error = child.communicate()
    for line in output.splitlines():
        if not line: continue
        if line.startswith("There are screens on"): continue
        if re.search(r'\d+ Sockets in', line): continue
        m = re.search(r'(\d+\.){3}\d+_\d+', line)
        if m:
            filename = m.group()
            filenames.append(filename)
    # Tianjin

    # Kunshan

    return filenames

def Update_Monitor():
    collect_list = Parse_File_Data()
    for temp in collect_list:
        ip,port = [temp.get(item,None) for item in ["IP","PORT"]]
        if ip and port:
            filename = "_".join([ip,port])
            for i in range(5):  # 检测5次 如果未监控 则开始收集日志
                monitor_list = Get_Filename_Via_Screen()
                if filename in monitor_list:
                    break
                time.sleep(1)
            else:
                if ip.startswith("10.0"):
                    cmd = "bash {0} serial {1} {2} {3}".format(Script_Path,ip,port,Log_Path)
                    status,output = commands.getstatusoutput(cmd)
                    if status == 0:
                        message = "[{0}] Collect serial log successfully.".format("{0} {1}".format(ip,port))
                        print(message)
                    else:
                        message = "[{0}] Collect serial log FAIL !".format("{0} {1}".format(ip,port))
                        print("\033[1;31m{0}\033[0m".format(message))



if __name__ == '__main__':
    """
    确定是否为北京机台 自动收集操作只执行在北京机台
    """
    if Get_NIC_Port_Name():
        while True:
            cmd = Get_Monitor_Command()
            if cmd:
                child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                child_pid = child.pid
                time.sleep(Monitor_Time)
                os.kill(child_pid,signal.SIGKILL)
                Kill_Process(name="tcpdump")
                time.sleep(1)
                Update_Monitor()
                time.sleep(Interval)
            else:
                time.sleep(3600)
    else:
        message = "The current server don't support auto collect !!!"
