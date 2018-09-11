# -*- coding:utf-8 -*-

import os
import sys
import time
import subprocess
import re

# 该脚本对串口日志进行检查并执行刷新操作
# 该脚本与run.sh和end.sh在相同目录

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
MAX_TIME = 60      # 如果当前时间与日志最后更新时间的时间差超过<MAX_TIME>，那么日志文件执行刷新操作
LOG_DIR = sys.argv[1]
end_script = os.path.join(CURRENT_PATH, "end.sh")
run_script = os.path.join(CURRENT_PATH, "run.sh")
END_CMD = "bash %s {0} {1}" %end_script
RUN_CMD = "bash %s serial {0} {1} {2}" %run_script

def get_current_time():
    timestamp = int(time.time())
    date = time.strftime("%Y-%m-%d")    # 日志目录以日期名称命名
    return timestamp, date

def get_update_time(filename):
    return int(os.stat(filename).st_ctime)

def get_filename_via_screen():
    # 返回使用screen监控的信息
    filenames = []
    cmd = "screen -ls"
    child = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output,error = child.communicate()
    for line in output.splitlines():
        if not line: continue
        if line.startswith("There are screens on"): continue
        if re.search(r'\d+ Sockets in', line): continue
        m = re.search(r'\d+\.\d+\.\d+\.\d+_\d+', line)
        if m:
            filename = m.group()
            filenames.append(filename)
    return filenames

def exec_file_flush(filename, current, max_time=MAX_TIME):
    # format: filename = "10.2.63.10_5000"
    ip,port = filename.split("_")
    end_cmd = END_CMD.format(ip, port)
    start_cmd = RUN_CMD.format(ip, port, LOG_DIR)
    filename = "{0}.log".format(filename)       # 日志名称的格式为"10.2.63.10_5000.log"
    if os.path.exists(filename):
        update_time = get_update_time(filename)
        interval = current-update_time
    else:
        interval = max_time
    if interval >= max_time:
        end = subprocess.Popen(end_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output,error = end.communicate()
        if end.returncode != 0:
            print "[{0}] Run FAIL !".format(end_cmd)
            print error
        time.sleep(1)
        start = subprocess.Popen(start_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output,error = start.communicate()
        if start.returncode != 0:
            print "[{0}] Run FAIL !".format(start_cmd)
            print error

def exec_directory_flush():
    os.chdir(LOG_DIR)
    current,directory = get_current_time()
    if not os.path.exists(directory):
        os.makedirs(directory)
    os.chdir(directory)     # 切换到当前日期的目录下
    filenames = get_filename_via_screen()
    for filename in filenames:
        exec_file_flush(filename, current)
    return True


if __name__ == '__main__':
    while True:
        ret = exec_directory_flush()
        time.sleep(30)