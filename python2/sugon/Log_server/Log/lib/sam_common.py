# -*- coding:utf-8 -*-

import re
import time
import datetime
import paramiko
import commands


def get_currnet_time(timestamp_format="%Y-%m-%d %H:%M:%S"):
    # return time.strftime(timestamp_format, time.localtime())
    return datetime.datetime.now().strftime(timestamp_format)

def get_time_interval(start, end, timestamp_format="%Y-%m-%d %H:%M:%S"):
    if isinstance(start, str):
        start = datetime.datetime.strptime(start, timestamp_format)
    if isinstance(end, str):
        end = datetime.datetime.strptime(end, timestamp_format)
    interval = (end - start).days * 86400 + (end - start).seconds
    return interval

def unicode_convert(data, code="utf-8"):
    if isinstance(data, list):
        return [unicode_convert(item) for item in data]
    elif isinstance(data, dict):
        return {unicode_convert(key): unicode_convert(value) for key,value in data.items()}
    elif isinstance(data, unicode):
        return data.encode(encoding=code)
    else:
        return data

def save_data(filename, data, flag="a", timestamp=True):
    if timestamp:
        data = "%s\t%s\n" %(get_currnet_time(), data)
    else:
        data = "%s\n" %data
    if flag == "w":
        f = open(filename, "w")
    else:
        f = open(filename, "a")
    f.write(data)
    f.close()

def run_cmd(cmd, filename=None):
    status, output = commands.getstatusoutput(cmd)
    if status != 0:
        msg = "[%s] Run FAIL !" %cmd
    else:
        msg = "[%s] Run successfully." %cmd
    if filename:
        msg = "\n".join([msg, output])
        save_data(filename, msg)
    return status, output.strip()

def judge_ip_location(IP):
    subnet = ".".join(IP.split(".")[:2])
    if subnet == "10.0":
        location = "Beijing"
    elif subnet == "10.2":
        location = "Tianjin"
    elif subnet == "10.8":
        location = "Kunshan"
    else:
        location = "Unknown"
    return location

def check_process_exist(name, flag="local", ip=None, username=None, password=None):
    is_exist = "Unknown"
    cmd = "ps -ef | grep '{0}' | grep -v grep".format(name)
    if flag == "local":
        ret = run_cmd(cmd)
        if ret[0] == 0:
            is_exist = True
        else:
            is_exist = False
    else:
        ret = Remote.ssh_run_cmd(cmd, ip, username, password)
        print ret
        if ret[0] == 0:
            if ret[1]:
                is_exist = True
            else:
                is_exist = False
    return is_exist



class Remote(object):
    def __init__(self, ip, username, password, ssh_count=3, ssh_interval=3, ping_count=3, ping_interval=3, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.ssh_count = ssh_count
        self.ssh_interval = ssh_interval
        self.ping_count = ping_count
        self.ping_interval = ping_interval
        self.port = port
    def init_ssh(self):
        # paramiko.util.log_to_file("/tmp/paramiko.log")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    def check_ssh_work(self):
        try:
            self.client.connect(self.ip, self.port, self.username, self.password)
        except Exception:
            return False
        else:
            self.close_ssh()
            return True
    def loop_check_ssh_work(self):
        self.init_ssh()
        count = self.ssh_count
        while count > 0:
            if self.check_ssh_work():
                return True
            time.sleep(self.ssh_interval)
            count -= 1
        return False
    @staticmethod
    def ping(ip):
        cmd = "ping -c 2 -w 2 %s" %ip
        status, output = commands.getstatusoutput(cmd)
        if status == 0:
            recv = re.search(r'\d received', output, re.IGNORECASE)
            if recv:
                n = recv.group().split()[0]
                if int(n) > 0:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
    def loop_ping(self):
        count = self.ping_count
        while count > 0:
            if self.ping(self.ip):
                return True
            time.sleep(self.ping_interval)
            count -= 1
        return False
    def close_ssh(self):
        self.client.close()
    @staticmethod
    def ssh_run_cmd(cmd, ip, username, password, port=22):
        output, error, e = None, None, None
        # paramiko.util.log_to_file("/tmp/paramiko.log")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, port=port, username=username, password=password)
            stdin, stdout, stderr = client.exec_command(cmd)
        except Exception as e:
            pass
        else:
            output = stdout.read().strip()
            error = stderr.read().strip()
        finally:
            client.close()
        if e:
            return 2, e
        elif error:
            return 1, error
        return 0, output
    @staticmethod
    def ssh_run_cmd_ping(cmd, ip, username, password, port=22):
        status, output = Remote.ssh_run_cmd(cmd, ip, username, password, port)
        if status == 0:
            recv = re.search(r'\d received', output, re.IGNORECASE)
            if recv:
                n = recv.group().split()[0]
                if int(n) > 0:
                    return 0, recv.group()
                else:
                    return 3, output
            else:
                return 4, output
        else:
            return status, output




if __name__ == "__main__":
    pass
    ip = "10.2.63.10"
    port = "5000"
    process = "socat - TCP:{0}:{1}".format(ip, port)
    print check_process_exist(process,"remote","10.2.34.225","root","111111")
    # print Remote.ssh_run_cmd("ps -ef | grep '%s' | grep -v grep"%process, "10.2.34.225", "root", "111111")
    # print judge_ip_location("10.2.39.240")
    # print judge_ip_location("10.8.27.211")
    # print judge_ip_location("10.0.21.101")
    # print Remote.ssh_run_cmd_ping("ping -c 1 10.0.21.21", "10.0.21.63", "root", "111111")