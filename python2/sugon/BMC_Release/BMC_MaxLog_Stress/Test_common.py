# -*- coding:utf-8 -*-

import os
import commands
import datetime
import time
import re
import signal
import paramiko

class AutoTest(object):
    """ 一些自动化测试通用的函数 """
    __timestamp_format = "%Y-%m-%d %H:%M:%S"

    def __init__(self):
        pass

    @classmethod
    def show_message(cls, message, flag="normal"):
        if flag == "red":
            print "%s\t\033[1;31m%s\033[0m" % (AutoTest.get_currnet_time(), message)
        elif flag == "green":
            print "%s\t\033[1;32m%s\033[0m" % (AutoTest.get_currnet_time(), message)
        elif flag == "yellow":
            print "%s\t\033[1;33m%s\033[0m" % (AutoTest.get_currnet_time(), message)
        else:
            print "%s\t%s" % (AutoTest.get_currnet_time(), message)

    @classmethod
    def kill_process(cls, name=None):
        if not name:
            message = "The 'name' is not defined !"
            print "Error: %s" %message
            return 1, message
        ret = cls.run_cmd(cmd="ps -ef")
        if ret[0] != 0:
            print ret[-1]
            return 2, ret[-1]
        find_process = False
        kill_fail = False
        fail_info = ""
        for line in ret[-1].splitlines():
            m = re.search(r'%s'%name, line)
            if m:
                find_process = True
                try:
                    pid = line.split()[1]
                    os.kill(int(pid), signal.SIGKILL)
                except Exception as e:
                    kill_fail = True
                    fail_info = "\n".join([fail_info, str(e)])
                    print "Error: %s" %str(e)
                else:
                    print "Process '%s' has been killed." %name
        if not find_process:
            return 0, "[%s] The process do not exist !" %name
        else:
            if kill_fail:
                return 3, fail_info
            else:
                return 0, "[%s] Kill process successfully." %name

    @classmethod
    def get_currnet_time(cls, timestamp_format=__timestamp_format):
        # return time.strftime(timestamp_format, time.localtime())
        return datetime.datetime.now().strftime(timestamp_format)

    @classmethod
    def calc_time_interval(cls, start_time, end_time, timestamp_format=__timestamp_format):
        if isinstance(start_time, str):
            start_time = datetime.datetime.strptime(start_time, timestamp_format)
        if isinstance(end_time, str):
            end_time = datetime.datetime.strptime(end_time, timestamp_format)
        interval = (end_time-start_time).days*86400 + (end_time-start_time).seconds
        return interval

    @classmethod
    def get_object_time(cls, base_time, delta, timestamp_format=__timestamp_format):
        """ 计算一定时间前后的时间 单位为秒
            eg: delta=86400 or delta=-43200 """
        if isinstance(base_time, str):
            base_time = datetime.datetime.strptime(base_time, timestamp_format)
        delta = datetime.timedelta(seconds=delta)
        obj_time = base_time + delta
        obj_time_str = obj_time.strftime(timestamp_format)
        return obj_time_str

    @classmethod
    def save_data(cls, filename, data, flag="a", timestamp=True):
        if timestamp:
            data = "%s\t%s\n" %(cls.get_currnet_time(), data)
        else:
            data = "%s\n" %data
        if flag == "w":
            f = open(filename, "w")
        else:
            f = open(filename, "a")
        f.write(data)
        f.close()

    @classmethod
    def run_cmd(cls, cmd, filename=None):
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            msg = "[%s] Run FAIL !" %cmd
        else:
            msg = "[%s] Run successfully." %cmd
        if filename:
            msg = "\n".join([msg, output])
            cls.save_data(filename, msg)
        return status, output.strip()

    @classmethod
    def retry_run(cls, cmd, interval=3, retry_counts=None, timeout=None):
        """ time unit: seconds """
        if retry_counts and timeout:
            return 1, "Please set retry_counts or timeout !"
        elif not retry_counts and not timeout:
            return 2, "Please set retry_counts or timeout !"
        count = 1
        if retry_counts:
            while count <= retry_counts:
                try:
                    status,output = cls.run_cmd(cmd=cmd)
                except Exception as e:
                    print "Exception:\n\t%s" %str(e)
                else:
                    if status == 0:
                        break
                    else:
                        print "[%s] Run FAIL ! Try count: %s/%s" %(cmd, count, retry_counts)
                finally:
                    count += 1
                    time.sleep(interval)
        elif timeout:
            interval = 0
            start_time = cls.get_currnet_time()
            while interval <= timeout:
                try:
                    status, output = cls.run_cmd(cmd=cmd)
                except Exception as e:
                    print "Exception:\n\t%s" % str(e)
                else:
                    if status == 0:
                        break
                    else:
                        print "[%s] Run FAIL ! Try count: %s" %(cmd, count)
                finally:
                    end_time = cls.get_currnet_time()
                    interval = cls.calc_time_interval(start_time=start_time, end_time=end_time)
                    count += 1
                    time.sleep(interval)
        return status, output


class Remote(object):
    def __init__(self, ip, username, password, ssh_count=3, ssh_interval=5, ping_count=3, ping_interval=5, port=22, timeout=60):
        self.ip = ip
        self.username = username
        self.password = password
        self.ssh_count = ssh_count
        self.ssh_interval = ssh_interval
        self.ping_count = ping_count
        self.ping_interval = ping_interval
        self.port = port
        self.timeout = timeout

    def init_ssh(self):
        # paramiko.util.log_to_file("/tmp/paramiko.log")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def check_ssh_work(self):
        try:
            self.client.connect(self.ip, self.port, self.username, self.password, timeout=self.timeout)
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

    def ping(self):
        cmd = "ping -c 3 %s" %self.ip
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
            if self.ping():
                return True
            time.sleep(self.ping_interval)
            count -= 1
        return False

    def close_ssh(self):
        self.client.close()

    @classmethod
    def ping_test(cls, ip, count=3, ipVers=4):
        if ipVers == 6:
            ping_cmd = "ping6"
        else:
            ping_cmd = "ping"
        cmd = "{0} -c {1} {2}".format(ping_cmd, count, ip)
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

    @staticmethod
    def ssh_run_cmd(cmd, ip, username, password, port=22, timeout=60):
        output, error, e = None, None, None
        paramiko.util.log_to_file("paramiko.log")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, port=port, username=username, password=password, timeout=timeout)
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
        if error:
            return 1, error
        return 0, output


if __name__ == '__main__':
    pass
    # ret = Remote.ssh_run_cmd("ls -l /var/log", "10.2.57.233", "sysadmin", "superuser")
    # print ret
    # print AutoTest.get_currnet_time()
    # print AutoTest.calc_time_interval("2018-08-29 10:34:30", "2018-08-29 10:34:48")
    # print AutoTest.get_object_time("2018-08-29 10:34:48", 7658)
    # print AutoTest.retry_run("haha", retry_counts=3)
    # print AutoTest.retry_run("ping -c 1 172.22.27.238", timeout=10)