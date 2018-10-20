# -*- coding:utf-8 -*-

import os
import commands
import datetime
import time
import re
import signal
import paramiko
import shutil
import json
import subprocess
from console_show import show_title

class LoginFail(Exception):
    def __init__(self, error):
        super(LoginFail, self).__init__(error)

class LogoutFail(Exception):
    def __init__(self, error):
        super(LogoutFail, self).__init__(error)

class AutoTest(object):

    __timestamp_format = "%Y-%m-%d %H:%M:%S"

    def __init__(self):
        pass

    @staticmethod
    def calc_runtime(func):
        def wrapper(*args,**kwargs):
            start_time = datetime.datetime.now()
            returnValue = func(*args,**kwargs)
            end_time = datetime.datetime.now()
            delta_time = end_time-start_time
            runtime = round(delta_time.days*86400+delta_time.seconds+delta_time.microseconds/1000000.0,2)
            return runtime
        return wrapper

    @classmethod
    def show_message(cls, message, color=None, timestamp=True, timestamp_format=None,indent=0):
        if color == "red":
            color_num = 31
        elif color == "green":
            color_num = 32
        elif color == "yellow":
            color_num = 33
        elif color == "blue":
            color_num = 34
        else:
            color_num = ""
        if color_num:
            if timestamp:
                if timestamp_format:
                    message = "{0}\t\033[1;{1}m{2}\033[0m".format(AutoTest.get_currnet_time(timestamp_format), color_num, message)
                else:
                    message = "{0}\t\033[1;{1}m{2}\033[0m".format(AutoTest.get_currnet_time(), color_num, message)
            else:
                message = "\033[1;{0}m{1}\033[0m".format(color_num, message)
        else:
            if timestamp:
                if timestamp_format:
                    message = "{0}\t{1}".format(AutoTest.get_currnet_time(timestamp_format), message)
                else:
                    message = "{0}\t{1}".format(AutoTest.get_currnet_time(), message)
        if indent:
            print("{0}{1}".format(" "*indent,message))
        else:
            print(message)

    @classmethod
    def kill_process(cls, name=None):
        if not name:
            message = "The 'name' is not defined !"
            print "Error: {0}".format(message)
            return 1, message
        ret = cls.run_cmd(cmd="ps -ef")
        if ret[0] != 0:
            print ret[-1]
            return 2, ret[-1]
        find_process = False
        kill_fail = False
        fail_info = ""
        for line in ret[-1].splitlines():
            m = re.search(r'{0}'.format(name), line)
            if m:
                find_process = True
                try:
                    pid = line.split()[1]
                    os.kill(int(pid), signal.SIGKILL)
                except Exception as e:
                    kill_fail = True
                    fail_info = "\n".join([fail_info, str(e)])
                    print "Error: {0}".format(e)
                else:
                    print "Process '{0}' has been killed.".format(name)
        if not find_process:
            return 0, "[{0}] The process do not exist !".format(name)
        else:
            if kill_fail:
                return 3, fail_info
            else:
                return 0, "[{0}] Kill process successfully.".format(name)

    @classmethod
    def get_currnet_time(cls, timestamp_format=__timestamp_format):
        # return time.strftime(timestamp_format, time.localtime())
        return datetime.datetime.now().strftime(timestamp_format)

    @classmethod
    def calc_time_interval(cls,start_time,end_time,timestamp_format=__timestamp_format,interval_int=True,decimal=2):
        if isinstance(start_time, str):
            start_time = datetime.datetime.strptime(start_time, timestamp_format)
        if isinstance(end_time, str):
            end_time = datetime.datetime.strptime(end_time, timestamp_format)
        if interval_int:
            interval = (end_time-start_time).days*86400 + (end_time-start_time).seconds
        else:
            interval = (end_time-start_time).days*86400 + (end_time-start_time).seconds + float((end_time-start_time).microseconds)/1000000
            interval = round(interval,decimal)
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
            data = "{0}\t{1}\n".format(cls.get_currnet_time(), data)
        else:
            data = "{0}\n".format(data)
        if flag == "w":
            method = "w"
        else:
            method = "a"
        with open(filename, method) as f:
            f.write(data)

    @classmethod
    def run_cmd(cls, cmd, filename=None):
        """ 使用commands执行命令，不适用于Windows """
        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            msg = "[{0}] Run FAIL !".format(cmd)
        else:
            msg = "[{0}] Run successfully.".format(cmd)
        if filename:
            msg = "\n".join([msg, output])
            cls.save_data(filename, msg)
        return status, output.strip()

    @classmethod
    def run_command(cls,command):
        """ 使用subprocess执行命令，兼容Linux和Windows """
        status,output,error,exception = 0,None,None,None
        try:
            child = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            output,error = child.communicate()
            status = child.returncode
        except Exception as exception:
            cls.show_message("[Exception]\n{0}".format(exception),color="red",timestamp=False)
        else:
            output = output.strip()
            error = error.strip()
        finally:
            if exception:
                return 2,exception
            if status == 0:
                return status,output
            else:
                return status,error

    @classmethod
    def retry_run(cls, cmd, interval=3, retry_counts=None, timeout=None):
        """ time unit: seconds """
        if retry_counts and timeout:
            return 1, "Please set retry_counts or timeout !"
        elif not retry_counts and not timeout:
            return 2, "Please set retry_counts or timeout !"
        count = 1
        status,output = 9,"default"
        if retry_counts:
            while count <= retry_counts:
                try:
                    status,output = cls.run_cmd(cmd=cmd)
                except Exception as e:
                    print "Exception:\n\t{0}".format(e)
                else:
                    if status == 0:
                        break
                    else:
                        cls.show_message("[{0}] Run FAIL ! Try count: {1}/{2}".format(cmd, count, retry_counts),color="red")
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
                    print "Exception:\n\t{0}".format(e)
                else:
                    if status == 0:
                        break
                    else:
                        cls.show_message("[{0}] Run FAIL ! Try count: {1}".format(cmd, count),color="red")
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
        paramiko.util.log_to_file("paramiko.log")
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
        cmd = "ping -c 3 {0}".format(self.ip)
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

    @classmethod
    def sftp_upload_file(cls,ip,username,password,local_path,server_path,port=22):
        upload_ok = False
        try:
            t = paramiko.Transport(ip,port)
            t.connect(username=username,password=password)
            sftp = paramiko.SFTPClient.from_transport(t)
            sftp.put(local_path,server_path)
            t.close()
        except Exception as e:
            message = "[{0}]\n{1}".format("Exception - upload",e)
            BMC.show_message(message,color="red")
        else:
            message = "[{0}] Upload successfully.".format(local_path)
            BMC.show_message(message,color="green")
            upload_ok = True
        return upload_ok


class BMC(AutoTest):
    """ 关于BMC测试的通用函数 """
    __username = "admin"
    __password = "admin"
    __lans = [1]

    def __init__(self):
        super(BMC, self).__init__()

    @classmethod
    def retry_BMC(cls, ip, username=__username, password=__password, interval=10, retry_counts=24):
        ipmitool = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(ip, username, password)
        cmd = "{0} raw 0x06 0x01".format(ipmitool)
        status,output = cls.retry_run(cmd=cmd, interval=interval, retry_counts=retry_counts)
        if status == 0:
            message = "BMC status is OK !"
            cls.show_message(message, color="green")
        else:
            message = "BMC status is not still restored after {0} seconds !".format(interval*retry_counts)
            cls.show_message(message, color="red")
            return False
        return True

    @classmethod
    def check_ipmi_command(cls, ip, username=__username, password=__password, lans=__lans):
        data = ""
        ipmi_fail = False
        ipmitool = "ipmitool -I lanplus -H {0} -U {1} -P {2}".format(ip, username, password)
        ipmi_cmds = {
            "version": "{0} raw 0x06 0x01".format(ipmitool),
            "mc info": "{0} mc info".format(ipmitool),
            "sdr info": "{0} sdr info".format(ipmitool),
            "sol info": "{0} sol info".format(ipmitool)
        }
        if lans:    # 注意: lans是列表 默认是[1]
            for lan in lans:
                name = "lan {0}".format(lan)
                cmd = "{0} lan print {1}".format(ipmitool, lan)
                ipmi_cmds[name] = cmd
        for name, ipmi_cmd in ipmi_cmds.iteritems():
            status, output = cls.run_cmd(ipmi_cmd)
            if status == 0:
                message = "Check BMC {0} OK !".format(name)
                cls.show_message(message, color="green")
            else:
                message = "Check BMC {0} FAIL !\n{1}".format(name, output)
                cls.show_message(message, color="red")
                ipmi_fail = True
            data = "\n".join([data,"[{0}]{1}\n".format(name,ipmi_cmd),output])
        if ipmi_fail:
            return False, data
        return True, data

    @classmethod
    def check_web_login(cls, ip , username=__username, password=__password):
        login_fail = False
        csrf_token = None
        logout_fail = False
        try:
            login_cmd = "curl -X POST -d \"username={0}&password={1}\" \"http://{2}/api/session\" -c ./cookie 2> /dev/null".format(
                username, password, ip)
            status, output = cls.run_cmd(login_cmd)
            if status == 0:
                ret_dict = json.loads(output.strip())
                if ret_dict.get("ok") == 0:
                    csrf_token = ret_dict.get("CSRFToken")
                else:
                    raise LoginFail(ret_dict)
            else:
                raise LoginFail("[curl] The return code is not 0 !")
        except Exception as e:
            login_fail = True
            message = "Login web FAIL !\n{0}".format(e)
            cls.show_message(message, color="red")
        else:
            message = "Login web OK !"
            cls.show_message(message, color="green")
        finally:
            if login_fail:
                return False
            else:
                if csrf_token:
                    try:
                        logout_cmd = 'curl -X DELETE -H "X-CSRFTOKEN:{0}" "http://{1}/api/session" -b ./cookie 2> /dev/null'.format(
                            csrf_token, ip)
                        status, output = cls.run_cmd(logout_cmd)
                        if status == 0:
                            ret_dict = json.loads(output.strip())
                            if ret_dict.get("ok") == 0:
                                message = "Logout web OK !"
                            else:
                                raise LogoutFail(ret_dict)
                        else:
                            raise LogoutFail("[curl] The return code is not 0 !")
                    except Exception as e:
                        logout_fail = True
                        message = "Logout web FAIL !\n{0}".format(e)
                        cls.show_message(message, color="red")
                    else:
                        cls.show_message(message, color="green")
                    finally:
                        if logout_fail:
                            return False
        return True


class CMM(AutoTest):

    def __init__(self):
        super(CMM, self).__init__()

    def case_init(self,case_name,log_dir):
        show_title(case_name)
        if os.path.exists(log_dir):
            shutil.rmtree(log_dir)
        os.makedirs(log_dir)

    def banner(self,message):
        length = 60
        top = "#{0}#".format("="*(length-2))
        bottom = top
        message = "#{0}#".format(message.center((length-2)," "))
        return "\n".join([top,message,bottom])



if __name__ == '__main__':
    pass
    # show_title("Hello world !",color="m")
    # cmm = CMM()
    # print(cmm.banner("Sam"))
    Remote.sftp_upload_file("10.0.21.86","root","dailyrun","SCELNX_64","/root/SCELNX_64")