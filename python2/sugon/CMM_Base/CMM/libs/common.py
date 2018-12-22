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

    @classmethod
    def deleteFile(cls,path,startWith=None,endWith=None):
        oldPath = os.getcwd()
        try:
            os.chdir(path)
        except Exception as e:
            print(e)
            return False
        for name in os.listdir(path):
            isDelete = False
            if startWith and endWith:
                if name.startswith(startWith) and name.endswith(endWith):
                    isDelete = True
            elif startWith:
                if name.startswith(startWith):
                    isDelete = True
            elif endWith:
                if name.endswith(endWith):
                    isDelete = True
            else:
                isDelete = True
            if isDelete:
                if os.path.isfile(name):
                    os.remove(name)
                elif os.path.isdir(name):
                    shutil.rmtree(name)
        os.chdir(oldPath)
        return True

    @classmethod
    def modify_file_content(cls,filename,old_data,new_data):
        file_data = ""
        is_fail = False
        try:
            with open(filename,"r") as temp_file:
                for line in temp_file:
                    if old_data in line:
                        line = line.replace(old_data,new_data)
                    file_data += line
            with open(filename,"w") as temp_file:
                temp_file.write(file_data)
        except Exception as e:
            temp_text = "[Exception] {0}".format(e)
            cls.show_message(temp_text,timestamp=False,color="red")
            is_fail = True
        return False if is_fail else True

    @classmethod
    def retry_run_cmd(cls,cmd,count=5,interval=3):
        status = 1
        output = "Default output"
        while count > 0:
            status,output = cls.run_cmd(cmd)
            if status == 0 and not re.search(r'error:',output,re.IGNORECASE):
                break
            count -= 1
            time.sleep(interval)
        return status,output

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
    def download_file(remote_path,local_path,ip,username,password,port=22):
        status = True
        try:
            t = paramiko.Transport(ip, port)
            t.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(t)
            sftp.get(remote_path, local_path)
        except Exception as e:
            print("[Exception download file] {0}".format(e))
            status = False
        else:
            t.close()
        return status

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

    @classmethod
    def curl_login_logout(cls,ip,flag="login",username="admin",password="admin",csrf_token=None,retry_count=2):
        restAPI = "/api/session"
        restcode = 0
        message = None
        flag = flag.lower()
        if flag == "login":
            cmd = "curl -X POST -d \"username={0}&password={1}\" \"http://{2}{3}\" -c ./cookie 2>/dev/null".format(
                username,password,ip,restAPI)
        elif flag == "logout":
            if not csrf_token:
                return 1,"[logout] \"csrf_token\" is not defined !"
            cmd = "curl -X DELETE -H \"X-CSRFTOKEN:{0}\" \"http://{1}{2}\" -b ./cookie 2>/dev/null".format(csrf_token, ip,restAPI)
        else:
            return 1,"The flag should be login|logout !"
        try:
            """ 刷新固件后第一次登录网页一定会出现500错误 因此增加retry 后续等待解决???  """
            while retry_count > 0:
                status,output = cls.retry_run_cmd(cmd)
                if status == 0:
                    try:
                        ret_dict = json.loads(output.strip())
                    except: pass
                    else:
                        if ret_dict.get("ok") == 0:
                            if flag == "login":
                                csrf_token = ret_dict.get("CSRFToken")
                            break
                retry_count -= 1
                time.sleep(3)
            else:
                raise LoginFail("FAIL") if flag == "login" else LogoutFail("FAIL")
        except Exception as e:
            restcode = 1
            message = "{0} {1}".format(flag,e)
        else:
            message = csrf_token if flag == "login" else "Logout successfully."
        finally:
            return restcode,message

    @classmethod
    def save_step_result(cls,filename, text, flag):
        TITLE_LENGTH = 64
        item = "{0} {1} ".format(text, "-" * (TITLE_LENGTH - len(text) - 8))
        if flag.upper() == "PASS":
            item += "[PASS]"
        elif flag.upper() == "FAIL":
            item += "[FAIL]"
        elif flag.upper() == "WARN":
            item += "[WARN]"
        else:
            pass
        with open(filename, "a") as f:
            f.write(item)
            f.write("\n")

    @classmethod
    def convert_to_decimal(cls,item):
        try:
            data = int(item,16)
        except Exception as e:
            data = "Unknown"
        return data

    @classmethod
    def convert_to_decimal_multi(cls,items,prior="L"):
        temp_list = []
        for item in items:
            temp = cls.convert_to_decimal(item)
            if temp != "Unknown":
                temp_list.append(temp)
            else:
                return False
        if prior.upper() == "L":
            pass
        elif prior.upper() == "H":
            temp_list.reverse()
        else:
            return False
        returnvalue = 0
        for index,value in enumerate(temp_list):
            returnvalue += value*(256**index)
        return returnvalue

    @classmethod
    def convert_to_IP(cls,items,vers=4):
        ip_address = ""
        if vers == 4:
            if len(items) == 4:
                for item in items:
                    temp = cls.convert_to_decimal(item)
                    if temp == "Unknown":
                        continue
                    if ip_address:
                        ip_address += ".{0}".format(temp)
                    else:
                        ip_address += "{0}".format(temp)
                return ip_address
        elif vers == 6:
            if len(items) == 16:
                ip_address = "".join(items)
                return ip_address
        return "Unknown"

    @classmethod
    def hex2str(cls,items):
        if isinstance(items,str):
            items = items.split()
        temp_str = ""
        for item in items:
            if item == "00":
                break
            temp_str += chr(int(item,16))
        return temp_str

    @classmethod
    def compare_dict(cls,baseline,loopdata):
        temp_list = []
        for k in baseline:
            v1 = baseline.get(k)
            v2 = loopdata.get(k)
            if v1 != v2:
                for kk in v1:
                    vv1 = v1.get(kk)
                    vv2 = v2.get(kk)
                    if vv1 != vv2:
                        temp1 = "{0} {1}".format(k,kk)
                        temp_list.append(temp1)
        return temp_list





""" 常用函数 """
def unicode_convert(data, code="utf-8"):
    if isinstance(data, list):
        return [unicode_convert(item) for item in data]
    elif isinstance(data, dict):
        return {unicode_convert(key): unicode_convert(value) for key, value in data.items()}
    elif isinstance(data, unicode):
        return data.encode(encoding=code)
    else:
        return data





if __name__ == '__main__':
    show_title("Hello world !",color="m")
    cmm = CMM()
    print(cmm.banner("Sam"))