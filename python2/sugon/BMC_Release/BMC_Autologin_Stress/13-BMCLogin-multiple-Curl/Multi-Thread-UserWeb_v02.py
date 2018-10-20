#!/usr/bin/python
# coding:utf-8
#===============Sugon test BMC 20 user login Web ====================================================
# Sugon Modified version v1.0
# Description:
# USAGE: 
# AUTHOR: Yanshupeng
# CREATED: 11/08/2017
#=====================================================================================================
import sys
import datetime
import os
import commands
import json
import time
import re
import threading
from optparse import OptionParser
import subprocess
import paramiko

class PingFail(Exception):
    def __init__(self, err):
        super(PingFail, self).__init__(err)

class LoginFail(Exception):
    def __init__(self, err):
        super(LoginFail, self).__init__(err)

class LogoutFail(Exception):
    def __init__(self, err):
        super(LogoutFail, self).__init__(err)

def del_file(dirname):
    l = os.listdir(dirname)
    for f in l:
        f = os.path.join(dirname, f)
        if os.path.isdir(f):
            del_file(f)
        else:
            os.remove(f)

def GetNowTime():
    return time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time()))

def SaveLog(filename, info, mode="a"):
    text_file = open(filename, mode)
    text_file.write(str(info))
    text_file.write("\n")
    text_file.close()

def calc_interval(startTime, endTime, flag="s"):
    interval = (endTime-startTime).days*86400+(endTime-startTime).total_seconds()
    if flag == "ms":
        return "%.1f" %(float(interval*1000))
    return "%.1f" %float(interval)

def ping_test(ip, count=3):     # For linux
    if ipVers == 6:
        ping_cmd = "ping6"
    else:
        ping_cmd = "ping"
    p =subprocess.Popen("{0} -c {1} {2}".format(ping_cmd,str(count),str(ip)), shell=True, stdout=subprocess.PIPE)
    output = p.stdout.read().strip()
    ret = re.findall(r'{0}.*ttl=\d+.*time=.*'.format(str(ip)), output, re.IGNORECASE)
    if ret:
        lat = re.search(r'time=.*s', ret[-1], re.IGNORECASE)
        return lat.group().split("time=")[-1]
    SaveLog(log_path, output)
    return False

def SSHAutoLogin(ip,username,password,cmd,filename,port=22):
    # IPV4 and IPV6
    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=ip,username=username,password=password,port=port)
        stdin,stdout,stderr=ssh.exec_command(cmd)
    except Exception,e:
        outstring = "[Exception - SSH]\n{0}".format(str(e))
        SaveLog(filename, outstring)
        print outstring
        ssh.close()
    else:
        output = stdout.read().strip()
        ssh.close()
        return output

def CheckLighttpd(ip,username,password,filename):
    cmd = "ps -ef | grep -i lighttpd | grep -v grep"
    ret = SSHAutoLogin(ip,username,password,cmd,filename)
    return ret

def doLogin(i):
    restapi='/api/session'
    if ipVers == 6:
        curlcmd = "curl -X POST -d \"username={0}&password={1}\" https://[{2}]{3} -c cookie{4} -6 -g -k 2>/dev/null".format(username, password, bmcip, restapi, i)
    else:
        curlcmd='curl -X POST -d \"username=' + username + '&password=' + password + '\" ' + '\"http://' + bmcip + restapi + '\" -c ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    print result
    if result[0] == 0:
        output=json.loads(result[1])
        global token
        if output.has_key('ok'):
            token[i]=output['CSRFToken']
            status=output['ok']
        else:
            status=1
    else:
        outstring = 'Thread is : {0}, login FAIL'.format(str(i))
        raise LoginFail(outstring)
    return status

def doLogout(i):
    logoutapi='/api/session'
    if ipVers == 6:
        curlcmd = "curl -X DELETE -H \"X-CSRFTOKEN:{0}\" https://[{1}]{2} -b cookie{3} -6 -g -k 2>/dev/null".format(token[i], bmcip, logoutapi, i)
    else:
        curlcmd='curl -X DELETE -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + logoutapi + '\" -b ./cookie'+str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    print result
    if result[0] == 0:
        output=json.loads(result[1])
        if output.has_key("ok"):
            status=output['ok']
        else:
            status = 1
    else:
        outstring = 'Thread is : {0}, logout FAIL'.format(str(i))
        raise LogoutFail(outstring)
    return status

def doLogout_retry(i, counts=3):
    logoutapi='/api/session'
    if ipVers == 6:
        curlcmd = "curl -X DELETE -H \"X-CSRFTOKEN:{0}\" https://[{1}]{2} -b cookie{3} -6 -g -k 2>/dev/null".format(token[i], bmcip, logoutapi, i)
    else:
        curlcmd='curl -X DELETE -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + logoutapi + '\" -b ./cookie'+str(i)+' 2>/dev/null'
    c = 0
    status = 1
    while c < counts:
        result = commands.getstatusoutput(curlcmd)
        if result[0] == 0:
            try:
                output = json.loads(result[1])
            except Exception:
                pass
            else:
                status = output.get("ok", 1)
        c += 1
        if status == 0:
            break
        else:
            print "[Thread {0}] Logout failed [{1}] ...".format(str(i), str(c))
    else:
        outstring = "[Thread {0}] Logout failed more than {1} times, exit ...".format(str(i), str(counts))
        SaveLog(log_path, outstring)
        print outstring
    return status

def getRestVal(i):
    """ check Webonline user number """
    """
    restapi='/api/serverinfo/fwinfo'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/sensors'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/serverinfo'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    """

    restapi='/api/serverinfo/dictnetinfo'
    if ipVers == 6:
        curlcmd = "curl -X GET -H \"X-CSRFTOKEN:{0}\" https://[{1}]{2} -b cookie{3} -6 -g -k 2>/dev/null".format(token[i], bmcip, restapi, i)
    else:
        curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    try:
        result = commands.getstatusoutput(curlcmd)
        print result
        output=json.loads(result[1])
    except Exception as e:
        outstring = "[Thread {0} Exception - Webonline]\n{1}".format(str(i), str(e))
        raise LoginFail(outstring)
    else:
        global user
        if output.has_key("Webonline"):
            print "Webonline: {0}".format(output["Webonline"])
            user.append(str(output['Webonline']))
        else:
            outstring = "[Thread {0}] Can not find key: Webonline".format(str(i))
            raise LoginFail(outstring)

    """
    restapi='/api/settings/users'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/firmware-info'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/configuration/project'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/serverstate'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/cpuusage'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/serverinfo/memusage'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/logs/event'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/configuration/runtime'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/api/chassis-status'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    restapi='/images/level.png'
    curlcmd='curl -X GET -H \"X-CSRFTOKEN:' + str(token[i]) + '\"' + ' \"http://' + bmcip + restapi + '\" -b ./cookie' + str(i)+' 2>/dev/null'
    result=commands.getstatusoutput(curlcmd)
    """

def login(i):
    try:
        lock.acquire()
        startTime = datetime.datetime.now()
        a=doLogin(i)
        tmpTime = datetime.datetime.now()
        interval = calc_interval(startTime, tmpTime)    # return string not float
        getRestVal(i)
        if a == 0:
            outstring = 'Thread is : {0}, login PASS'.format(str(i))
            timestring = "[Thread {0}] Login time : {1}s".format(str(i), str(interval))
            SaveLog(log_path, outstring)
            SaveLog(loginTime_path, timestring)
            print outstring
            print timestring
            global ok_list
            ok_list.append(str(i))
        else:
            outstring = 'Thread is : {0}, login FAIL'.format(str(i))
            timestring = "[Thread {0}] Login time : failed".format(str(i))
            SaveLog(loginTime_path, timestring)
            raise LoginFail(outstring)
    except LoginFail as e:
        SaveLog(log_path, e)
        print e
        print "[Thread {0}] Try ping {1} ...".format(str(i), bmcip)
        timeout = 30
        t = 0
        ping_start = datetime.datetime.now()
        while float(t/1000) <= timeout:
            ret = ping_test(bmcip)
            ping_tmp = datetime.datetime.now()
            t = calc_interval(ping_start, ping_tmp, flag="ms")     # return string not float
            if ret:
                outstring = "[{0}] ping time : {1}ms".format(bmcip, t)
                SaveLog(log_path, outstring)
                print outstring
                break
        else:
            current = GetNowTime()
            output = "Current time is : {0}, {1} ping fail exceeds {2}s, exit ...".format(current, bmcip, str(timeout))
            SaveLog(log_path, output)
            print output
            os._exit(1)
        ret = CheckLighttpd(bmcip, username, password, log_path)
        outstring = "Check Service lighttpd:\n[{0}]".format(ret)
        SaveLog(log_path, outstring)
        print outstring
        if not ret:
            if ret == None:     # return None: paramiko ssh command executes fail
                os._exit(2)
            output = "Service lighttpd fail, exit ..."
            SaveLog(log_path, output)
            print output
            os._exit(2)
        else:
            output = "Service lighttpd OK, next loop ..."
            SaveLog(log_path, output)
            print output
    except Exception as e:
        outstring = "[Thread {0} Exception - login]\n{1}".format(str(i), str(e))
        SaveLog(log_path, outstring)
        print outstring
    finally:
        lock.release()

def logout(i):
    if str(i) not in ok_list:
        return
    try:
        lock.acquire()
        b = doLogout(i)
        if b == 0:
            outstring = 'Thread is : {0}, logout PASS'.format(str(i))
            print outstring
            SaveLog(log_path, outstring)
        else:
            outstring = 'Thread is : {0}, logout FAIL'.format(str(i))
            raise LogoutFail(outstring)
    except LogoutFail as e:
        SaveLog(log_path, e)
        print e
        ret = doLogout_retry(i, counts=3)
        if ret == 0:
            outstring = "Re-logout successful."
            SaveLog(log_path, outstring)
            print outstring
        else:
            os._exit(1)     # Logout retry fail, exit ...
    except Exception as e:
        outstring = "[Thread {0} Exception - logout]\n{1}".format(str(i), str(e))
        SaveLog(log_path, outstring)
        print outstring
    finally:
        lock.release()

def check_mc_info(ip, username, password):
    # IPV4 and IPV6
    vers_info = ""
    cmd = "{0} -I lanplus -H {1} -U {2} -P {3} mc info".format(ipmitool, ip, username, password)
    ret = os.popen(cmd).readlines()
    for line in ret:
        if not line: continue
        m = re.search(r'Firmware Revision.*', line, re.IGNORECASE)
        if m:
            vers_info = m.group().split(":")[-1].strip()
    return vers_info

def main(counts):
    counts += 1
    for count in range(1,counts):
        global token
        token=dict()
        global user
        user=list()
        loopNum = " Loop %s " %str(count)
        print loopNum.center(50, "#")
        outstring='\nThe Login count is : %s, login begin...\n' %str(count)
        SaveLog(log_path, outstring)
        SaveLog(loginTime_path, loopNum.center(50, "#"))
        ret = ping_test(bmcip, count=3)
        if not ret:
            outstring = "IP {0} ping fail, please check BMC network ...".format(bmcip)
            SaveLog(log_path, outstring)
            print outstring
            sys.exit(1)
        ret = check_mc_info(bmcip, username, password)
        current = GetNowTime()
        if not ret:
            output = "Current time is : {0}, get BMC version fail !".format(current)
            SaveLog(log_path, output)
            print output
            # sys.exit(2)
        output = "Current time is : {0}, BMC version is {1}.".format(current, ret)
        SaveLog(log_path, output)
        print output
        for func in [login, logout]:
            threads = []
            if func == login:
                global ok_list
                ok_list = []        # Append thread flag which login successfully
            for i in range(userNum):
                t = threading.Thread(target=func, args=(str(i),))
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            # check user number
            if func == login:
                user_int = map(int, user)
                current_user = max(user_int)
                if userNum == current_user:
                    outstring = '\n%s User Check PASS.\n' %str(userNum)
                else:
                    outstring = '\n%s User Check FAIL. Current user: %s.\n' %(str(userNum), current_user)
                SaveLog(log_path, outstring)
                print outstring
            time.sleep(1)
        time.sleep(5)
        count += 1

def parse_time(filename):
    tmp_list = list()
    f = open(filename, "r")
    data = f.readlines()
    f.close()
    for line in data:
        if not line: continue
        if "#" in line: continue
        if "failed" in line: continue
        t = line.split(":")[-1].strip().split("s")[0]
        tmp_list.append(float(t))
    return min(tmp_list), max(tmp_list)

def run(flag, ip, username="admin", password="admin"):
    if flag == "before":
        sel_cmd = "%s -I lanplus -H %s -U %s -P %s sel clear" %(ipmitool, ip, username, password)
    elif flag == "after":
        sel_cmd = "%s -I lanplus -H %s -U %s -P %s sel elist" %(ipmitool, ip, username, password)
    else:
        sel_cmd = ""
    bmc_ret = os.popen(sel_cmd).read().strip()
    return bmc_ret


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-H','--host',dest='host',type='string',help='ip address for login eg: 172.16.48.10')
    parser.add_option('-U','--username',dest='username',type='string',help='username for login')
    parser.add_option('-P','--password',dest='password',type='string',help='password for login')
    parser.add_option('-C','--count',dest='count',type='int',help='test count for login, default=1000',default=1000)
    parser.add_option('-M','--max',dest='userNum',type='int',help='max user for login, default=20',default=20)
    # Select IPV4 or IPV6
    parser.add_option('-I','--ipvers',dest='ipVers',type='int',help='ip version, default=4',default=4)
    opts,args = parser.parse_args()
    current_path = os.path.dirname(os.path.abspath(__file__))
    usage = os.popen("python %s --help" %(sys.argv[0])).read().strip()
    if not opts.host or not opts.username or not opts.password:
        print "\n%s" %usage
        sys.exit(1)
    bmcip=opts.host
    username=opts.username
    password=opts.password
    counts=opts.count
    userNum=opts.userNum
    ipVers=opts.ipVers
    # define path
    ipmitool = "ipmitool"
    dirname = "log_%s" %(bmcip)
    log_dir = os.path.join(current_path, dirname)
    log_path = os.path.join(log_dir, "Multi-Thread.log")
    loginTime_path = os.path.join(log_dir, "Login_Time.log")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    else:
        del_file(log_dir)
    # main test
    ping_ret = ping_test(bmcip, count=3)
    if not ping_ret:
        output = "[{0}] Ping fail, please BMC network ...".format(bmcip)
        SaveLog(log_path, output)
        print output
        sys.exit(1)
    run("before", bmcip, username, password)
    lock = threading.Lock()
    main(counts)
    bmc_ret = run("after", bmcip, username, password)
    output = "\n[ BMC SEL info ]\n   {0}".format(bmc_ret)
    SaveLog(log_path, output)
    print output
    min_time, max_time = parse_time(loginTime_path)
    output = "\n[ Login Time ]\n"
    output += "  min: {0}s\n".format(str(min_time))
    output += "  max: {0}s\n".format(str(max_time))
    SaveLog(log_path, output)
    print output