#!/usr/bin/env python
#=============================Sugon test BMC NCSI Switch=================================
# Sugon Modified version v1.0
# Description:script will shutdown and up into dedicatelan and sharelan repeatedly ,and ping Bond IP and report link time (ncsi test)
# USAGE: python switch_test.py  <-d dedicatelan > < -s sharelan > < -i bond ip > < -t run time >
# AUTHOR: Yanshupeng
# CREATED: 04/15/2017
#==============================================================================================
from sugonSIT.config_handler import ConfigHandler
from sugonSIT.debugport import DebugPort
from sugonSIT.fs import *
# import argparse
import time
import os
# import re
import subprocess
import threading
import time



PASS_BANNER = """
########     ###     ######   ######     #### ####
##     ##   ## ##   ##    ## ##    ##    #### ####
##     ##  ##   ##  ##       ##          #### ####
########  ##     ##  ######   ######      ##   ##
##        #########       ##       ##
##        ##     ## ##    ## ##    ##    #### ####
##        ##     ##  ######   ######     #### ####
"""

FAIL_BANNER = """
########    ###    #### ##          #### ####
##         ## ##    ##  ##          #### ####
##        ##   ##   ##  ##          #### ####
######   ##     ##  ##  ##           ##   ##
##       #########  ##  ##
##       ##     ##  ##  ##          #### ####
##       ##     ## #### ########    #### ####
"""

#==============================================================================================
#The function is showing pass and fail messages
#==============================================================================================
def print_green(msg):
    print '\033[32;1m%s\033[0m'%(msg)

def print_red(msg):
    print '\033[31;1m%s\033[0m'%(msg)

#==============================================================================================
#The function is check switch Authority  
#==============================================================================================
# def check_prompt():
    # while True:
    #     dp1.Send('')
    #     recv = dp1.Recv()
    #     print recv[0]
    #     if recv[0] == 'Ruijie>':
    #         print '- Enter to Privilege mode : -'
    #         dp1.Send('enable')
    #         continue
    #     elif recv[0] == 'Ruijie#':
    #         print '- Current is Privilege mode : -'
    #         output= '---Current Switch is Privilege mode ---'
    #         with open("log/NCSI_Switch.log", "a") as text_file:
    #             text_file.write(output)
    #             text_file.write('\n')
    #         return 0
    #     elif recv[0] == 'Ruijie(config)#':
    #         dp1.Send('exit')
    #     else:
    #         dp1.Send('enable')
    #         continue
def check_prompt():
    # Enter configure mode #
    while True:
        dp1.Send("")
        recv = dp1.Recv()
        # print recv
        if recv[-1] == "Ruijie>":
            dp1.Send("enable")
        elif recv[-1] == "Password:":
            dp1.Send("ruijie")  # password is ruijie
        elif recv[-1] == "Ruijie#":
            dp1.Send("configure")
        elif recv[-1] == "Ruijie(config)#":
            print "- Enter configure mode -"
            break
        elif recv[-1].startswith("Ruijie(config-if-GigabitEthernet"):
            dp1.Send("exit")
        else:
            dp1.Send("exit")
        time.sleep(1)

#==============================================================================================
#The function is shutdown and up console in switch   
#==============================================================================================
def login_switch(bond_ip, D_port, S_port, mode, log_file):
    lock.acquire()
    count = 0
    print '- [%s] Enter switch and Begin shutdown/up Port -...' %bond_ip
    cmd_int_a = 'interface gigabitEthernet 0/' + str(D_port)
    if mode == 'L' :
        cmd_int_b = 'interface gigabitEthernet 0/' + str(S_port)
    elif mode == 'H' :
        cmd_int_b = 'interface TenGigabitEthernet 0/' + str(S_port)
    else :
        cmd_int_b = ""
        print_red("[%s] Please input mode is ..........H or L" %bond_ip)
        # sys.exit(1)
    current_time = int(time.time())
    end_time= int(current_time) + int(times)
    # ping_cmd='ping -c 5 '+str(bond_ip)+' >>network_begin.log'
    # ping_cmd_2='ping -c 20 '+str(bond_ip)+' >>network_sharelan.log'
    # ping_cmd_3='ping -c 20 '+str(bond_ip)+' >>network_Dedicatelan.log'
    ping_cmd='ping -c 5 '+str(bond_ip)+' >>./log/network_begin_%s.log' %bond_ip
    ping_cmd_2='ping -c 20 '+str(bond_ip)+' >>./log/network_sharelan_%s.log' %bond_ip
    ping_cmd_3='ping -c 20 '+str(bond_ip)+' >>./log/network_Dedicatelan_%s.log' %bond_ip
    current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
    output = 'Current time is :' + str(current) + "," + "Dedicate lan and Share lan to begin to off/on [%s]" %bond_ip
    # with open("log/NCSI_Switch.log", "a") as text_file:
    with open(log_file, "a") as text_file:
        text_file.write(output)
        text_file.write('\n')
    lock.release()
    time.sleep(5)
    # Start Stress Test #
    while current_time < end_time :
        try:
            lock.acquire()      ############# lock acquire #############
            # dp1.Send('enable')
            # dp1.Send('configure')
            print '- [%s] Begin to Dedicatelan and Sharelan all on - ' %bond_ip
            check_prompt()
            dp1.Send(cmd_int_a)     # Dedicated LAN
            dp1.Send('no shutdown')
            time.sleep(1)
            dp1.Send("")
            dp1.Send('exit')
            check_prompt()
            dp1.Send(cmd_int_b)     # Shared LAN
            dp1.Send('no shutdown')
            time.sleep(1)
            dp1.Send("")
            dp1.Send('exit')
            print '- [%s] Dedicatelan and Sharelan all on -' %bond_ip
            current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
            output = 'Current time is :' + str(current) + "," + "- Dedicatelan and Sharelan all on - [%s]" %bond_ip
            # with open("log/NCSI_Switch.log", "a") as text_file:
            with open(log_file, "a") as text_file:
                text_file.write(output)
                text_file.write('\n')
        except Exception as e:
            print "[%s] %s" %(bond_ip, str(e))
        finally:
            lock.release()      ############# lock release #############
        timeout_5s = 1
        for i in range(timeout_5s):
            print'"%s secs...[%s]"'% (5*(timeout_5s - i), bond_ip)
            time.sleep(5)
        print '- [%s] Begin to ping Bond IP - ' %bond_ip
        # with open("log/NCSI_Switch.log", "a") as text_file:
        with open(log_file, "a") as text_file:
            output = '- [%s] Begin to ping Bond IP - ' %bond_ip
            text_file.write(output)
            text_file.write('\n')
        subprocess.Popen(ping_cmd,shell=True)
        time.sleep(5)
        a=subprocess.Popen("cat ./log/network_begin_%s.log | grep -i '5 packets transmitted, 0 received' >> ./log/pingerror_%s" %(bond_ip, bond_ip),shell=True)
        if  a.wait() == 0 :
            print '[%s] BMC Bond ip unreached' %bond_ip
            # with open("log/NCSI_Switch.log", "a") as text_file:
            with open(log_file, "a") as text_file:
                current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
                output = 'Current time is : ' + str(current) +  ' - ping Bond IP unreached - [%s]' %bond_ip
                text_file.write(output)
                text_file.write('\n')
            # print_red(FAIL_BANNER)
            # sys.exit(1)
        # global count
        try:
            lock.acquire()      ############# lock acquire #############
            count+=1
            print '- [%s] Begin to shut down Dedicatelan - ' %bond_ip
            check_prompt()
            dp1.Send(cmd_int_a)
            dp1.Send('shutdown')
            time.sleep(1)
            dp1.Send("")
            dp1.Send('exit')
            print '- [%s] Dedicatelan current is off -' %bond_ip
            sharelan_log='- [%s] Begin to shut down Dedicatelan but sharelan is on : %s' %(bond_ip,str(count))
            file_object = open('./log/network_sharelan_%s.log'%bond_ip, 'a+')
            file_object.write(sharelan_log)
            file_object.write('\n')
            file_object.close( )
            with open(log_file, "a") as text_file:
                current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
                output = 'Current time is : ' + str(current) + ',' + str(sharelan_log)
                text_file.write(output)
                text_file.write('\n')
            subprocess.Popen(ping_cmd_2,shell=True)
        except Exception as e:
            print "[%s] %s" %(bond_ip, str(e))
        finally:
            lock.release()      ############# lock release #############
        for i in range(timeout_5s):
            print'"%s secs...[%s]"'% (18*(timeout_5s - i), bond_ip)
            time.sleep(18)
        try:
            lock.acquire()      ############# lock acquire #############
            print '- [%s] Begin to shut down Sharelan and Open Dedicatelan -' %bond_ip
            check_prompt()
            dp1.Send(cmd_int_b)
            dp1.Send('shutdown')
            time.sleep(1)
            dp1.Send("")
            dp1.Send('exit')
            check_prompt()
            dp1.Send(cmd_int_a)
            dp1.Send('no shutdown')
            time.sleep(1)
            dp1.Send("")
            dp1.Send('exit')
            print '- [%s] Dedicatelan current is on ,Share lan is off -' %bond_ip
            Dedicatelan_log='- [%s] Begin to shut down sharelan but Dedicatelan is on : %s'%(bond_ip, str(count))
            file_object = open('./log/network_Dedicatelan_%s.log'%bond_ip, 'a+')
            file_object.write(Dedicatelan_log)
            file_object.write('\n')
            file_object.close( )
            with open(log_file, "a") as text_file:
                current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
                output = 'Current time is : ' + str(current) + ',' + str(Dedicatelan_log)
                text_file.write(output)
                text_file.write('\n')
                text_file.close()
            subprocess.Popen(ping_cmd_3,shell=True)
        except Exception as e:
            print "[%s] %s" %(bond_ip, str(e))
        finally:
            lock.release()      ############# lock release #############
        for i in range(timeout_5s):
            print'"%s secs...[%s]"'% (18*(timeout_5s - i), bond_ip)
            time.sleep(18)
        current_time=int(time.time())


def for_test():
    for num in range(9,12):
        check_prompt()
        cmd_int_a = 'interface gigabitEthernet 0/%s' %str(num)
        dp1.Send(cmd_int_a)
        dp1.Send("shutdown")
        # time.sleep(1)
        print dp1.Recv()
        check_prompt()
        dp1.Send(cmd_int_a)
        dp1.Send("no shutdown")
        # time.sleep(1)
        print dp1.Recv()



#====================================MAIN==========================================
print '\033[1;32;40m'
print '*' * 70
print '***********************- BMC NCSI STRESS TEST -***********************'
print '***Please input -d (Dedicatelan num) -s (sharelan num) -i (bondip)-***'
print '****************-m (mode ,defalut is low speed) -r (run time) -*******'
print '*' * 70
print '\033[0m'

# opts = argparse.ArgumentParser(description = "BMC NCSI switch test Tool, By Sugon SIT, Version: 1.0")
# opts.add_argument('-v', '--version', action = 'version', version = "1.0", help = "Show Tool Version")
# opts.add_argument('-d', '--dedicatelan', required = False, default = "", help = "Dedicatelan Number")
# opts.add_argument('-s', '--share', required = False, default = "", help = "Sharelan Number")
# opts.add_argument('-c', '--Com', required = False, default = "COM3", help = "COM Port")
# opts.add_argument('-t','--time',required = False, default = "172800", help = "Run Time")
# opts.add_argument('-i','--bondip',required = False, default = "",help = "Bond IP")
# opts.add_argument('-m','--mode',required = False,default = "L",help = " Mode ")
# args = opts.parse_args()
# # dedicatelan = args.dedicatelan
# dedicatelans = [i.strip() for i in args.dedicatelan.split(",")]     # dedicated lan port list
# # sharelan = args.share
# sharelans = [i.strip() for i in args.share.split(",")]      # shared lan port list
# COM_PORT = args.Com
# times = int(args.time)
# # bondip = args.bondip
# bondips = [i.strip() for i in args.bondip.split(",")]       # bond ip list
# mode = args.mode
# # if bondip == "" or sharelan == "" or dedicatelan == "" or mode == "" :
# #     print '\033[1;31;40m ***Please input -d (Dedicatelan num) -s (sharelan num) -i (bondip) -m (mode)-***\033[0m'
# #     sys.exit(1)


# Test time
times = 43200

# MultiThreads run
threads = []
lock = threading.Lock()

current_path = os.path.dirname(os.path.abspath(__file__))
# print current_path
os.chdir(current_path)
if not os.path.exists("log"):
    os.makedirs("log")

# Read config from file
server_config = []
f = open("server_config.txt", "r")
for line in f.readlines():
    if not line: continue
    if line.startswith("#"): continue
    tmp = [i.strip() for i in line.split()]
    log_file = os.path.join(current_path, "log", "NCSI_Switch_%s.log"%tmp[0])
    tmp_tuple = (tmp[0], tmp[1], tmp[2], tmp[3], log_file)
    server_config.append(tmp_tuple)
f.close()
for i in server_config:
    print i

# count=0

ch = ConfigHandler('config.txt','=')
tty = ch.GetValue('tty')
dp1 = DebugPort(tty, logFile='./log/console.log')

check_prompt()  # Enter config mode (configure)

current=time.strftime('%m-%d,%H:%M:%S',time.localtime(time.time()))
output = 'Current time is :' + str(current) + "," + "Begin test NCSI Switch "
for conf in server_config:
    # conf = (bond_ip, D_port, S_port, mode, log_file)
    with open(conf[-1], "w") as text_file:
        text_file.write(output)
        text_file.write('\n')
        conf_info = 'dedicate lan num is : ' + conf[1] + "," + 'Share lan num is : ' + conf[2] + "," + 'Bond IP is : ' + conf[0]+ "," + 'Mode is : ' + conf[3]
        text_file.write(conf_info)
        text_file.write("\n")
        t = threading.Thread(target=login_switch, args=conf)
        t.start()
        threads.append(t)

for thread in threads:
    thread.join()

print_green(PASS_BANNER)