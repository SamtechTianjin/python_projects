# -*- coding:utf-8 -*-

import os

# Define some common arguments
APP_Log_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
debug_log_path = os.path.join(APP_Log_path, "log", "debug.log")
TJ_username = "root"
KS_username = "root"
TJ_password = "111111"
KS_password = "abcdef@123"
# Beijing
script_path = os.path.join(APP_Log_path, "lib", "shell")
log_path = "/log"
# Tianjin
TJ_server_ip = "10.2.34.137"
TJ_script_path = "/root/LogServerScripts/"
TJ_log_path = "/log"
# Kunshan
KS_server_ip = "10.8.27.211"
KS_script_path = "/root/LogServerScripts/"
KS_log_path = "/home/log"


if __name__ == '__main__':
    print APP_Log_path