#!/usr/bin/env bash
# __author__ = "Sam"


function show_fail_message(){
    message=$@
    echo -e "\033[1;31m ${message} \033[0m"
}

function show_pass_message(){
    message=$@
    echo -e "\033[1;32m ${message} \033[0m"
}

function usage(){
    show_fail_message "Usage: bash $0 < serial|system > < IP > < port > < log path > !"
}


which screen &> /dev/null
if [ $? -ne 0 ]; then
    show_fail_message "Please install tool: screen !"
    exit 1
fi

if [ $# -ne 4 ]; then
    usage
    exit 1
elif [ "$1" != "serial" -a "$1" != "system" ]; then
    usage
    exit 1
fi

log_type=$1
IP=$2
port=$3
log_path=$4
session_name="${IP}_${port}"
current_path=$(cd `dirname $0`; pwd)

if [ "${log_type}" == "serial" ]; then
    script="${current_path}/serial.sh"
elif [ "${log_type}" == "system" ]; then
    script="${current_path}/system.sh"
fi

# Flush process
flush_process=`screen -ls | grep serial_log_flush`
if [ -z "${flush_process}" ]; then
    flush_session="serial_log_flush"
    flush_cmd="python ${current_path}/serial_log_update.py ${log_path}"
    screen -dmS ${flush_session}
    screen -S ${flush_session} -p 0 -X stuff "${flush_cmd}\n"
fi


cmd="bash ${script} ${IP} ${port} ${log_path}"

# Create screen session to run script
screen -dmS ${session_name}
screen -S ${session_name} -p 0 -X stuff "${cmd}\n"