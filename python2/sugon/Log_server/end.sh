#!/usr/bin/env bash
# __author__ = "Sam"


IP=$1
port=$2
session_name="${IP}_${port}"

screen -S ${session_name} -X quit
