# -*- coding:utf-8 -*-

###################### 获取测试镜像参数 ######################
# CMM Firmware Release Server
IMAGE_SERVER_IP = "10.0.22.99"
IMAGE_SERVER_USERNAME = "testteam"
IMAGE_SERVER_PASSWORD = "111111"
"""
# IMAGE_PATH = "/home/CMMBuild/KLS/Release"
# IMAGE_PATH = "/home/CMMBuild/KLS/xxxx-xx-xx-xx-xx-xx/Project/SugonBase/development/Build/output/*.ima"
镜像路径中的日期会每天更新 镜像名称不确定 但是以ima为后缀
TEMP_PATH是/home/CMMBuild/KLS/ 需要到改目录下去得到日期目录的名称 从而获得镜像目录
"""
TEMP_PATH = "/home/CMMBuild/KLS/"


##################### 测试请修改以下参数 #####################
# CMM 测试参数
IP = "10.0.22.234"
USERNAME = "admin"
PASSWORD = "admin"
LAN = 8
PSU_NUM = 4
SWITCH_NUM = 2
FAN_NUM = 5
NODE_NUM = 8
CPU_NUM = 2
CHANNEL_NUM = 6
DIMM_NUM_PER_CHANNEL = 2
FIRMWARE_UPDATE_TIME = 10800
COLD_RESET_TIME = 10800



