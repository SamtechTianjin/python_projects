"""
参数说明
1. 测试需要将bmc1.ima和bmc2.ima放于当前目录下,bmc1.ima对应highfw, bmc2.ima对应lowfw
2. BMC_IP为BMC测试IP
3. 如果测试ShareLAN,需要将test_SharedLan设置为1,否则设置为0即可
4. dedicate_lan为DedicateLAN IP,测试ShareLAN时必须填写
5. Count为BMC刷新次数
"""

BMC_IP=['10.2.57.237',]
highfw='3.50'
lowfw='3.49'
Count=100
dedicate_lan="10.2.57.101"
test_SharedLan=1
