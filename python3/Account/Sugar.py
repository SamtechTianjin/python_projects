# -*- coding:utf-8 -*-

import datetime
import time

# time_format = "%Y-%m-%d %H:%M:%S"
# start = "2019-10-23 19:24:31"
# end = "2020-02-28 01:11:11"
#
# delta = datetime.datetime.strptime(end,time_format)-datetime.datetime.strptime(start,time_format)
# days = delta.days
# secs = delta.seconds
#
# start = [time.strptime(start,time_format)[item] for item in range(6)]
# end = [time.strptime(end,time_format)[item] for item in range(6)]
#
# result = ""
# year = days//365
# month = days%365//30
# day = days%365%30
# hour = secs//3600
# mins = secs%3600//60
# sec = secs%3600%60
# data = [year,month,day,hour,mins,sec]
# unit = ["年","月","日","时","分","秒"]
# for index in range(6):
#     result += "{0}{1}".format(data[index],unit[index])
# print(result)


text = """
{0:>10}
{1:>10}
{2:>10}
""".format("user","password","email")
print(text)
