#!/usr/bin/env python
# -*- coding:utf-8 -*-

""" Should install matplotlib module """

import matplotlib
matplotlib.use("Agg")
import sys
import matplotlib.pyplot as plt
import re
import collections

def parse_log(log):
    res = collections.OrderedDict()
    f = open(log, "r")
    data = f.readlines()
    f.close()
    for line in data:
        if not line: continue
        if "FAN" not in line: continue
        if not re.match(r'FAN\d+_Speed.*\d+.*RPM.*ok', line, re.IGNORECASE): continue
        tmp_list = line.split()
        fan_name = tmp_list[0].split("_")[0]
        speed = int(tmp_list[2])
        if not res.has_key(fan_name):
            res[fan_name] = list()
        res[fan_name].append(speed)
    return res

def fig(res, log):
    fig = plt.figure(figsize=(12,9))
    fan_num = len(res.keys())
    if fan_num == 0:
        return False
    elif fan_num <= 4:
        flag = 22
    elif fan_num <= 6:
        flag = 23
    elif fan_num <= 9:
        flag = 33
    else:
        flag = 44
    for i in range(fan_num):
        fan_name = res.keys()[i]
        speed_list = res.values()[i]
        check_index = range(1, len(speed_list)+1)
        i += 1
        tmp = "%s%s" %(flag, i)
        tmp = int(tmp)
        ax = fig.add_subplot(tmp)
        ax.patch.set_facecolor("white")
        ax.plot(check_index, speed_list, color="green")
        ax.set_title(label=fan_name, fontsize=12, color="r", pad=float(-12))
    plt.savefig(log.split(".log")[0], dpi=200)

if __name__ == '__main__':
    log = sys.argv[1]
    res = parse_log(log)
    fig(res, log)