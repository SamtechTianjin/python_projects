# -*- coding:utf-8 -*-
__author__ = "Sam"

"""
统计执行所在目录的python|shell代码行数
"""

import os


def calculateLineNumber(filename):
    count = 0
    with open(filename,"r") as f:
        while True:
            content = f.readline()
            if content:
                if content.strip() and not content.startswith("#"):
                    count += 1
            else:
                """ 注意只有当结尾时才会break 空行会包含换行符 """
                break
    return count

def codeStatistics(path):
    global count
    for item in os.listdir(path):
        subPath = os.path.join(path,item)
        if os.path.isfile(subPath):
            if subPath.endswith("py") or subPath.endswith("sh") or subPath.endswith("expect"):
                tempCount = calculateLineNumber(subPath)
                count += tempCount
                print(" {0}\t{1}".format(subPath,tempCount))
        else:
            codeStatistics(subPath)



if __name__ == '__main__':
    path = os.getcwd()
    print("\nCurrent path: {0}\n".format(path))
    count = 0
    codeStatistics(path)
    print("\nCode line number: {0}".format(count))

