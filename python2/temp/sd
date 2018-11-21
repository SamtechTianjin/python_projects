#!/usr/bin/env python
# coding=utf-8

""" To convert file format via dos2unix under current path """

import os
import re

def dos2unix(dirname):
    for f in os.listdir(dirname):
        f = os.path.join(dirname, f)
        if os.path.isfile(f):
            ret = os.popen("file %s" %f).read().strip()
            if re.search(r'.*script.*ASCII text executable', ret, re.IGNORECASE) or f.endswith(".py") or f.endswith(".sh"):
                os.system("dos2unix %s" %f)
                os.system("chmod +x %s" %f)
        else:
            dos2unix(f)

if __name__ == '__main__':
    path = os.getcwd()
    print "Current path:", path
    dos2unix(path)
