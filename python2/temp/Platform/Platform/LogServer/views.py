# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render,render_to_response,HttpResponse

import json
from libs.sam_common import unicode_convert,ssh_run_cmd

# Create your views here.

def index(request):
    if request.method == "POST":
        data = request.POST.dict()
        if data:
            data = unicode_convert(data)
        name = data.get("name")
        cmd = "cd /log/{0}; ls -lh".format(name)
        log_list = []
        log_server = "192.168.116.129"
        status,output = ssh_run_cmd(cmd,log_server,"root","111111")
        for line in output.splitlines():
            if line.startswith("total"):
                continue
            temp = line.split()
            size = temp[4]
            name = temp[-1]
            log_list.append([name,size])
        ret_dict = unicode_convert({"log_list": log_list})
        return HttpResponse(json.dumps(ret_dict), content_type="application/json")
    else:
        return render_to_response("LogServer.html")
