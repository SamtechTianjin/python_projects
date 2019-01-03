# -*- coding:utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render_to_response, HttpResponse, HttpResponseRedirect
import models
import json
import re
from django.core.exceptions import ValidationError
from lib.sam_common import Remote, unicode_convert, run_cmd, save_data, judge_ip_location, check_process_exist
from lib.Log_args import *

# Create your views here.

def update_log(request):
    serial_add_script = os.path.join(script_path, "run.sh")
    serial_del_script = os.path.join(script_path, "end.sh")
    ret_dict = dict()
    if request.method == "POST":
        ret_dict["status"] = "FAIL"
        data = unicode_convert(request.POST.dict())
        print "request data: {0}".format(data)
        save_data(debug_log_path, "request data: {0}".format(json.dumps(data)))
        opt = re.search(r'ADD|DELETE', data.keys()[0], re.IGNORECASE).group()
        key_ip = unicode_convert("%s[IP]"%opt)
        key_port = unicode_convert("%s[Port]"%opt)
        ip = data[key_ip]
        port = data[key_port]
        ret_dict["flag"] = opt
        filename = "%s_%s.log" %(ip, port)      # The filename should be unique
        log = models.Log(ip=ip, port=port, filename=filename)
        try:
            log.full_clean()
        except ValidationError as e:
            # ret_dict["error"] = unicode_convert(e.message_dict)
            ret_dict["error"] = "Input error !"
        else:
            filter_res = models.Log.objects.filter(filename=filename)
            if opt == "ADD":
                """
                # Don't care database !!!
                if filter_res:
                    ret_dict["error"] = "[%s %s] Already monitored !" %(ip, port)
                """
                serial_cmd = "bash %s serial %s %s %s" % (serial_add_script, ip, port, log_path)
            elif opt == "DELETE":
                """
                # Don't care database !!!
                if not filter_res:
                    ret_dict["error"] = "[%s %s] Not being collected !" %(ip, port)
                """
                serial_cmd = "bash %s %s %s" % (serial_del_script, ip, port)
            else:
                serial_cmd = "false"    # return not 0
            if ret_dict.has_key("error"):
                ret_dict = unicode_convert(ret_dict)
                print "ret_dict: {0}".format(ret_dict)
                save_data(debug_log_path, "ret_dict: {0}".format(json.dumps(ret_dict)))
                return HttpResponse(json.dumps(ret_dict), content_type="application/json")
            process = "socat - TCP:{0}:{1}".format(ip, port)
            print "process: {0}".format(process)
            save_data(debug_log_path, "process: {0}".format(process))
            location = judge_ip_location(ip)
            print "location: {0}".format(location)
            save_data(debug_log_path, "location: {0}".format(location))
            ### Log server is Platform server ###
            if location == "Beijing":
                process_exist = check_process_exist(process, flag="local")
                print "process status: {0}".format(process_exist)
                save_data(debug_log_path, "process status: {0}".format(process_exist))
                if opt == "DELETE":
                    if process_exist == True:
                        ret = run_cmd(serial_cmd)
                        if ret[0] == 0:
                            ret_dict["status"] = "OK"
                            if filter_res:
                                filter_res.delete()
                        else:
                            ret_dict["error"] = "[%s %s] Stop logging FAILED !" %(ip, port)
                            save_data(debug_log_path, ret[-1])
                    elif process_exist == False:
                        ret_dict["status"] = "OK"
                        if filter_res:
                            filter_res.delete()
                    else:
                        ret_dict["status"] = "Unknown"
                        if filter_res:
                            filter_res.delete()
                elif opt == "ADD":
                    if process_exist:
                        ret_dict["status"] = "OK"
                        if not filter_res:
                            log.save()
                    else:
                        ping_ret = Remote.ping(ip)
                        if ping_ret:
                            ret = run_cmd(serial_cmd)
                            if ret[0] == 0:
                                ret_dict["status"] = "OK"
                                if not filter_res:
                                    log.save()
                            else:
                                ret_dict["error"] = "[%s %s] Log collection FAILED !" %(ip, port)
                                save_data(debug_log_path, ret[-1])
                        else:
                            ret_dict["error"] = "[%s] Connection FAIL !" %ip
            ### Log server is other server (Tianjin or Kunshan) ###
            else:
                remote_log_path, remote_add_script, remote_del_script = None,None,None
                server_ip, server_username,server_password = None,None,None
                if location == "Kunshan":
                    server_ip = KS_server_ip
                    server_username = KS_username
                    server_password = KS_password
                    remote_log_path = KS_log_path
                    remote_add_script = os.path.join(KS_script_path, "run.sh")
                    remote_del_script = os.path.join(KS_script_path, "end.sh")
                elif location == "Tianjin":
                    server_ip = TJ_server_ip
                    server_username = TJ_username
                    server_password = TJ_password
                    remote_log_path = TJ_log_path
                    remote_add_script = os.path.join(TJ_script_path, "run.sh")
                    remote_del_script = os.path.join(TJ_script_path, "end.sh")
                if server_ip:
                    ping_server_ret = Remote.ping(server_ip)
                    if ping_server_ret:
                        process_exist = check_process_exist(process, "remote", server_ip, server_username, server_password)
                        print "process status: {0}".format(process_exist)
                        save_data(debug_log_path, "process status: {0}".format(process_exist))
                        if opt == "DELETE":
                            if process_exist == True:
                                remote_serial_cmd = "bash %s %s %s" % (remote_del_script, ip, port)
                                ret = Remote.ssh_run_cmd(remote_serial_cmd, server_ip, server_username, server_password)
                                if ret[0] == 0:
                                    ret_dict["status"] = "OK"
                                    if filter_res:
                                        filter_res.delete()
                                else:
                                    ret_dict["error"] = "[%s %s] Stop logging FAILED !" % (ip, port)
                                    save_data(debug_log_path, ret[-1])
                            elif process_exist == False:
                                ret_dict["status"] = "OK"
                                if filter_res:
                                    filter_res.delete()
                            else:
                                ret_dict["status"] = "Unknown"
                                if filter_res:
                                    filter_res.delete()
                        elif opt == "ADD":
                            if process_exist:
                                ret_dict["status"] = "OK"
                                if not filter_res:
                                    log.save()
                            else:
                                ping_ret = Remote.ping(ip)
                                if ping_ret:
                                    remote_serial_cmd = "bash %s serial %s %s %s" % (remote_add_script, ip, port, remote_log_path)
                                    ret = Remote.ssh_run_cmd(remote_serial_cmd, server_ip, server_username, server_password)
                                    if ret[0] == 0:
                                        save_data(debug_log_path, str(ret[-1]))
                                        ret_dict["status"] = "OK"
                                        if not filter_res:
                                            log.save()
                                    else:
                                        ret_dict["error"] = "[%s %s] Log collection FAILED !" % (ip, port)
                                        save_data(debug_log_path, ret[-1])
                                else:
                                    ret_dict["error"] = "[%s] Connection FAIL !" %ip
                    else:
                        ret_dict["error"] = "[%s] Connection FAIL !" %server_ip
                else:
                    ret_dict["error"] = "[%s] Unknown location !" %ip
        ret_dict = unicode_convert(ret_dict)
        print "ret_dict: {0}".format(ret_dict)
        save_data(debug_log_path, "ret_dict: {0}".format(json.dumps(ret_dict)))
        return HttpResponse(json.dumps(ret_dict), content_type="application/json")
    return render_to_response("Equipment/LogServer.html")