# -*- coding:utf-8 -*-

import paramiko

def unicode_convert(data, code="utf-8"):
    if isinstance(data, list):
        return [unicode_convert(item) for item in data]
    elif isinstance(data, dict):
        return {unicode_convert(key): unicode_convert(value) for key, value in data.items()}
    elif isinstance(data, unicode):
        return data.encode(encoding=code)
    else:
        return data

def ssh_run_cmd(cmd, ip, username, password, port=22, timeout=60):
        output, error, e = None, None, None
        paramiko.util.log_to_file("paramiko.log")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, port=port, username=username, password=password, timeout=timeout)
            stdin, stdout, stderr = client.exec_command(cmd)
        except Exception as e:
            pass
        else:
            output = stdout.read().strip()
            error = stderr.read().strip()
        finally:
            client.close()
        if e:
            return 2, e
        if error:
            return 1, error
        return 0, output