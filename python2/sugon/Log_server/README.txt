Log Server
    使用socat命令进行串口日志监控，由于网络问题需要本地搭建log server
    串口日志将会以日期建立目录存放，日志文件名格式: ${IP}_${port}.log
    北京: 10.0.21.63  /log        (脚本目录: /var/www/html/Platform/Log/lib/shell/)
    昆山: 10.8.27.211 /home/log   (脚本目录: /root/LogServerScripts/)
    天津: 10.2.34.225 /log        (脚本目录: /root/LogServerScripts/)

0. 准备
    安装socat和screen
        yum install socat
        yum install screen
1. 开启监控
    Usage: bash run.sh serial < IP > < port > < log path >
    eg: bash run.sh serial 10.2.63.10 5000 /home/log
    注意: < log path > 是日志存放的主目录
2. 停止监控
    Usage: bash end.sh < IP > < port >
    eg: bash end.sh 10.2.63.10 5000
3. 刷新日志
    使用socat命令间歇性会出现无日志输出情况，现在采取重启socat操作予以解决
    脚本中定义每30s检查日志一次，若日志超过1分钟未更新则重启socat
    Usage: python serial_log_update.py < log path >
    注意: 需要放置在后台执行，可以开启一个screen session来执行该刷新脚本