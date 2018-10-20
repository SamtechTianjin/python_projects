Switch Test Program

1. Please modify "config.txt" before test, and the following items may need to change:
tty=/dev/ttyUSB0    <--- TTY of usb-rs232 connection cable is ttyUSB0. TTY of serial port is ttyS0.

2. Install Pyserial
    tar -zxvf pyserial-3.0.1.tar.gz
    cd pyserial...
    python setup.py install

3. 修改server_config.txt文件，依次填入Bond_IP,Dedicated_LAN_port,Shared_LAN_port,Mode
4. 运行python switch_test.py