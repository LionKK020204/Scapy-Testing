from md_fw_declare import *
from md_fw_menu import *
PKT_Default_Receive[IPv6].src=INVALID_SRC_IPv6
def print_infor():
    try:
        global PKT_Default_Receive
        print("\n----------Packet-information-------------")
        PKT_Default_Receive.show()
    except Exception as ex:
        print("Error:"+ex)
#16.1.13.4 Undefined target IPv6 address
def send_packet():
    global PKT_Default_Receive
    try:
        PKT_Default_Receive.show()
        sendp(PKT_Default_Receive, iface=IFACE)
    except:
        print("Error: Please Connect Ethernet...")
def main():
    cloop=True
    while cloop:
        try:
            choice = print_menu()
            if int(choice) ==1:
                print_infor()
            elif int(choice) ==2:
                send_packet()
            elif int(choice) ==0:
                cloop=False
        except KeyboardInterrupt:
            print ('\nThanks! See you later!\n\n')
    cloop=False
if __name__ == '__main__':
    main()
#Check Log to show result
# tail /data/log_data/ulogd/full.log
# Sep 20 20:04:36 Input DROP IN=eth0.5 OUT=
# MAC='ff:ff:ff:ff:ff:ff:xx:xx:xx:xx:xx:xx:xx:xx:xx:00:00:00 SRC=fd22:xxxx:xxx:3::10'
# DST='fd22:xxxx:xx:5::14 LEN=67 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=TCP SPT=13344'
# DPT=13344 
# SEQ=0 
# ACK=0 
# WINDOW=8192 
# SYN 
# URGP=0 
# MARK=0