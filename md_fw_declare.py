from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
from random import randint
from netaddr import *
import binascii
import sys
import signal
from threading import Thread
from sqlalchemy import false
from scapy.layers.l2 import Dot1Q
# Interface
IFACE = "Ethernet"
# Number of threads used
PKT_COUNT = 5
# Scan Ports
FROM_PORT = 1
TO_PORT = 65536
# MAC Address
SRC_MAC = "2C:58:B9:8B:4C:6A"
DST_MAC = "D8:3A:DD:E5:31:B7" #Board
INVALID_SRC_MAC = "2C:58:B9:8B:4C:6F" #Invalid MAC
# VLAN ID
VLAN_ID = 5
# IPv6s
INVALID_DST_IPv6 = "fe80::da3a:ddff:fee5:ffff" #Invalid IPv6
INVALID_SRC_IPv6 = "fe80::a26d:40be:1318:ffff" #Invalid IPv6
VALID_SRC_IPv6 = "fe80::a26d:40be:1318:c596"
VALID_DST_IPv6 = "fe80::da3a:ddff:fee5:31b7"
VALID_DST_Multicast = "ff02::1"
INVALID_DST_Multicast = "ff02::2"
# Ports
VALID_SPORT = 13344
VALID_DPORT = 13344
INVALID_DPORT = 13456
INVALID_SPORT = 13456
RANGE = (1000, 65535)
pro_type = TCP
# Layers
dot1q = Dot1Q(vlan=VLAN_ID)
# Payload
payload_default ="Default"
PKT_Default_Receive = Ether()/dot1q/IPv6(src=VALID_SRC_IPv6,dst=VALID_DST_IPv6)/pro_type(sport=VALID_SPORT, dport=VALID_DPORT)/payload_default
PKT_Default_Send = Ether(dst=SRC_MAC,src=DST_MAC)/dot1q/IPv6(src=VALID_DST_IPv6,dst=VALID_SRC_IPv6)/pro_type(sport=VALID_DPORT, dport=VALID_SPORT)/payload_default
