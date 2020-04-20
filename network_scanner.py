import scapy.all as scapy
import argparse


class NetworkScanner:

    @staticmethod
    def get_arguments():
        parser_obj = argparse.ArgumentParser()
        parser_obj.add_argument("-t", "--target_ip", dest="target", help="TARGET IP/IP RANGE")
        values = parser_obj.parse_args()
        if not values.target:
            parser_obj.error("PLEASE PROVIDE TARGET IP/IP RANGE")
        return values

    @staticmethod
    def scan_dev(ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        client_list = []
        for e in answered_list:
            d = {"ip": e[1].psrc, "mac": e[1].hwsrc}
            client_list.append(d)
        return client_list

    @staticmethod
    def print_clients(client_list):
        print("IP\t\t\tMAC ADDRESS\n-----------------------------------------")
        for element in client_list:
            print(element["ip"] + "\t\t" + element["mac"])

    def execute_network_scanner(self):
        ip_target = self.get_arguments()
        self.print_clients(self.scan_dev(ip_target.target))












