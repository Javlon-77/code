import scapy.all as scapy
import argparse

def scann(ip):
  arp_request = scapy.ARP(pdst=ip)
  brotecast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  arp_request_brotecast = brotecast/arp_request

  answare_list = scapy.srp(arp_request_brotecast, timeout=1, verbose=False)[0]

  print("--------------------------------------------------\nIP\t\t\tMAC_Adress\n--------------------------------------------------")
  for element in answare_list:
    print(element[1].psrc + "\t\t" + element[1].hwsrc)

parser = argparse.ArgumentParser()
parser.add_argument("-target", dest="ip", required=True)
options = parser.parse_args()

scann(options.ip)
