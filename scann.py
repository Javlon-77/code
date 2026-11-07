import scapy.all as scapy
def scann(ip):
        scapy.arping(ip)

scann("10.0.2.2/24")
