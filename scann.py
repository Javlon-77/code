
import scapy.all as scapy
import ipaddress
import csv
import os
import time
from datetime import datetime
from pathlib import Path

# ==========================================
#          PRO NETWORK SCANNER
# ==========================================

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN = Fore.GREEN
    RED = Fore.RED
    CYAN = Fore.CYAN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = RED = CYAN = YELLOW = BLUE = RESET = ""

REPORT_DIR = Path("scanner_reports")
REPORT_DIR.mkdir(exist_ok=True)

last_results = []


def line():
    print(CYAN + "=" * 65 + RESET)


def banner():
    os.system("cls" if os.name == "nt" else "clear")

    line()
    print(GREEN + r"""
     _   _ _____ _____ _    _  ____  _____  _  __
    | \ | | ____|_   _| |  | |/ ___|| ____|| |/ /
    |  \| |  _|   | | | |  | | |    |  _|  | ' /
    | |\  | |___  | | | |__| | |___ | |___ | . \
    |_| \_|_____| |_|  \____/ \____||_____||_|\_\
    """ + RESET)
    print(YELLOW + "              PROFESSIONAL NETWORK SCANNER" + RESET)
    print("                     Version 2.0")
    line()


def get_vendor(mac):
    try:
        return scapy.conf.manufdb._get_manuf(mac) or "Unknown"
    except Exception:
        return "Unknown"


def validate_ip(ip):
    try:
        network = ipaddress.ip_network(ip, strict=False)

        if network.num_addresses > 4096:
            print(RED + "[-] Network is too large! Maximum: 4096 addresses.")
            return None

        return network

    except ValueError:
        print(RED + "[-] Invalid IP address or network!")
        return None


def save_csv(results):
    filename = REPORT_DIR / (
        "scan_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv"
    )

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["IP", "MAC", "VENDOR"]
        )
        writer.writeheader()
        writer.writerows(results)

    return filename


def save_txt(results, network, duration):
    filename = REPORT_DIR / (
        "scan_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
    )

    with open(filename, "w", encoding="utf-8") as file:
        file.write("PRO NETWORK SCANNER REPORT\n")
        file.write("=" * 50 + "\n")
        file.write(f"Network: {network}\n")
        file.write(f"Date: {datetime.now()}\n")
        file.write(f"Duration: {duration:.2f} seconds\n")
        file.write(f"Devices found: {len(results)}\n")
        file.write("=" * 50 + "\n\n")

        for device in results:
            file.write(f"IP: {device['IP']}\n")
            file.write(f"MAC: {device['MAC']}\n")
            file.write(f"Vendor: {device['VENDOR']}\n")
            file.write("-" * 50 + "\n")

    return filename


def scan_network(ip):
    global last_results

    network = validate_ip(ip)

    if network is None:
        return

    print()
    line()
    print(YELLOW + f" TARGET NETWORK: {network}" + RESET)
    print(YELLOW + f" TOTAL ADDRESSES: {network.num_addresses}" + RESET)
    line()

    print(CYAN + "\n[+] Starting network scan..." + RESET)

    start_time = time.time()

    try:
        answered, unanswered = scapy.arping(
            str(network),
            timeout=3,
            verbose=False
        )

        results = []
        seen = set()

        print()
        line()
        print(
            GREEN +
            f"{'IP ADDRESS':<20}{'MAC ADDRESS':<25}{'VENDOR'}"
            + RESET
        )
        line()

        for sent, received in answered:
            ip_address = received.psrc
            mac_address = received.hwsrc.lower()

            if mac_address in seen:
                continue

            seen.add(mac_address)

            vendor = get_vendor(mac_address)

            device = {
                "IP": ip_address,
                "MAC": mac_address,
                "VENDOR": vendor
            }

            results.append(device)

            print(
                GREEN +
                f"{ip_address:<20}{mac_address:<25}{vendor}"
                + RESET
            )

        duration = time.time() - start_time
        last_results = results

        print()
        line()
        print(GREEN + "[+] SCAN COMPLETED!" + RESET)
        print(f"[+] Devices found: {len(results)}")
        print(f"[+] No response: {len(unanswered)}")
        print(f"[+] Scan time: {duration:.2f} seconds")

        if results:
            csv_file = save_csv(results)
            txt_file = save_txt(results, network, duration)

            print()
            print(CYAN + "[+] REPORTS SAVED:" + RESET)
            print(f"[+] CSV: {csv_file}")
            print(f"[+] TXT: {txt_file}")
        else:
            print(YELLOW + "[!] No devices found." + RESET)

        line()

    except PermissionError:
        print(RED + "[-] Administrator/root permissions required!" + RESET)

    except Exception as error:
        print(RED + f"[-] ERROR: {error}" + RESET)


def show_last_results():
    line()
    print(YELLOW + "          LAST SCAN RESULTS" + RESET)
    line()

    if not last_results:
        print(RED + "[-] No scan results available." + RESET)
        return

    print(f"{'IP ADDRESS':<20}{'MAC ADDRESS':<25}{'VENDOR'}")
    line()

    for device in last_results:
        print(
            f"{device['IP']:<20}"
            f"{device['MAC']:<25}"
            f"{device['VENDOR']}"
        )

    line()
    print(f"Total devices: {len(last_results)}")


def show_statistics():
    line()
    print(YELLOW + "             STATISTICS" + RESET)
    line()

    total = len(last_results)

    print(f"[+] Total devices: {total}")

    vendors = {}

    for device in last_results:
        vendor = device["VENDOR"]
        vendors[vendor] = vendors.get(vendor, 0) + 1

    print("\n[+] Vendor statistics:")

    for vendor, count in vendors.items():
        print(f"    {vendor}: {count}")

    line()


def main():
    while True:
        banner()

        print(GREEN + "[1]" + RESET + " Start Network Scan")
        print(GREEN + "[2]" + RESET + " Show Last Results")
        print(GREEN + "[3]" + RESET + " Show Statistics")
        print(GREEN + "[4]" + RESET + " Exit")

        line()

        choice = input(YELLOW + "\nSelect option: " + RESET)

        if choice == "1":
            ip = input("\nEnter network IP (e.g. 10.0.2.0/24): ")
            scan_network(ip)

        elif choice == "2":
            show_last_results()

        elif choice == "3":
            if last_results:
                show_statistics()
            else:
                print(RED + "[-] Scan a network first!" + RESET)

        elif choice == "4":
            print(GREEN + "\n[+] Scanner closed. Goodbye!" + RESET)
            break

        else:
            print(RED + "[-] Invalid option!" + RESET)

        input("\nPress ENTER to continue...")


if __name__ == "__main__":
    main()
