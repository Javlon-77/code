
import scapy.all as scapy
from datetime import datetime

def scann(ip):
    print("=" * 55)
    print(f"  NETWORK SCANNER | {datetime.now()}")
    print("=" * 55)

    try:
        print(f"\n[+] Scanning: {ip}\n")

        answered, unanswered = scapy.arping(
            ip,
            verbose=False,
            timeout=3
        )

        print("-" * 55)
        print(f"{'IP ADDRESS':<20} {'MAC ADDRESS':<25}")
        print("-" * 55)

        for sent, received in answered:
            print(f"{received.psrc:<20} {received.hwsrc:<25}")

        print("-" * 55)
        print(f"\n[+] Found devices: {len(answered)}")

    except PermissionError:
        print("[-] Run this program as Administrator or root!")

    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    scann("10.0.2.0/24")
