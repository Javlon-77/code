import requests
import socket
import dns.resolver
import ssl
import re
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

GREEN = Fore.GREEN
CYAN = Fore.CYAN
RED = Fore.RED
YELLOW = Fore.YELLOW

REPORT = "osint_report.txt"


def banner():
    os.system("clear")
    print(CYAN + """
 ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║   ██║███████╗██║██╔██╗ ██║   ██║
██║   ██║╚════██║██║██║╚██╗██║   ██║
╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝

        OSINT MASTER v1.0
    OPEN SOURCE INTELLIGENCE
""" + GREEN)


def save(title, data):
    with open(REPORT, "a", encoding="utf-8") as file:
        file.write("\n" + "=" * 45 + "\n")
        file.write(title + "\n")
        file.write(str(data) + "\n")

    print(GREEN + "[+] Natija saqlandi: " + REPORT)


def check_ip():
    ip = input("IP manzil: ").strip()

    print(YELLOW + "\n[+] IP tekshirilmoqda...")

    try:
        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        if data.get("error"):
            print(RED + "IP ma'lumoti topilmadi.")
            return

        result = f"""
IP: {data.get('ip')}
Country: {data.get('country_name')}
City: {data.get('city')}
Region: {data.get('region')}
ASN: {data.get('asn')}
Organization: {data.get('org')}
Timezone: {data.get('timezone')}
"""

        print(CYAN + result)
        save("IP INFORMATION", result)

    except requests.RequestException as error:
        print(RED + str(error))


def check_domain():
    domain = input("Domen (masalan example.com): ").strip()

    print(YELLOW + "\n[+] Domen tekshirilmoqda...")

    try:
        ip = socket.gethostbyname(domain)

        result = f"""
Domain: {domain}
IP address: {ip}
"""

        print(CYAN + result)
        save("DOMAIN INFORMATION", result)

    except socket.gaierror:
        print(RED + "Domen topilmadi.")


def dns_lookup():
    domain = input("Domen: ").strip()

    records = ["A", "AAAA", "MX", "NS", "TXT"]

    for record in records:
        print(YELLOW + f"\n[+] {record} records:")

        try:
            answers = dns.resolver.resolve(domain, record)

            for answer in answers:
                print(GREEN + str(answer))
                save(f"DNS {record}", answer)

        except Exception:
            print(RED + "Ma'lumot mavjud emas.")


def website_info():
    domain = input("Sayt manzili: ").strip()

    if not re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", domain):
        print(RED + "Domen formati noto'g'ri.")
        return

    url = "https://" + domain

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        result = f"""
URL: {url}
Status: {response.status_code}
Final URL: {response.url}
Server: {response.headers.get('Server')}
Content-Type: {response.headers.get('Content-Type')}
"""

        print(CYAN + result)

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options"
        ]

        print(YELLOW + "\nSecurity headers:")

        for header in security_headers:
            value = response.headers.get(header, "Not found")
            print(f"{header}: {value}")
            result += f"\n{header}: {value}"

        save("WEBSITE INFORMATION", result)

    except requests.RequestException as error:
        print(RED + str(error))


def ssl_check():
    domain = input("Domen: ").strip()

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443), timeout=10
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=domain
            ) as secure_socket:

                cert = secure_socket.getpeercert()
              result = f"""
Domain: {domain}
SSL Certificate:
Subject: {cert.get('subject')}
Issuer: {cert.get('issuer')}
Valid from: {cert.get('notBefore')}
Valid until: {cert.get('notAfter')}
"""

                print(CYAN + result)
                save("SSL CERTIFICATE", result)

    except Exception as error:
        print(RED + str(error))


def email_check():
    email = input("Email: ").strip()

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if re.match(pattern, email):
        print(GREEN + "[+] Email formati to'g'ri.")
        save("EMAIL FORMAT", email)
    else:
        print(RED + "[-] Email formati noto'g'ri.")


def menu():
    while True:
        banner()

        print(GREEN + """
[1] IP Information
[2] Domain Information
[3] DNS Lookup
[4] Website Analysis
[5] SSL Certificate Check
[6] Email Format Check
[7] Exit
""")

        choice = input(CYAN + "OSINT-MASTER > ")

        if choice == "1":
            check_ip()
        elif choice == "2":
            check_domain()
        elif choice == "3":
            dns_lookup()
        elif choice == "4":
            website_info()
        elif choice == "5":
            ssl_check()
        elif choice == "6":
            email_check()
        elif choice == "7":
            print(GREEN + "OSINT MASTER yopildi.")
            break
        else:
            print(RED + "Noto'g'ri tanlov!")

        input("\nDavom etish uchun ENTER bosing...")


if name == "main":
    menu()
