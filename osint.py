
#!/usr/bin/env python3

import socket
import ssl
import json
import re
import requests
import dns.resolver
import whois
import time

from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()
results = {}

HEADERS = {
    "User-Agent": "NIGHTHAWK-OSINT/2.0"
}

# ==============================
#       NIGHTHAWK OSINT PRO
# ==============================

def banner():
    console.clear()

    console.print(
        Panel.fit(
            "[bold cyan]NIGHTHAWK OSINT PRO[/bold cyan]\n"
            "[white]Advanced Open Source Intelligence Toolkit[/white]\n"
            "[dim]Python Edition | Version 2.0[/dim]",
            border_style="cyan"
        )
    )


def save(key, value):
    results[key] = value


def get_domain(value):
    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return urlparse(value).hostname


# ==============================
# DOMAIN INFORMATION
# ==============================

def domain_info():
    domain = Prompt.ask("[cyan]Domain kiriting")

    console.print("\n[bold yellow]DOMAIN ANALYSIS[/bold yellow]")

    try:
        data = whois.whois(domain)

        info = {
            "Domain": domain,
            "Registrar": str(data.registrar),
            "Creation Date": str(data.creation_date),
            "Expiration Date": str(data.expiration_date),
            "Name Servers": str(data.name_servers),
            "Status": str(data.status)
        }

        table = Table(box=box.ROUNDED)

        table.add_column("Property", style="cyan")
        table.add_column("Information", style="white")

        for key, value in info.items():
            table.add_row(key, str(value))

        console.print(table)
        save("Domain Information", info)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# ==============================
# DNS ANALYSIS
# ==============================

def dns_analysis():
    domain = Prompt.ask("[cyan]Domain kiriting")

    records = {}
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    table = Table(title="DNS RECORDS", box=box.ROUNDED)

    table.add_column("Type", style="cyan")
    table.add_column("Records", style="green")

    for record in types:
        try:
            answers = dns.resolver.resolve(
                domain, record, lifetime=5
            )

            values = [str(x) for x in answers]
            records[record] = values

            table.add_row(record, "\n".join(values))

        except Exception:
            records[record] = []
            table.add_row(record, "[dim]Not found[/dim]")

    console.print(table)
    save("DNS Records", records)


# ==============================
# IP ANALYSIS
# ==============================

def ip_analysis():
    ip = Prompt.ask("[cyan]IP address kiriting")

    try:
        socket.inet_pton(
            socket.AF_INET if "." in ip else socket.AF_INET6,
            ip
        )

        hostname = None

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unavailable"

        info = {
            "IP": ip,
            "Reverse DNS": hostname
        }

        console.print(Panel(
            f"[green]IP:[/green] {ip}\n"
            f"[green]Hostname:[/green] {hostname}",
            title="IP INFORMATION"
        ))

        save("IP Information", info)

    except Exception:
        console.print("[red]Invalid IP address[/red]")


# ==============================
# WEBSITE ANALYSIS
# ==============================

def website_analysis():
    domain = Prompt.ask("[cyan]Website domain")

    url = (
        domain if domain.startswith(("http://", "https://"))
        else "https://" + domain
    )

    try:
        response = requests.get(
            url,
            headers=HEADERS,
            timeout=10
        )

        info = {
            "URL": url,
            "Final URL": response.url,
            "Status": response.status_code,
            "Server": response.headers.get("Server"),
            "Content-Type": response.headers.get("Content-Type"),
            "Powered By": response.headers.get("X-Powered-By")
        }

        title = re.search(
            r"<title[^>]*>(.*?)</title>",
            response.text,
            re.I | re.S
        )

        info["Title"] = (
            title.group(1).strip() if title else "Unknown"
        )

        table = Table(title="WEBSITE INFORMATION")

        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        for key, value in info.items():
            table.add_row(key, str(value))

        console.print(table)
        save("Website Analysis", info)

    except Exception as e:
        console.print(f"[red]Website error: {e}[/red]")


# ==============================
# SSL ANALYSIS
# ==============================

def ssl_analysis():
    domain = Prompt.ask("[cyan]Domain kiriting")
    domain = get_domain(domain)

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443), timeout=8
        ) as sock:

            with context.wrap_socket(
                sock, server_hostname=domain
            ) as secure:

                cert = secure.getpeercert()

        info = {
            "Subject": str(cert.get("subject")),
            "Issuer": str(cert.get("issuer")),
            "Valid From": cert.get("notBefore"),
            "Valid Until": cert.get("notAfter"),
            "SAN": str(cert.get("subjectAltName"))
        }

        console.print(Panel(
            "\n".join(
                f"[cyan]{k}:[/cyan] {v}"
                for k, v in info.items()
            ),
            title="SSL CERTIFICATE"
        ))

        save("SSL Information", info)

    except Exception as e:
        console.print(f"[red]SSL error: {e}[/red]")


# ==============================
# SECURITY HEADERS
# ==============================

def security_analysis():
    domain = Prompt.ask("[cyan]Website kiriting")

    url = (
        domain if domain.startswith(("http://", "https://"))
        else "https://" + domain
    )

    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    try:
        response = requests.get(
            url, headers=HEADERS, timeout=10
        )

        table = Table(title="SECURITY HEADERS")

        table.add_column("Header", style="cyan")
        table.add_column("Status", style="white")

        data = {}

        for header in security_headers:
            value = response.headers.get(header)

            if value:
                status = "[green]PRESENT[/green]"
            else:
                status = "[yellow]MISSING[/yellow]"

            table.add_row(header, status)
            data[header] = value

        console.print(table)
        save("Security Headers", data)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# ==============================
# PUBLIC FILES
# ==============================

def public_files():
    domain = Prompt.ask("[cyan]Website kiriting")

    url = (
        domain if domain.startswith(("http://", "https://"))
        else "https://" + domain
    )

    files = [
        "/robots.txt",
        "/.well-known/security.txt"
    ]

    data = {}

    for path in files:
        try:
            response = requests.get(
                url.rstrip("/") + path,
                headers=HEADERS,
                timeout=8
            )

            data[path] = {
                "Status": response.status_code,
                "Content": (
                    response.text[:2000]
                    if response.status_code == 200
                    else ""
                )
            }

            console.print(
                f"[green]{path}[/green] "
                f"HTTP {response.status_code}"
            )

        except Exception as e:
            console.print(f"[red]{path}: {e}[/red]")

    save("Public Files", data)


# ==============================
# EMAIL VALIDATION
# ==============================

def email_analysis():
    email = Prompt.ask("[cyan]Email kiriting")

    pattern = r"^[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}$"

    if not re.match(pattern, email):
        console.print("[red]Invalid email format[/red]")
        return

    domain = email.split("@")[1]

    try:
        mx = dns.resolver.resolve(domain, "MX")

        records = [str(x.exchange) for x in mx]

        console.print(Panel(
            f"[green]Email format: VALID[/green]\n"
            f"[green]Domain: {domain}[/green]\n"
            f"[green]MX Records: {records}[/green]",
            title="EMAIL ANALYSIS"
        ))

        save("Email Analysis", {
            "Email": email,
            "Format": "Valid",
            "MX Records": records
        })

    except Exception:
        console.print(
            "[yellow]Format valid, but MX records unavailable[/yellow]"
        )


# ==============================
# USERNAME SEARCH
# ==============================

def username_search():
    username = Prompt.ask("[cyan]Username kiriting")

    websites = {
        "GitHub": "https://github.com/",
        "Reddit": "https://www.reddit.com/user/",
        "Pinterest": "https://www.pinterest.com/",
        "GitLab": "https://gitlab.com/",
        "Codeberg": "https://codeberg.org/"
    }

    table = Table(title=f"USERNAME: {username}")

    table.add_column("Platform", style="cyan")
    table.add_column("Result", style="white")
    table.add_column("URL", style="green")

    data = {}

    for name, base in websites.items():
        url = base + username

        try:
            response = requests.get(
                url, headers=HEADERS, timeout=8
            )

            # HTTP status alone does not prove account existence.
            result = (
                f"HTTP {response.status_code} - CHECK MANUALLY"
            )

            data[name] = {
                "URL": url,
                "Status": response.status_code,
                "Verified": False
            }

            table.add_row(name, result, url)

        except requests.RequestException:
            table.add_row(name, "Connection error", url)

    console.print(table)
    save("Username Search", data)


# ==============================
# TECHNOLOGY DETECTION
# ==============================

def technology_detection():
    domain = Prompt.ask("[cyan]Website kiriting")

    url = (
        domain if domain.startswith(("http://", "https://"))
        else "https://" + domain
    )

    try:
        response = requests.get(
            url, headers=HEADERS, timeout=10
        )

        technologies = []

        headers = response.headers

        if "PHP" in headers.get("X-Powered-By", ""):
            technologies.append("PHP")

        if "nginx" in headers.get("Server", "").lower():
            technologies.append("Nginx")

        if "apache" in headers.get("Server", "").lower():
            technologies.append("Apache")

        if "wp-content" in response.text:
            technologies.append("WordPress")

        if "next" in response.text.lower():
            technologies.append("Possible Next.js")

        console.print(Panel(
            "\n".join(technologies) if technologies
            else "No technologies identified",
            title="TECHNOLOGY DETECTION"
        ))

        save("Technologies", technologies)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# ==============================
# REPORT EXPORT
# ==============================

def export_report():
    if not results:
        console.print("[yellow]No results to export[/yellow]")
        return

    report = {
        "Tool": "NIGHTHAWK OSINT PRO",
        "Version": "2.0",
        "Generated": datetime.now().isoformat(),
        "Results": results
    }

    with open(
        "nighthawk_report.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
            default=str
        )

    console.print(
        "[green]JSON report saved successfully![/green]"
    )


# ==============================
# MAIN MENU
# ==============================

def menu():
    while True:
        banner()

        table = Table(
            title="MAIN OSINT MENU",
            box=box.ROUNDED,
            border_style="cyan"
        )

        table.add_column("ID", style="yellow")
        table.add_column("Module", style="white")

        modules = [
            ("1", "Domain Information"),
            ("2", "DNS Analysis"),
            ("3", "IP Analysis"),
            ("4", "Website Analysis"),
            ("5", "SSL Certificate"),
            ("6", "Security Headers"),
            ("7", "Public Files"),
            ("8", "Email Analysis"),
            ("9", "Username Search"),
            ("10", "Technology Detection"),
            ("11", "Export JSON Report"),
            ("0", "Exit")
        ]

        for number, name in modules:
            table.add_row(number, name)

        console.print(table)

        choice = Prompt.ask(
            "[bold cyan]Select module[/bold cyan]"
        )

        actions = {
            "1": domain_info,
            "2": dns_analysis,
            "3": ip_analysis,
            "4": website_analysis,
            "5": ssl_analysis,
            "6": security_analysis,
            "7": public_files,
            "8": email_analysis,
            "9": username_search,
            "10": technology_detection,
            "11": export_report
        }

        if choice == "0":
            console.print("[cyan]NIGHTHAWK shutting down...[/cyan]")
            break

        action = actions.get(choice)

        if action:
            try:
                action()
            except KeyboardInterrupt:
                console.print("\n[yellow]Cancelled[/yellow]")
            except Exception as e:
                console.print(f"[red]Module error: {e}[/red]")

            Prompt.ask("\n[dim]Enter to continue[/dim]", default="")
        else:
            console.print("[red]Invalid selection[/red]")
            time.sleep(1)


if __name__ == "__main__":
    menu()
