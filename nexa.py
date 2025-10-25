#!/usr/bin/env python3
import argparse
import asyncio
import shutil
import subprocess
import os
import json
import time
import xml.etree.ElementTree as ET
from asyncio import Semaphore
from typing import List, Tuple, Optional, Dict


try:
    from tqdm import tqdm
except Exception:
    tqdm = None

try:
    from prettytable import PrettyTable
except Exception:
    PrettyTable = None

try:
    from colorama import Fore, Style, init as color_init
    color_init(autoreset=True)
except Exception:
    class DummyColor:
        RESET = ''
        RED = ''
        GREEN = ''
        YELLOW = ''
        CYAN = ''
        MAGENTA = ''
        WHITE = ''
        BRIGHT = ''
    Fore = Style = DummyColor()


def print_banner():
    banner = fr"""
{Fore.CYAN}{Style.BRIGHT}
 ______  _______ _    _        
|  ___ \(_______) \  / /  /\   
| |   | |_____   \ \/ /  /  \  
| |   | |  ___)   )  (  / /\ \ 
| |   | | |_____ / /\ \| |__| |
|_|   |_|_______)_/  \_\______|
                               
{Fore.RED}      Intelligent Port Scanner{Style.RESET_ALL}
"""
    print(banner)


async def probe_port_once(host: str, port: int, timeout: float) -> Tuple[str, str]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except asyncio.TimeoutError:
        return 'FILTERED', ''
    except ConnectionRefusedError:
        return 'CLOSED', ''
    except OSError:
        return 'FILTERED', ''
    except Exception:
        return 'FILTERED', ''

    banner = ''
    try:
        if port in (80, 8080, 8000, 443):
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=0.9)
        except asyncio.TimeoutError:
            data = b''
        if data:
            banner = data.decode(errors='replace').strip().replace('\r',' ').replace('\n',' ')
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return 'OPEN', banner

async def run_scan(host: str, ports: List[int], concurrency: int, timeout: float):
    sem = Semaphore(concurrency)
    results: Dict[int, Tuple[str,str]] = {}

    progress = tqdm(total=len(ports), desc=f"{Fore.YELLOW}Scanning", ncols=80) if tqdm else None

    async def worker(port: int):
        async with sem:
            status, banner = await probe_port_once(host, port, timeout)
            results[port] = (status, banner)
            if progress:
                progress.update(1)

    tasks = [asyncio.create_task(worker(p)) for p in ports]
    await asyncio.gather(*tasks)
    if progress:
        progress.close()
    return results


def run_nmap_and_parse(target: str, ports: str = '1-1024', debug: bool=False) -> Tuple[Dict[int,str], str, Optional[str]]:
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        return {}, '', None

    cmd = [nmap_path, '-p', ports, '-sS', '-sV', '-O', '-oX', '-', target]
    if debug: print(f"{Fore.CYAN}[debug]{Style.RESET_ALL} running nmap:", ' '.join(cmd))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    stderr = proc.stderr or ''
    xml_out = proc.stdout or ''
    parsed: Dict[int,str] = {}
    if xml_out:
        try:
            root = ET.fromstring(xml_out)
            for host in root.findall('host'):
                ports_el = host.find('ports')
                if ports_el is None: continue
                for port_el in ports_el.findall('port'):
                    state_el = port_el.find('state')
                    if state_el is None: continue
                    state = state_el.get('state')
                    portid = int(port_el.get('portid'))
                    if state != 'open':
                        parsed[portid] = state
                        continue
                    service_el = port_el.find('service')
                    svc_desc = ''
                    if service_el is not None:
                        name = service_el.get('name') or ''
                        product = service_el.get('product') or ''
                        version = service_el.get('version') or ''
                        extrainfo = service_el.get('extrainfo') or ''
                        parts = [p for p in (name, product, version, extrainfo) if p]
                        svc_desc = ' '.join(parts)
                    parsed[portid] = svc_desc or '(unknown)'
        except ET.ParseError:
            pass
    return parsed, stderr, xml_out


def print_table(merged_ports: List[Dict]):
    """Show only OPEN ports + FILTERED ports that have a service."""
    rows = []
    for item in merged_ports:
        s = item['status']
        svc = item['service']
        if s == 'OPEN' or (s == 'FILTERED' and svc and svc.lower() not in ('', '(unknown)')):
            rows.append((item['port'], s, svc, item['version']))

    if not rows:
        print(f"{Fore.RED}[!] No open or relevant filtered ports found.{Style.RESET_ALL}")
        return

    if PrettyTable:
        table = PrettyTable()
        table.field_names = ["Port", "Status", "Service", "Version/Banner"]
        for p, s, svc, ver in rows:
            color = Fore.GREEN if s == 'OPEN' else Fore.YELLOW
            table.add_row([
                f"{Fore.CYAN}{p}{Style.RESET_ALL}",
                f"{color}{s}{Style.RESET_ALL}",
                f"{Fore.WHITE}{svc}{Style.RESET_ALL}",
                ver
            ])
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- PORT STATUS TABLE ---{Style.RESET_ALL}")
        print(table)
    else:
        print(f"{'Port':<6}{'Status':<9}{'Service':<12}{'Version/Banner'}")
        print('-'*70)
        for p,s,svc,ver in rows:
            color = Fore.GREEN if s == 'OPEN' else Fore.YELLOW
            print(f"{Fore.CYAN}{p:<6}{color}{s:<9}{Fore.WHITE}{svc:<12}{ver}{Style.RESET_ALL}")
        print('-'*70)


def highlight_gemini_output(text: str) -> str:
    lines = text.splitlines()
    colored = []
    for line in lines:
        if line.strip().startswith("**") or line.strip().startswith("#"):
            colored.append(Fore.CYAN + Style.BRIGHT + line + Style.RESET_ALL)
        elif any(word in line.lower() for word in ("VULNERABILITIES","impact","recommendation","cve","advisories","EXPLOITATION STEPS","remediation","DETECTION")):
            colored.append(Fore.YELLOW + line + Style.RESET_ALL)
        else:
            colored.append(Fore.WHITE + line + Style.RESET_ALL)
    return "\n".join(colored)


def main():
    p = argparse.ArgumentParser(description='NEXA - Intelligent Port Scanner')
    p.add_argument('target')
    p.add_argument('--ports','-p',default='1-1024')
    p.add_argument('--concurrency','-c',type=int,default=200)
    p.add_argument('--timeout',type=float,default=2.0)
    p.add_argument('--no-nmap',action='store_true')
    p.add_argument('--debug',action='store_true')
    args = p.parse_args()

    print_banner()
    print(f"{Fore.YELLOW}[+] Target:{Style.RESET_ALL} {args.target}")
    print(f"{Fore.YELLOW}[+] Ports:{Style.RESET_ALL} {args.ports}")
    print(f"{Fore.YELLOW}[+] Concurrency:{Style.RESET_ALL} {args.concurrency}")

    ports = []
    for part in args.ports.split(','):
        if '-' in part:
            a,b = map(int, part.split('-'))
            ports.extend(range(a,b+1))
        else:
            ports.append(int(part))
    ports = sorted(set(ports))

    probe_results = asyncio.run(run_scan(args.target, ports, args.concurrency, args.timeout))
    nmap_info, nmap_stderr, nmap_xml = ({}, '', None)
    if not args.no_nmap:
        nmap_info, nmap_stderr, nmap_xml = run_nmap_and_parse(args.target, args.ports, args.debug)

    merged = []
    for port, (status,banner) in probe_results.items():
        svc = nmap_info.get(port, '')
        merged.append({'port':port,'status':status,'service':svc,'version':banner[:120]})

    print_table(merged)

    whois_out = subprocess.getoutput(f"whois {args.target}")
    dns_out = subprocess.getoutput(f"host {args.target}")
    http_out = subprocess.getoutput(f"curl -I -m 8 -s https://{args.target} || curl -I -m 8 -s http://{args.target}")

    summary = "\n".join([f"{m['port']} {m['status']} {m['service']} {m['version']}" for m in merged])
    prompt = f"""TASK: You are a security analyst and a red-teamer producing an intelligence-style, ACTIONABLE report.
    Analyze this target based on port scan, whois, dns, and http headers:

{summary}

WHOIS:
{whois_out}

DNS:
{dns_out}

HTTP:
{http_out}

        
        "Do provide exploit steps, payloads, or step-by-step instructions for compromise. Search exploit-DB or github for available exploit",
        "For each exposed service, list likely CVE IDs (by ID) and vendor advisories (only link or cite) if applicable, explain high-level impact, and provide defensive remediation and detection recommendations.",
        "Also summarize WHOIS/DNS info (hosting, ASN, registrar) and any public signals that appear relevant.",
        "Keep output concise and suitable for a disclosure or SOC ticket.",
        ""
"""

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- GEMINI ANALYSIS ---{Style.RESET_ALL}")
    proc = subprocess.run(["/usr/bin/gemini-cli", "-p", ""], input=prompt.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = proc.stdout.decode(errors='replace')
    print(highlight_gemini_output(out))

if __name__ == '__main__':
    main()

