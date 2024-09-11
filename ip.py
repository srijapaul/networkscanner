import subprocess
import time
from multiprocessing.pool import ThreadPool
from tabulate import tabulate
import socket
import re
from colorama import Fore, Style

def nmap_scan(ip):
    ip_addr = f'192.168.0.{ip}'
    try:
        result = subprocess.Popen(['nmap', '-O', ip_addr], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if b'Running' in stdout:  
            os_info = stdout.decode().split('Running: ')[1].split('\n')[0]
            return f"Host {ip_addr} is up, OS: {os_info}"
    except Exception as e:
        return f"{Fore.RED}Error scanning {ip_addr}: {e}{Style.RESET_ALL}"

def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return "Unknown"

def identify_device_type(mac_address):
    vendors = {
        "00:1A:79": "Apple Device",
        "00:09:2D": "Samsung Device",
        "00:11:22": "Cisco Device",
    }
    prefix = ":".join(mac_address.split(":")[:3]).upper()
    return vendors.get(prefix, "Unknown Device")

def ipcleaning(ip_list):
    clean_list = [ip for ip in ip_list if ip is not None]
    return clean_list

def thread_scan():
    print("Scanning the network...")
    with ThreadPool(50) as pool:
        results = pool.map(nmap_scan, range(1, 255))  # Adjust range if using multiple subnets
    print("\nScan complete")
    return results    

def deep_scan(target_ip):
    print(f"Performing deep scan on {target_ip}...")
    result = subprocess.Popen(['nmap', '-A', '-sV', '-p-', target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = result.communicate()
    if stderr:
        return stderr.decode()
    return stdout.decode()

def format_output(results):
    table_data = []
    for result in results:
        if result:
            match = re.search(r'Host (.+) is up, OS: (.+)', result)
            if match:
                ip_addr, os_info = match.groups()
                hostname = resolve_hostname(ip_addr)
                table_data.append([ip_addr, hostname, os_info])
    print(tabulate(table_data, headers=["IP Address", "Hostname", "Operating System"], tablefmt="pretty"))

def save_to_file(data, filename="scan_results.txt"):
    with open(filename, 'w') as f:
        f.write(data)
    print(f"Results saved to {filename}")

if __name__ == '__main__':
    start_time = time.perf_counter()
    
    #network scan
    scan_results = ipcleaning(thread_scan())
    
    # Formatting output
    print("\nFormatted Scan Results:")
    format_output(scan_results)
    
    # Save scan results to a file
    save_to_file("\n".join(scan_results), "network_scan_report.txt")
    
    end_time = time.perf_counter()
    print(f'\nTotal scan time: {"{:.2f}".format(end_time - start_time)} seconds')

    # deep scan on each IP
    for result in scan_results:
        match = re.search(r'Host (.+) is up, OS: (.+)', result)
        if match:
            ip_addr, _ = match.groups()
            print(deep_scan(ip_addr))
