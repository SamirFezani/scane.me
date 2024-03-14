import nmap
import json
import threading
import ipaddress
import requests
import os
from datetime import datetime

# Import tkinter only if not running in GitHub Actions environment
if os.getenv('GITHUB_ACTIONS') != 'true':
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

def save_results_to_json(result_data):
    with open('scan_results.json', 'w') as json_file:
        json.dump(result_data, json_file, indent=2)
        print("Results saved to scan_results.json successfully.")

def upload_to_github():
    if os.path.exists('scan_results.json') and os.path.getsize('scan_results.json') > 0:
        with open('scan_results.json', 'r') as json_file:
            data = json.load(json_file)

        json_data = json.dumps(data)

        url = 'https://raw.githubusercontent.com/SamirFezani/scane.me/main/scan_results.json'
        token = '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'

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {token}'
        }
        payload = {
            'message': 'Update scan results',
            'content': json_data
        }

        response = requests.put(url, headers=headers, json=payload)

        if response.status_code == 200:
            print("JSON file uploaded to GitHub successfully.")
        else:
            print("Failed to upload JSON file to GitHub. Status code:", response.status_code)
    else:
        print("The scan_results.json file is empty.")

def scan_network():
    threading.Thread(target=perform_scan).start()

def perform_scan():
    try:
        if os.getenv('GITHUB_ACTIONS') != 'true':
            # Create GUI if not running in GitHub Actions environment
            root = tk.Tk()
            root.title("Scanner de réseaux locaux")

            label_ip_address = tk.Label(root, text="Adresse IP:")
            label_ip_address.pack(pady=5)

            entry_ip_address = tk.Entry(root, width=40)
            entry_ip_address.pack(pady=5)

            label_subnet_mask = tk.Label(root, text="Masque de sous-réseau:")
            label_subnet_mask.pack(pady=5)

            entry_subnet_mask = tk.Entry(root, width=40)
            entry_subnet_mask.pack(pady=5)

            result_text = scrolledtext.ScrolledText(root, width=80, height=20)
            result_text.pack(expand=True, fill="both", padx=10, pady=10)

            button_scan = tk.Button(root, text="Scanner le réseau local", command=lambda: start_scan(entry_ip_address.get(), entry_subnet_mask.get(), result_text))
            button_scan.pack(pady=10)

            root.mainloop()
        else:
            # If running in GitHub Actions, run scan directly without GUI
            start_scan("192.168.1.1", "24", None)  # Example IP address and subnet mask, replace with your logic
    except Exception as e:
        print("An error occurred during the scan:", str(e))

def start_scan(ip_address, subnet_mask, result_text):
    nm = nmap.PortScanner()
    nm.scan(hosts=calculate_network_range(ip_address, subnet_mask), arguments='-sn')

    result_data = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            host_info = {
                'IP Address': host,
                'Hostname': get_hostnames(nm[host]) if 'hostnames' in nm[host] else 'N/A',
                'State': nm[host].state(),
                'MAC Address': nm[host]['addresses']['mac'] if 'mac' in nm[host]['addresses'] else 'N/A',
                'Vendor': nm[host]['vendor'] if 'vendor' in nm[host] else 'N/A',
                'Date': datetime.now().strftime("%Y-%m-%d"),
                'Time': datetime.now().strftime("%H:%M:%S")
            }
            result_data.append(host_info)

    if result_data:
        save_results_to_json(result_data)
        upload_to_github()
        if result_text:
            display_results(result_data, result_text)

def display_results(result_data, result_text):
    for host_info in result_data:
        result_text.insert(tk.END, "IP Address: {}\n".format(host_info['IP Address']))
        result_text.insert(tk.END, "Hostname: {}\n".format(host_info['Hostname']))
        result_text.insert(tk.END, "State: {}\n".format(host_info['State']))
        result_text.insert(tk.END, "MAC Address: {}\n".format(host_info['MAC Address']))
        result_text.insert(tk.END, "Vendor: {}\n".format(host_info['Vendor']))
        result_text.insert(tk.END, "Date: {}\n".format(host_info['Date']))
        result_text.insert(tk.END, "Time: {}\n".format(host_info['Time']))
        result_text.insert(tk.END, "\n")

def get_hostnames(host_data):
    hostnames = host_data['hostnames']
    if hostnames:
        return ', '.join(name['name'] for name in hostnames)
    else:
        return 'N/A'

def calculate_network_range(ip_address, subnet_mask):
    network_address = ipaddress.IPv4Network(ip_address + '/' + subnet_mask, strict=False)
    return str(network_address.network_address) + '/' + str(network_address.prefixlen)

if __name__ == "__main__":
    scan_network()
