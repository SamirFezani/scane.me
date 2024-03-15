import tkinter as tk
from tkinter import messagebox, scrolledtext
import nmap
import json
import threading
import ipaddress
import requests
import os
from datetime import datetime

def save_results_to_json(result_data):
    with open('scan_results.json', 'w') as json_file:
        json.dump(result_data, json_file, indent=2)
        messagebox.showinfo("Information", "Résultats du scan sauvegardés avec succès.")

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
            print("Fichier JSON envoyé avec succès sur GitHub.")
        else:
            print("Échec de l'envoi du fichier JSON sur GitHub. Code de statut :", response.status_code)
    else:
        print("Le fichier scan_results.json est vide.")

def scan_network():
    threading.Thread(target=perform_scan).start()

def perform_scan():
    try:
        ip_address = entry_ip_address.get()
        subnet_mask = entry_subnet_mask.get()
        network_range = calculate_network_range(ip_address, subnet_mask)

        nm = nmap.PortScanner()
        nm.scan(hosts=network_range, arguments='-sn')

        result_data = []

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                host_info = {
                    'Adresse IP': host,
                    'Nom d\'hôte': get_hostnames(nm[host]) if 'hostnames' in nm[host] else 'Non disponible',
                    'État': nm[host].state(),
                    'Adresses MAC': nm[host]['addresses']['mac'] if 'mac' in nm[host]['addresses'] else 'Non disponible',
                    'Fabricant': nm[host]['vendor'] if 'vendor' in nm[host] else 'Non disponible',
                    'Date': datetime.now().strftime("%Y-%m-%d"),
                    'Heure': datetime.now().strftime("%H:%M:%S")
                }
                result_data.append(host_info)

        root.after(0, lambda: display_results(result_data))

        if result_data:
            save_results_to_json(result_data)
            upload_to_github()  # Appel de la fonction pour téléverser les résultats sur GitHub
        else:
            messagebox.showinfo("Information", "Aucun hôte disponible trouvé pendant le scan.")
            
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur s'est produite pendant le scan : {str(e)}")

def get_hostnames(host_data):
    hostnames = host_data['hostnames']
    if hostnames:
        return ', '.join(name['name'] for name in hostnames)
    else:
        return 'Non disponible'

def display_results(result_data):
    result_window = tk.Toplevel()
    result_window.title("Résultats du scan")

    result_text = scrolledtext.ScrolledText(result_window, width=80, height=20)
    result_text.pack(expand=True, fill="both")

    for host_info in result_data:
        result_text.insert(tk.END, "Adresse IP: {}\n".format(host_info['Adresse IP']))
        result_text.insert(tk.END, "Nom d'hôte: {}\n".format(host_info['Nom d\'hôte']))
        result_text.insert(tk.END, "État: {}\n".format(host_info['État']))
        result_text.insert(tk.END, "Adresses MAC: {}\n".format(host_info['Adresses MAC']))
        result_text.insert(tk.END, "Fabricant: {}\n".format(host_info['Fabricant']))
        result_text.insert(tk.END, "Date du scan: {}\n".format(host_info['Date']))
        result_text.insert(tk.END, "Heure du scan: {}\n".format(host_info['Heure']))
        result_text.insert(tk.END, "\n")

    result_text.configure(state='disabled')

def calculate_network_range(ip_address, subnet_mask):
    network_address = ipaddress.IPv4Network(ip_address + '/' + subnet_mask, strict=False)
    return str(network_address.network_address) + '/' + str(network_address.prefixlen)

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

button_scan = tk.Button(root, text="Scanner le réseau local", command=scan_network)
button_scan.pack(pady=10)

root.mainloop()
