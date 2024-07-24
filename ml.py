#!/usr/bin/env python
import os
import subprocess
import time
import tkinter as tk
from tkinter import scrolledtext, filedialog
import requests

# Known files
known_files = set()

def reset_background(root):
    root.configure(bg='#00cc44')

def delete_file(file_path, log_widget):
    try:
        os.remove(file_path)
        log_widget.insert(tk.END, f"Deleted malicious file: {file_path}\n", 'error')
    except Exception as e:
        log_widget.insert(tk.END, f"Error deleting file {file_path}: {e}\n", 'error')

def scan_file(file_path, log_widget, root):
    result = subprocess.run(["clamscan", "--stdout", file_path], capture_output=True, text=True)
    scan_output = result.stdout.strip()
    if "FOUND" in scan_output:
        log_widget.insert(tk.END, f"Malicious file named {file_path} was just downloaded\n", 'error')
        log_widget.insert(tk.END, f"{scan_output}\n", 'error')
        root.configure(bg='red')
        root.after(10000, lambda: reset_background(root))  # Reset background after 10 seconds
        delete_file(file_path, log_widget)
    else:
        log_widget.insert(tk.END, f"File {file_path} is clean.\n", 'clean')
    log_widget.see(tk.END)

def download_monitor(directory, log_widget, root):
    while True:
        # Get list of files
        files = os.listdir(directory)

        # Watch for new files
        for filename in files:
            if filename not in known_files:
                log_widget.insert(tk.END, f"New file downloaded: {filename}\n", 'info')
                known_files.add(filename)
                scan_file(os.path.join(directory, filename), log_widget, root)

        # Wait 5 seconds for another check
        time.sleep(5)

def start_monitoring(directory, log_widget, root):
    import threading
    monitor_thread = threading.Thread(target=download_monitor, args=(directory, log_widget, root))
    monitor_thread.daemon = True
    monitor_thread.start()

def choose_directory(log_widget, root):
    directory = filedialog.askdirectory()
    if directory:
        log_widget.insert(tk.END, f"Monitoring directory: {directory}\n", 'info')
        start_monitoring(directory, log_widget, root)

def check_website_security(url_entry, log_widget, api_key, root):
    url = url_entry.get()
    if not url.startswith('http'):
        url = 'http://' + url
    
    # Check if the URL uses HTTPS
    if not url.startswith('https://'):
        log_widget.insert(tk.END, f"The website {url} is not secure (does not use HTTPS).\n", 'error')
        root.configure(bg='red')
        root.after(10000, lambda: reset_background(root))  # Reset background after 10 seconds
    else:
        log_widget.insert(tk.END, f"The website {url} uses HTTPS.\n", 'clean')
    
    # Scan the URL using VirusTotal API
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': api_key, 'resource': url}
    
    try:
        response = requests.get(vt_url, params=params)
        vt_result = response.json()
        
        if vt_result['response_code'] == 1:
            positives = vt_result['positives']
            total = vt_result['total']
            if positives > 0:
                log_widget.insert(tk.END, f"VirusTotal Report: {positives}/{total} scans detected this URL as malicious.\n", 'error')
                root.configure(bg='red')
                root.after(10000, lambda: reset_background(root))  # Reset background after 10 seconds
            else:
                log_widget.insert(tk.END, f"VirusTotal Report: {positives}/{total} scans detected this URL as clean.\n", 'clean')
        else:
            log_widget.insert(tk.END, f"VirusTotal Report: No information available for this URL.\n", 'info')
    except requests.RequestException as e:
        log_widget.insert(tk.END, f"Error checking the website {url} with VirusTotal: {e}\n", 'error')
        root.configure(bg='red')
        root.after(10000, lambda: reset_background(root))  # Reset background after 10 seconds
    
    log_widget.see(tk.END)

# Tkinter setup
root = tk.Tk()
root.title("Download Monitor")
root.geometry("700x600")

# Set background color and font
root.configure(bg='#00cc44')

# Title Label
title_label = tk.Label(root, text="Download Monitor & Website Security Checker", font=("Helvetica", 16, "bold"), bg='#00cc44', fg='black')
title_label.pack(pady=10)

# Frame for URL Entry and Button
url_frame = tk.Frame(root, bg='#00cc44')
url_frame.pack(pady=10)

url_label = tk.Label(url_frame, text="Enter URL to Check Security:", font=("Helvetica", 12), bg='#00cc44', fg='black')
url_label.grid(row=0, column=0, padx=5)

url_entry = tk.Entry(url_frame, width=50, font=("Helvetica", 12))
url_entry.grid(row=0, column=1, padx=5)

# User needs to change api key to their own from VirusTotal
api_key = 'bb5c48a4e5ddc7226438cafa1edceb6058681f6f027763f3cfe1bb55baca4347'
check_button = tk.Button(url_frame, text="Check Website Security", command=lambda: check_website_security(url_entry, log_widget, api_key, root), font=("Helvetica", 12), bg='#004d00', fg='white')
check_button.grid(row=0, column=2, padx=5)

# Instructions Label
instructions_label = tk.Label(root, text="Click 'Choose Directory' to select a directory to monitor for malicious files.", font=("Helvetica", 12), bg='#00cc44', fg='black')
instructions_label.pack(pady=5)

# Frame for Logs and Button
log_frame = tk.Frame(root, bg='#00cc44')
log_frame.pack(pady=10)

# Scrolled text widget for logs
log_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20, font=("Helvetica", 12), bg='#e6ffe6', fg='black')
log_widget.grid(row=0, column=0, padx=10, pady=10)
log_widget.tag_config('info', foreground='black')
log_widget.tag_config('error', foreground='red')
log_widget.tag_config('clean', foreground='green')

# Choose directory button
choose_dir_button = tk.Button(log_frame, text="Choose Directory", command=lambda: choose_directory(log_widget, root), font=("Helvetica", 12), bg='#004d00', fg='white')
choose_dir_button.grid(row=1, column=0, pady=10)

# Run the Tkinter event loop
root.mainloop()
