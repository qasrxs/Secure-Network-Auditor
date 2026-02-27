#!/usr/bin/env python3
"""
ScopeSecure Network Auditing Tool (LIVE ENGINE w/ SMART REPORTING)
============================================================

An internal, GUI-based cybersecurity tool developed specifically for 
Scope Engineering Consultancy to automate routine network scanning.
This version executes LIVE Nmap scans and dynamically generates
executive vulnerability reports.

Author: Khaled Yousef Alqasrawi (Cybersecurity Intern)
Organization: Scope Engineering Consultancy (Al Ain)
Version: 3.0 (Smart Live Engine Release)
Requirements: tkinter, subprocess, threading, nmap
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import time
import sys
import re
from datetime import datetime

class ScopeSecureScanner:
    """Main application class for the ScopeSecure Auditing Tool"""
    
    def __init__(self, root):
        self.root = root
        self.setup_gui()
        self.is_scanning = False
        
        # Knowledge Base for dynamic risk assessment during live scans
        self.vuln_db = {
            445: {"risk": "Critical", "cve": "CVE-2017-0144", "desc": "Exposed SMB port vulnerable to EternalBlue. High risk of ransomware lateral movement.", "rem": "Configure Windows Defender Firewall inbound rules to immediately block SMB Port 445 on non-essential clients."},
            80: {"risk": "High", "cve": "CWE-319", "desc": "Service transmitting data (potentially credentials) in absolute clear-text over HTTP.", "rem": "Enforce HTTPS and deploy SSL/TLS certificates on all internal web services to prevent credential theft."},
            23: {"risk": "High", "cve": "CWE-306", "desc": "Device utilizing unencrypted Telnet, highly susceptible to packet sniffing.", "rem": "Disable clear-text Telnet services on all network switches and devices; enforce SSH protocols."},
            21: {"risk": "High", "cve": "CWE-319", "desc": "Unencrypted FTP service allows clear-text credential interception.", "rem": "Enforce SFTP/FTPS and disable anonymous FTP access."},
            3389: {"risk": "Medium", "cve": "CWE-300", "desc": "Exposed RDP port increases brute-force attack surface.", "rem": "Enforce Network Level Authentication (NLA) and restrict RDP access to VPN connections only."}
        }
        
    def setup_gui(self):
        """Initialize and configure the GUI components"""
        self.root.title("🛡️ ScopeSecure Live Auditing Tool v3.0")
        self.root.geometry("950x750")
        self.root.configure(bg='#1e272e') 
        
        self.setup_styles()
        
        main_frame = ttk.Frame(self.root, style='Main.TFrame', padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        self.create_header(main_frame)
        self.create_input_section(main_frame)
        self.create_progress_section(main_frame)
        self.create_results_section(main_frame)
        self.create_control_section(main_frame)
        self.create_status_bar()
        
    def setup_styles(self):
        style = ttk.Style()
        style.configure('Main.TFrame', background='#1e272e')
        style.configure('Header.TLabel', 
                       background='#1e272e', 
                       foreground='#ff4757', 
                       font=('Segoe UI', 18, 'bold'))
        style.configure('Info.TLabel',
                       background='#1e272e',
                       foreground='#d2dae2',
                       font=('Segoe UI', 10, 'italic'))
        style.configure('Scan.TButton',
                       font=('Segoe UI', 11, 'bold'))
        
    def create_header(self, parent):
        header_frame = ttk.Frame(parent, style='Main.TFrame')
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        
        title_label = ttk.Label(header_frame, 
                               text="🛡️ ScopeSecure Network Auditor (SMART LIVE ENGINE)",
                               style='Header.TLabel')
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        info_label = ttk.Label(header_frame,
                              text="WARNING: This tool executes LIVE network scans and dynamically generates Executive Reports.",
                              style='Info.TLabel')
        info_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
    def create_input_section(self, parent):
        input_frame = ttk.LabelFrame(parent, text="🎯 Network Target Configuration", padding="10")
        input_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(input_frame, text="Target IP/Subnet:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.target_var = tk.StringVar(value="192.168.1.1") 
        self.target_entry = ttk.Entry(input_frame, textvariable=self.target_var, font=('Consolas', 11))
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        options_frame = ttk.Frame(input_frame)
        options_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Label(options_frame, text="Audit Profile:").grid(row=0, column=0, sticky=tk.W)
        self.scan_type_var = tk.StringVar(value="Service & Version Detection")
        
        scan_type_combo = ttk.Combobox(options_frame, textvariable=self.scan_type_var,
                                      values=[
                                          "Fast Port Scan (Default)", 
                                          "Service & Version Detection", 
                                          "Aggressive Vulnerability Scan", 
                                          "Ping Sweep (Discover Hosts)"
                                      ],
                                      state="readonly", width=30)
        scan_type_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 20))
        
        self.scan_button = ttk.Button(options_frame, text="🚀 Execute Live Scan",
                                     command=self.start_scan, style='Scan.TButton')
        self.scan_button.grid(row=0, column=2, padx=(10, 0))
        
    def create_progress_section(self, parent):
        progress_frame = ttk.LabelFrame(parent, text="📊 Scan Telemetry", padding="10")
        progress_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                           maximum=100, length=400, mode='determinate')
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.status_var = tk.StringVar(value="System Ready. Waiting for target...")
        status_label = ttk.Label(progress_frame, textvariable=self.status_var, font=('Segoe UI', 9))
        status_label.grid(row=1, column=0, sticky=tk.W)
        
    def create_results_section(self, parent):
        results_frame = ttk.LabelFrame(parent, text="📋 Live Executive Report", padding="10")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 15))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                     wrap=tk.WORD, 
                                                     height=15,
                                                     font=('Consolas', 10),
                                                     bg='#0d1117',
                                                     fg='#2ecc71',
                                                     insertbackground='#2ecc71')
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.results_text.tag_configure("header", foreground="#f1c40f", font=('Consolas', 11, 'bold'))
        self.results_text.tag_configure("warning", foreground="#e67e22")
        self.results_text.tag_configure("success", foreground="#2ecc71")
        self.results_text.tag_configure("error", foreground="#e74c3c", font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure("raw", foreground="#7f8c8d")
        
    def create_control_section(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        ttk.Button(control_frame, text="💾 Export Report (TXT)",
                  command=self.export_txt).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(control_frame, text="🗑️ Clear Buffer",
                  command=self.clear_results).grid(row=0, column=1, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="⏹️ Abort Scan",
                                     command=self.stop_scan, state='disabled')
        self.stop_button.grid(row=0, column=2, padx=(10, 0))
        
    def create_status_bar(self):
        self.status_bar = ttk.Label(self.root, text="ScopeSecure Engine Ready", relief=tk.SUNKEN, anchor=tk.W,
                                   font=('Segoe UI', 8), background='#1e272e', foreground='#d2dae2')
        self.status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
    
    def start_scan(self):
        target = self.target_var.get().strip()
        scan_type = self.scan_type_var.get()
        
        if not target:
            messagebox.showerror("Error", "Target field cannot be empty.")
            return
            
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress_var.set(0)
        self.status_var.set(f"Initializing live {scan_type} on {target}...")
        self.status_bar.configure(text=f"Engaging live target {target}...")
        
        self.results_text.delete(1.0, tk.END)
        
        threading.Thread(target=self.run_real_scan, args=(target, scan_type), daemon=True).start()
    
    def run_real_scan(self, target, scan_type):
        """Execute actual live Nmap scans utilizing system subprocesses"""
        try:
            self.add_result(f"{'='*65}\n", "header")
            self.add_result(f" SCOPESECURE LIVE VULNERABILITY AUDIT\n", "header")
            self.add_result(f"{'='*65}\n", "header")
            self.add_result(f"Target Network : {target}\n")
            self.add_result(f"Audit Profile  : {scan_type}\n")
            self.add_result(f"Timestamp      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.add_result(f"Auditor        : Khaled Yousef Alqasrawi\n")
            self.add_result(f"{'='*65}\n\n")
            
            cmd = ["nmap"]
            
            if scan_type == "Fast Port Scan (Default)":
                cmd.extend(["-F", target])
            elif scan_type == "Service & Version Detection":
                cmd.extend(["-sV", target])
            elif scan_type == "Aggressive Vulnerability Scan":
                cmd.extend(["-A", "-T4", target])
            elif scan_type == "Ping Sweep (Discover Hosts)":
                cmd.extend(["-sn", target])
                
            self.update_progress(10, f"Executing Engine Command: {' '.join(cmd)}")
            
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                     text=True, universal_newlines=True)
            
            for i in range(10, 90, 5):
                if not self.is_scanning:
                    self.process.terminate()
                    return
                time.sleep(1)
                self.update_progress(i, "Awaiting live Nmap telemetry. Generating dynamic report...")
            
            stdout, stderr = self.process.communicate()
            
            if self.process.returncode == 0:
                self.update_progress(95, "Parsing raw output into Executive Report format...")
                self.parse_and_format_nmap_output(stdout) # Send raw output to the parsing engine
                self.update_progress(100, "Live Audit cycle complete.")
            else:
                self.add_result(f"❌ Scan failed with return code {self.process.returncode}\n", "error")
                if stderr:
                    self.add_result(f"Error details: {stderr}\n", "error")
                    
        except FileNotFoundError:
            self.add_result("❌ CRITICAL ERROR: Native 'Nmap' is not installed or not in system PATH.\n", "error")
            self.add_result("Please install Nmap from https://nmap.org/download.html to run live scans.\n", "error")
        except Exception as e:
            self.add_result(f"❌ Core Fault: {str(e)}\n", "error")
        finally:
            self.root.after(0, self.scan_completed)

    def parse_and_format_nmap_output(self, raw_output):
        """The brain of the tool: reads raw Nmap text and turns it into a formatted report."""
        hosts = []
        current_ip = "Unknown"
        
        # Regex to pull IPs, open ports, services, and versions out of raw Nmap text
        for line in raw_output.split('\n'):
            ip_match = re.search(r'Nmap scan report for (\S+)', line)
            if ip_match:
                current_ip = ip_match.group(1)

            # Matches format: "80/tcp open http Apache httpd 2.4"
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?', line)
            if port_match:
                port = int(port_match.group(1))
                service = port_match.group(3)
                version = port_match.group(4) or "Version Unknown"
                hosts.append({"ip": current_ip, "port": port, "service": service, "version": version.strip()})

        # Section 1: Port Discovery
        self.add_result("🔍 LAYER 4 PORT DISCOVERY:\n", "header")
        self.add_result("-" * 50 + "\n")
        
        found_vulns = []
        found_rems = []

        if not hosts:
            self.add_result("No open ports discovered, or targets are blocking ICMP pings.\n\n", "success")
        else:
            for p in hosts:
                port_num = p['port']
                # Check our knowledge base to see if this port is risky
                risk_info = self.vuln_db.get(port_num, {"risk": "Low", "cve": None, "desc": None, "rem": None})
                risk_level = risk_info["risk"]
                
                status = "success" if risk_level == "Low" else ("warning" if risk_level == "Medium" else "error")
                self.add_result(f"Host {p['ip']} | Port {p['port']}/tcp OPEN | {p['service'].upper()} ({p['version']}) | Risk: {risk_level}\n", status)
                
                # If there's a risk, add it to our vulnerability list
                if risk_info["cve"]:
                    if not any(v['cve'] == risk_info["cve"] for v in found_vulns):
                        found_vulns.append({
                            "cve": risk_info["cve"],
                            "severity": risk_level.upper(),
                            "service": f"{p['service'].upper()} ({p['port']})",
                            "desc": risk_info["desc"]
                        })
                    if risk_info["rem"] not in found_rems:
                        found_rems.append(risk_info["rem"])

        self.add_result("\n\n🚨 CRITICAL VULNERABILITY ANALYSIS:\n", "header")
        self.add_result("-" * 50 + "\n")
        if not found_vulns:
            self.add_result("No critical vulnerabilities detected based on current open ports.\n", "success")
        else:
            for v in found_vulns:
                color = "error" if v["severity"] == "CRITICAL" else "warning"
                self.add_result(f"🔴 {v['cve']} [{v['severity']}]\n   Target: {v['service']}\n   Finding: {v['desc']}\n\n", color)

        self.add_result("\n💡 MANDATORY REMEDIATION STEPS:\n", "header")
        self.add_result("-" * 50 + "\n")
        if not found_rems:
            self.add_result("No immediate remediation required. Continue standard logging.\n", "success")
        else:
            for i, rec in enumerate(found_rems, 1):
                self.add_result(f"[{i}] {rec}\n", "success")
                
        # Finally, append the raw Nmap data at the bottom for verification
        self.add_result("\n\n" + "="*50 + "\n")
        self.add_result(" RAW NMAP TELEMETRY (For IT Dept Review)\n", "raw")
        self.add_result("="*50 + "\n")
        self.add_result(raw_output, "raw")


    def add_result(self, text, tag=None):
        def update_gui():
            self.results_text.insert(tk.END, text, tag)
            self.results_text.see(tk.END)
            self.results_text.update()
        self.root.after(0, update_gui)
    
    def update_progress(self, value, status):
        def update_gui():
            self.progress_var.set(value)
            self.status_var.set(status)
        self.root.after(0, update_gui)
    
    def scan_completed(self):
        self.is_scanning = False
        self.scan_button.configure(state='normal')
        self.stop_button.configure(state='disabled')
        self.status_bar.configure(text="Engine Standby.")
    
    def stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            try:
                self.process.terminate()
            except:
                pass
            self.add_result("\n⏹️ Audit manually aborted by operator.\n", "error")
            
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.status_var.set("System Ready...")
        
    def export_txt(self):
        content = self.results_text.get(1.0, tk.END)
        filename = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Audit Log")
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Success", f"Log saved to {filename}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ScopeSecureScanner(root)
    root.mainloop()
