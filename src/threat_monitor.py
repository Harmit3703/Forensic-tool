import psutil
import os
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import requests
import threading
import time
import datetime

try:
    repo_root = os.path.dirname(os.path.dirname(__file__))
    env_path = os.path.join(repo_root, '.env')
    if os.path.exists(env_path) and not os.environ.get('VIRUSTOTAL_API_KEY'):
        with open(env_path, 'r', encoding='utf-8') as ef:
            for raw in ef:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                if k.strip() == 'VIRUSTOTAL_API_KEY':
                    os.environ['VIRUSTOTAL_API_KEY'] = v.strip().strip('"').strip("'")
                    break
except Exception:
    pass


# Configuration
# The application expects the VIRUSTOTAL_API_KEY to be provided via environment
# variables (for example via a local .env file that users load themselves).
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
SUSPICIOUS_KEYWORDS = ["ransomware", "stealer", "keylogger", "malware", "trojan"]
SUSPICIOUS_PORTS = [4444, 6666, 6667, 1337]
MEMORY_SPIKE_THRESHOLD = 0.5

class ThreatMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Process Threat Monitor")
        self.root.geometry("1200x600")
        # Explicit check: require a local .env file and a configured VIRUSTOTAL_API_KEY.
        repo_root = os.path.dirname(os.path.dirname(__file__))
        env_path = os.path.join(repo_root, '.env')
        if not os.path.exists(env_path):
            messagebox.showerror("Configuration error", ".env file not found in repository root.\n\nPlease create a local .env file with VIRUSTOTAL_API_KEY and re-run the application.")
            try:
                root.destroy()
            except Exception:
                pass
            return

        if not VIRUSTOTAL_API_KEY:
            messagebox.showerror("Configuration error", "VIRUSTOTAL_API_KEY not found in environment or .env.\n\nOpen .env and set VIRUSTOTAL_API_KEY=your_api_key_here then re-run the app.")
            try:
                root.destroy()
            except Exception:
                pass
            return
        self.flagged_processes = {}
        self.hash_cache = {}
        self.memory_cache = {}

        self._logfile = os.path.join(os.path.dirname(os.path.dirname(__file__)), "forensic_log.txt")
        
        self.columns = ("PID", "Name", "Path", "Memory (MB)", "Remote IP", "Port",
                        "File Created", "File Modified", "File Size (KB)", "Start Time",
                        "Runtime (min)", "Memory Anomaly", "Fileless Risk")
        self.setup_gui()
        self.start_background_scan()
        self.update_table()

    def log_event(self, message):
        """Append a timestamped message to the project log file (forensic_log.txt)."""
        try:
            with open(self._logfile, "a") as f:
                f.write(f"{datetime.datetime.now()}: {message}\n")
        except Exception:
           
            pass

    def get_process_hash(self, pid):
        try:
            proc = psutil.Process(pid)
            with open(proc.exe(), "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            self.log_event(f"Failed to hash process {pid}: {e}")
            return None

    def check_virustotal(self, file_hash):
        if file_hash in self.hash_cache:
            positives, timestamp = self.hash_cache[file_hash]
            if time.time() - timestamp < 86400:
                return positives
        if not VIRUSTOTAL_API_KEY:
            # No API key configured: skip VirusTotal checks.
            self.log_event(f"VirusTotal API key not set; skipping check for {file_hash}")
            return -1
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                positives = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                self.hash_cache[file_hash] = (positives, time.time())
                return positives
            return -1
        except Exception as e:
            self.log_event(f"VirusTotal check failed for hash {file_hash}: {e}")
            return -1

    def get_processes(self):
        processes = []
        current_time = time.time()
        for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'memory_info', 'create_time']):
            try:
                pid = proc.info['pid']
                memory_mb = round(proc.info['memory_info'].rss / (1024 * 1024), 2)
                anomaly = "No"
                if pid in self.memory_cache:
                    prev_memory, prev_time = self.memory_cache[pid]
                    time_diff = current_time - prev_time
                    if time_diff > 0 and (memory_mb / prev_memory - 1) > MEMORY_SPIKE_THRESHOLD:
                        anomaly = "Yes"
                self.memory_cache[pid] = (memory_mb, current_time)
                fileless_risk = "No" if proc.info['exe'] and proc.info['exe'] != "Unknown" else "Yes"
                info = {
                    "PID": pid,
                    "Name": proc.info['name'],
                    "Path": proc.info['exe'] or "Unknown",
                    "Memory (MB)": memory_mb,
                    "Remote IP": "None",
                    "Port": "None",
                    "File Created": "Unknown",
                    "File Modified": "Unknown",
                    "File Size (KB)": "Unknown",
                    "Start Time": datetime.datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S'),
                    "Runtime (min)": round((current_time - proc.info['create_time']) / 60, 2),
                    "Memory Anomaly": anomaly,
                    "Fileless Risk": fileless_risk
                }
                try:
                    connections = proc.net_connections()
                    if connections:
                        conn = connections[0]
                        if conn.raddr:
                            info["Remote IP"] = conn.raddr.ip
                            info["Port"] = str(conn.raddr.port)
                except Exception:
                    pass
                if info["Path"] != "Unknown":
                    try:
                        stat = os.stat(info["Path"])
                        info["File Created"] = datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                        info["File Modified"] = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        info["File Size (KB)"] = round(stat.st_size / 1024, 2)
                    except Exception:
                        pass
                processes.append(info)
            except Exception:
                continue
        return processes

    def is_suspicious(self, process):
        try:
            start_time = datetime.datetime.strptime(process["Start Time"], '%Y-%m-%d %H:%M:%S')
            return (
                any(keyword in process["Name"].lower() or keyword in process["Path"].lower() for keyword in SUSPICIOUS_KEYWORDS) or
                (process["Port"] != "None" and int(process["Port"]) in SUSPICIOUS_PORTS) or
                (1 <= start_time.hour <= 5) or
                (process["Runtime (min)"] < 1) or
                process["Memory Anomaly"] == "Yes" or
                process["Fileless Risk"] == "Yes"
            )
        except Exception as e:
            self.log_event(f"Error checking suspicious process {process['PID']}: {e}")
            return False

    def monitor_new_processes(self):
        try:
            # Initial full scan
            processes = self.get_processes()
            seen_pids = set()
            for process in processes:
                pid = process["PID"]
                seen_pids.add(pid)
                proc_hash = self.get_process_hash(pid)
                if proc_hash:
                    positives = self.check_virustotal(proc_hash)
                    if positives > 0:
                        self.flagged_processes[pid] = positives
            self.update_table()
            self.status_label.config(text=f"Last full scan: {datetime.datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            self.log_event(f"Initial scan error: {e}")
            seen_pids = set()

        # Monitor loop: look for new PIDs and scan them immediately
        while True:
            try:
                current_pids = set()
                for proc in psutil.process_iter(attrs=['pid']):
                    current_pids.add(proc.info['pid'])
                new_pids = current_pids - seen_pids
                if new_pids:
                    for pid in new_pids:
                        try:
                            process_list = [p for p in self.get_processes() if p['PID'] == pid]
                            if process_list:
                                proc_info = process_list[0]
                                proc_hash = self.get_process_hash(pid)
                                if proc_hash:
                                    positives = self.check_virustotal(proc_hash)
                                    if positives > 0:
                                        self.flagged_processes[pid] = positives
                                # update table after each new process scan
                                self.update_table()
                                self.status_label.config(text=f"Scanned new PID {pid} at {datetime.datetime.now().strftime('%H:%M:%S')}")
                        except Exception as e:
                            self.log_event(f"Error scanning new process {pid}: {e}")
                    seen_pids.update(new_pids)
                time.sleep(1)
            except Exception as e:
                self.log_event(f"Monitor loop error: {e}")
                time.sleep(2)

    def setup_gui(self):
        self.status_label = tk.Label(self.root, text="Starting scan...")
        self.status_label.pack(pady=5)
        search_frame = tk.Frame(self.root)
        search_frame.pack(pady=10)
        tk.Label(search_frame, text="Search Process:").pack(side=tk.LEFT, padx=5)
        self.search_entry = tk.Entry(search_frame, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<KeyRelease>", lambda e: self.update_table())
        tk.Button(search_frame, text="Search", command=self.update_table).pack(side=tk.LEFT, padx=5)
        table_frame = ttk.Frame(self.root)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.table = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        for col in self.columns:
            self.table.heading(col, text=col)
            self.table.column(col, anchor="w", width=120)
        v_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.table.tag_configure("red", foreground="red")
        self.table.tag_configure("orange", foreground="orange")
        self.table.tag_configure("purple", foreground="purple")
        self.table.tag_configure("black", foreground="black")
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        buttons = [
            ("Refresh", self.update_table),
            ("Show Suspicious", lambda: self.update_table(suspicious_only=True)),
            ("Kill Process", self.kill_process),
            ("Check Process", self.check_process),
            ("Legend", self.show_legend),
        ]
        for text, cmd in buttons:
            tk.Button(btn_frame, text=text, command=cmd).pack(side=tk.LEFT, padx=5)

    def update_table(self, suspicious_only=False):
        self.table.delete(*self.table.get_children())
        processes = self.get_processes()
        keyword = self.search_entry.get().lower()
        if suspicious_only:
            processes = [p for p in processes if self.is_suspicious(p)]
        elif keyword:
            processes = sorted(processes, key=lambda p: keyword not in p["Name"].lower())
        for process in processes:
            color = "black"
            if process["PID"] in self.flagged_processes:
                color = "red"
            elif process["Memory Anomaly"] == "Yes":
                color = "orange"
            elif process["Fileless Risk"] == "Yes":
                color = "purple"
            elif self.is_suspicious(process):
                color = "red"
            self.table.insert("", "end", values=tuple(process[col] for col in self.columns), tags=(color,))

    def kill_process(self):
        selected = self.table.selection()
        if not selected:
            messagebox.showerror("Error", "No process selected!")
            return
        pid = self.table.item(selected[0])["values"][0]
        try:
            os.kill(int(pid), 9)
            self.log_event(f"Terminated process {pid}")
            messagebox.showinfo("Success", f"Process {pid} terminated!")
            self.update_table()
        except Exception as e:
            self.log_event(f"Failed to kill process {pid}: {e}")
            messagebox.showerror("Error", f"Could not kill process: {e}")

    def check_process(self):
        selected = self.table.selection()
        if not selected:
            messagebox.showerror("Error", "No process selected!")
            return
        pid = self.table.item(selected[0])["values"][0]
        process_hash = self.get_process_hash(pid)
        if not process_hash:
            messagebox.showerror("Error", "Could not retrieve process hash!")
            return
        result = self.check_virustotal(process_hash)
        self.log_event(f"Checked process {pid}, result: {result}")
        if result == -1:
            messagebox.showinfo("Result", "Process not found in VirusTotal.")
        elif result > 0:
            messagebox.showwarning("Warning", f"Process flagged by {result} scanners!")
        else:
            messagebox.showinfo("Result", "Process appears secure.")

    def show_legend(self):
        
        legend = tk.Toplevel(self.root)
        legend.title("Legend: Color / Criteria")
        legend.geometry("600x320")
        frame = tk.Frame(legend, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)

        entries = [
            ("red", "Flagged / Suspicious" ,
             "Red marks processes that were flagged by VirusTotal OR match the suspicious criteria.\n" \
             "Suspicious criteria (any of): contains suspicious keyword in name/path; uses suspicious port;\n" \
             "starts between 01:00 and 05:59 (hour value in 1..5); runtime < 1 minute; memory anomaly detected; or fileless (no executable path)."),
            ("orange", "Memory Anomaly",
             "Memory spike detected: process memory increased sharply compared to last observation (threshold set by MEMORY_SPIKE_THRESHOLD)."),
            ("purple", "Fileless Risk",
             "Process appears 'fileless' (no executable path available) which can indicate injection or evasive activity."),
            ("black", "Normal / Unflagged",
             "No suspicious indicators found for this process at the last scan."),
        ]

        for color, title, desc in entries:
            row = tk.Frame(frame, pady=6)
            row.pack(fill=tk.X)
            swatch = tk.Label(row, width=3, bg=color)
            swatch.pack(side=tk.LEFT, padx=(0,8))
            txt = tk.Label(row, text=title, font=(None, 10, 'bold'))
            txt.pack(anchor='w')
            desc_lbl = tk.Label(row, text=desc, justify='left', wraplength=520)
            desc_lbl.pack(anchor='w', padx=(28,0))

        note = tk.Label(frame, text="Note: 'Flagged by VirusTotal' means one or more scanners reported maliciousness.", fg='gray')
        note.pack(anchor='w', pady=(8,0))

    def start_background_scan(self):
        monitor_thread = threading.Thread(target=self.monitor_new_processes, daemon=True)
        monitor_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = ThreatMonitor(root)
    root.mainloop()