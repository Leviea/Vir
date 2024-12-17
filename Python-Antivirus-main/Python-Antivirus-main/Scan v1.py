import requests
import hashlib
import time
import tkinter as tk
from tkinter import ttk
from tkinter import Tk, filedialog, messagebox, scrolledtext
import json
import os
from tkinter import Menu
from datetime import datetime

# Replace with your actual API key
API_KEY = "b50bb2a6ea26edf717c86cd35f927d9c157a92de20bb7ae986be917d4796a59c"
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"

def get_file_hash(file_path):
    """Calculate SHA256 hash of the file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for chunk in iter(lambda: file.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None

def check_file_status(file_hash):
    """Check the status of a file using its SHA256 hash."""
    headers = {"x-apikey": API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print("File already scanned. Retrieving report...")
        return response.json()
    elif response.status_code == 404:
        print("File not found in VirusTotal's database.")
        return None
    else:
        print(f"Error checking file status: {response.status_code}, {response.text}")
        return None

def upload_file_to_virustotal(file_path):
    """Upload a file to VirusTotal for scanning."""
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as file:
        files = {"file": file}
        print("Uploading file to VirusTotal...")
        response = requests.post(VT_FILE_SCAN_URL, headers=headers, files=files)
    
    if response.status_code == 200:
        file_id = response.json()["data"]["id"]
        print("File uploaded successfully. Waiting for scan to complete...")
        return file_id
    else:
        print(f"Error uploading file: {response.status_code}, {response.text}")
        return None

def wait_for_scan(file_id):
    """Wait for the scan report to become available."""
    headers = {"x-apikey": API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_id}"  # Correct URL for fetching report
    
    for _ in range(20):  # Poll for 5 minutes (20 tries, 15 seconds each)
        print("Checking scan status...")
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            print("Scan complete!")
            return response.json()
        elif response.status_code == 404:
            print("Scan not ready yet. Waiting for 15 seconds...")
            time.sleep(15)
        else:
            print(f"Error fetching report: {response.status_code}, {response.text}")
            return None
    print("Scan timed out. Please try again later.")
    return None

def scan_file_with_virustotal(file_path):
    """Orchestrates the VirusTotal scanning process for a single file."""
    file_hash = get_file_hash(file_path)
    if not file_hash:
        return
    
    print(f"File: {file_path}")
    print(f"SHA256 Hash: {file_hash}")
    
    # Check if the file has already been scanned
    report = check_file_status (file_hash)
    
    if report:
        display_report(report, file_path)  # Display the existing report from VirusTotal
    else:
        file_id = upload_file_to_virustotal(file_path)
        if file_id:
            report = wait_for_scan(file_id)
            if report:
                display_report(report, file_path)  # Display the new scan result

def scan_directory_with_virustotal(directory_path):
    """Scan all files in a directory using VirusTotal."""
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            print(f"\nScanning file: {file_path}")
            scan_file_with_virustotal(file_path)

class ModernScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VT Scanner")
        self.root.geometry("1000x700")
        
        # Konfigurasi tema modern
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Warna-warna modern
        self.colors = {
            'bg': '#1e1e1e',
            'secondary': '#252526',
            'accent': '#007acc',
            'text': '#ffffff',
            'text_secondary': '#cccccc',
            'success': '#4EC9B0',
            'warning': '#CE9178',
            'error': '#F44747'
        }
        
        # Konfigurasi style
        self.root.configure(bg=self.colors['bg'])
        self.style.configure('TFrame', background=self.colors['bg'])
        self.style.configure('TLabel', 
                           background=self.colors['bg'], 
                           foreground=self.colors['text'])
        
        # Custom button style
        self.style.configure('Modern.TButton',
                           background=self.colors['accent'],
                           foreground=self.colors['text'],
                           padding=(20, 10),
                           font=('Segoe UI', 10))
        
        # Progress bar style
        self.style.configure('Modern.Horizontal.TProgressbar',
                           background=self.colors['accent'],
                           troughcolor=self.colors['secondary'])
        
        self.setup_gui()
        self.setup_menu()
        
    def setup_gui(self):
        # Main container dengan padding
        container = ttk.Frame(self.root, padding="20", style='TFrame')
        container.grid(row=0, column=0, sticky="nsew")
        
        # Grid configuration
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        # Header dengan logo (opsional) dan judul
        header_frame = ttk.Frame(container, style='TFrame')
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        title_label = ttk.Label(header_frame, 
                              text="VT Scanner",
                              font=('Segoe UI', 24, 'bold'),
                              style='TLabel')
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(header_frame,
                                 text="Powered by VirusTotal API",
                                 font=('Segoe UI', 10),
                                 foreground=self.colors['text_secondary'])
        subtitle_label.pack()
        
        # Button container dengan efek hover
        button_frame = ttk.Frame(container, style='TFrame')
        button_frame.grid(row=1, column=0, pady=(0, 20))
        
        scan_file_btn = ttk.Button(button_frame,
                                 text="Scan File",
                                 command=self.scan_file,
                                 style='Modern.TButton')
        scan_file_btn.pack(side=tk.LEFT, padx=5)
        
        scan_dir_btn = ttk.Button(button_frame,
                                text="Scan Directory",
                                command=self.scan_directory,
                                style='Modern.TButton')
        scan_dir_btn.pack(side=tk.LEFT, padx=5)
        
        # Tambahkan tombol Save
        save_btn = ttk.Button(button_frame,
                            text="Save Results",
                            command=self.save_results,
                            style='Modern.TButton')
        save_btn.pack(side=tk.LEFT, padx=5)
        
        # Tambahkan tombol Clear
        clear_btn = ttk.Button(button_frame,
                             text="Clear",
                             command=self.clear_results,
                             style='Modern.TButton')
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Status frame
        status_frame = ttk.Frame(container, style='TFrame')
        status_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame,
                                    text="Ready to scan",
                                    font=('Segoe UI', 10),
                                    foreground=self.colors['text_secondary'])
        self.status_label.pack(side=tk.LEFT)
        
        # Modern progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(container,
                                      length=300,
                                      mode='determinate',
                                      variable=self.progress_var,
                                      style='Modern.Horizontal.TProgressbar')
        self.progress.grid(row=3, column=0, sticky="ew", pady=(0, 20))
        
        # Results area dengan custom styling
        self.result_text = scrolledtext.ScrolledText(
            container,
            height=20,
            font=('Consolas', 10),
            bg=self.colors['secondary'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            selectbackground=self.colors['accent'],
            selectforeground=self.colors['text'],
            relief='flat',
            padx=10,
            pady=10
        )
        self.result_text.grid(row=4, column=0, sticky="nsew")
        
        # Custom tag configurations untuk hasil pemindaian
        self.result_text.tag_configure('success', foreground=self.colors['success'])
        self.result_text.tag_configure('warning', foreground=self.colors['warning'])
        self.result_text.tag_configure('error', foreground=self.colors['error'])
        
    def setup_menu(self):
        """Setup menu bar"""
        menubar = Menu(self.root, bg=self.colors['secondary'], fg=self.colors['text'])
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0, bg=self.colors['secondary'], 
                        fg=self.colors['text'], activebackground=self.colors['accent'])
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0, bg=self.colors['secondary'], 
                        fg=self.colors['text'], activebackground=self.colors['accent'])
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def save_results(self):
        """Menyimpan hasil pemindaian ke file"""
        if not self.result_text.get(1.0, tk.END).strip():
            messagebox.showwarning("Peringatan", "Tidak ada hasil pemindaian untuk disimpan!")
            return
            
        # Buat nama file default dengan timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"scan_result_{timestamp}.txt"
        
        # Dialog save file
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=default_filename,
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                # Dapatkan semua teks dengan tag warnanya
                content = []
                text = self.result_text.get(1.0, tk.END)
                
                # Header file
                content.append("=== VT Scanner Results ===")
                content.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                content.append("=" * 30 + "\n")
                
                # Tambahkan isi hasil pemindaian
                content.append(text)
                
                # Tulis ke file
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write('\n'.join(content))
                
                self.update_status(f"Hasil pemindaian berhasil disimpan ke: {file_path}", 'success')
                
            except Exception as e:
                messagebox.showerror("Error", f"Gagal menyimpan file: {str(e)}")
                self.update_status(f"Error menyimpan file: {str(e)}", 'error')

    def show_about(self):
        """Menampilkan dialog About"""
        about_text = """
        VT Scanner
        Beta Version 0.01
        
        A (Not) virus scanning tool powered by VirusTotal API.
        
        © 2024 Kelompok AMD
        22.83.0902
              0920
              0945
        """
        messagebox.showinfo("About VT Scanner", about_text.strip())
        
    def update_status(self, message, status_type='normal'):
        """Update status dengan warna sesuai tipe status"""
        color = {
            'normal': self.colors['text_secondary'],
            'success': self.colors['success'],
            'warning': self.colors['warning'],
            'error': self.colors['error']
        }.get(status_type, self.colors['text_secondary'])
        
        self.status_label.configure(foreground=color)
        self.status_label.configure(text=message)
        
        timestamp = time.strftime('%H:%M:%S')
        self.result_text.insert(tk.END, f"[{timestamp}] {message}\n", status_type)
        self.result_text.see(tk.END)
        self.root.update()

    def display_report(self, report, file_path):
        """Tampilkan hasil pemindaian dengan formatting yang lebih baik"""
        stats = report["data"]["attributes"]["last_analysis_stats"]
        
        self.result_text.insert(tk.END, "\n═══════════ SCAN REPORT ═══════════\n", 'normal')
        self.result_text.insert(tk.END, f"File: {file_path}\n\n", 'normal')
        
        # Tampilkan statistik dengan warna yang sesuai
        if stats['malicious'] > 0:
            self.result_text.insert(tk.END, f"Malicious: {stats['malicious']}\n", 'error')
        else:
            self.result_text.insert(tk.END, f"Malicious: {stats['malicious']}\n", 'success')
            
        self.result_text.insert(tk.END, f"Suspicious: {stats['suspicious']}\n", 'warning')
        self.result_text.insert(tk.END, f"Harmless: {stats['harmless']}\n", 'success')
        self.result_text.insert(tk.END, f"Undetected: {stats['undetected']}\n", 'normal')
        self.result_text.insert(tk.END, "═══════════════════════════════\n\n", 'normal')
        
        self.result_text.see(tk.END)
        
        if stats["malicious"] > 0:
            if messagebox.askyesno("⚠️ Malicious File Detected",
                                 f"The file '{os.path.basename(file_path)}' is flagged as malicious.\n"
                                 f"Would you like to delete it?",
                                 icon='warning'):
                try:
                    os.remove(file_path)
                    self.update_status(f"File '{file_path}' has been removed.", 'success')
                except Exception as e:
                    self.update_status(f"Error deleting file: {e}", 'error')

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.result_text.delete(1.0, tk.END)
            self.update_status(f"Memindai file: {file_path}")
            
            # Hitung hash
            file_hash = get_file_hash(file_path)
            if not file_hash:
                self.update_status("Error menghitung hash file")
                return
                
            # Cek status
            self.update_status("Memeriksa file di VirusTotal...")
            report = check_file_status(file_hash)
            
            if report:
                self.display_report(report, file_path)
            else:
                # Upload dan pindai
                self.update_status("Mengunggah file ke VirusTotal...")
                file_id = upload_file_to_virustotal(file_path)
                if file_id:
                    report = wait_for_scan(file_id)
                    if report:
                        self.display_report(report, file_path)
                    else:
                        self.update_status("Timeout menunggu hasil pemindaian")
                else:
                    self.update_status("Gagal mengunggah file")

    def scan_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.result_text.delete(1.0, tk.END)
            self.update_status(f"Memindai direktori: {directory}")
            
            # Dapatkan semua file dalam direktori dan subdirektori
            files_to_scan = []
            for root, _, files in os.walk(directory):
                for file in files:
                    files_to_scan.append(os.path.join(root, file))
            
            total_files = len(files_to_scan)
            if total_files == 0:
                self.update_status("Tidak ada file yang ditemukan di direktori")
                return
                
            self.update_status(f"Ditemukan {total_files} file untuk dipindai")
            
            for i, file_path in enumerate(files_to_scan, 1):
                self.progress_var.set((i/total_files) * 100)
                self.update_status(f"[{i}/{total_files}] Memindai: {file_path}")
                
                # Hitung hash
                file_hash = get_file_hash(file_path)
                if not file_hash:
                    self.update_status(f"Error menghitung hash untuk: {file_path}")
                    continue
                    
                # Cek status
                report = check_file_status(file_hash)
                
                if report:
                    self.display_report(report, file_path)
                else:
                    # Upload dan pindai
                    self.update_status(f"Mengunggah file: {file_path}")
                    file_id = upload_file_to_virustotal(file_path)
                    if file_id:
                        report = wait_for_scan(file_id)
                        if report:
                            self.display_report(report, file_path)
                        else:
                            self.update_status(f"Timeout menunggu hasil untuk: {file_path}")
                    else:
                        self.update_status(f"Gagal mengunggah: {file_path}")
                
                # Update GUI
                self.root.update()
            
            self.update_status("Pemindaian selesai")
            self.progress_var.set(0)

    def scan_file_with_progress(self, file_path):
        """Tidak digunakan lagi - logika pemindaian sekarang ada di scan_directory"""
        pass

    def clear_results(self):
        """Membersihkan area hasil"""
        if self.result_text.get(1.0, tk.END).strip():
            if messagebox.askyesno("Konfirmasi", "Hapus semua hasil pemindaian?"):
                self.result_text.delete(1.0, tk.END)
                self.progress_var.set(0)
                self.update_status("Hasil pemindaian dibersihkan", 'normal')

    def run(self):
        self.root.mainloop()

def main():
    app = ModernScannerGUI()
    app.run()

if __name__ == "__main__":
    main()