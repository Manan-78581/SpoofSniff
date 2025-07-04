# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import os
import sys
import time
import platform # To check OS for privilege warning

from sniffer import start_sniffer, stop_sniffer_event
from resolver import load_dns_cache, save_dns_cache, TRUSTED_DNS_SERVERS # Import global trusted servers

# --- Configuration File for Trusted DNS Servers ---
CONFIG_FILE = "config.json"

# Function to load configuration (Trusted DNS Servers)
def load_config():
    import json
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            try:
                config = json.load(f)
                return config.get('trusted_dns_servers', [])
            except json.JSONDecodeError:
                return []
    return []

# Function to save configuration (Trusted DNS Servers)
def save_config(trusted_servers):
    import json
    with open(CONFIG_FILE, 'w') as f:
        json.dump({'trusted_dns_servers': trusted_servers}, f, indent=4)

# --- Main GUI Application Class ---
class SpoofSniffGUI:
    def __init__(self, master):
        self.master = master
        master.title("SpoofSniff - DNS Spoofing Detection")
        master.geometry("1000x700") # Set initial window size
        master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close event

        self.sniffer_thread = None
        self.sniffer_running = False
        self.message_queue = queue.Queue() # Queue for communication from sniffer to GUI

        # --- Configure ttk Style (Theme) ---
        self.style = ttk.Style()
        self.style.theme_use('clam') # Try 'clam', 'alt', 'flat', 'vista', 'xpnative', 'aqua' (macOS)
        
        # Configure fonts and colors
        self.style.configure('.', font=('Segoe UI', 10)) # Default font for all widgets
        self.style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=5)
        self.style.configure('TLabel', font=('Segoe UI', 10), foreground='#333333')
        self.style.configure('TFrame', background='#f0f0f0') # Light gray background for frames
        
        # --- Main Layout Frames ---
        self.top_frame = ttk.Frame(master, padding="10 10 10 10", style='TFrame')
        self.top_frame.pack(fill=tk.X, expand=False)

        self.log_frame = ttk.Frame(master, padding="10 10 10 10", style='TFrame')
        self.log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.bottom_frame = ttk.Frame(master, padding="10 10 10 10", style='TFrame')
        self.bottom_frame.pack(fill=tk.X, expand=False)

        # --- Top Frame Widgets (Buttons) ---
        self.start_button = ttk.Button(self.top_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = ttk.Button(self.top_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.clear_log_button = ttk.Button(self.top_frame, text="Clear Log", command=self.clear_log)
        self.clear_log_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.configure_dns_button = ttk.Button(self.top_frame, text="Configure Trusted DNS", command=self.open_dns_config_window)
        self.configure_dns_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # --- Log Frame (Scrolled Text Area) ---
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD, state='disabled',
                                                 font=('Consolas', 10), bg='#ffffff', fg='#333333',
                                                 relief=tk.FLAT, bd=2)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Configure tags for different message types
        self.log_text.tag_config('info', foreground='#000080') # Dark blue
        self.log_text.tag_config('alert', foreground='#FF4500', font=('Consolas', 10, 'bold')) # Orange-red, bold
        self.log_text.tag_config('error', foreground='#DC143C', font=('Consolas', 10, 'bold')) # Crimson red, bold
        self.log_text.tag_config('status', foreground='#006400') # Dark green

        # --- Status Bar ---
        self.status_label = ttk.Label(self.bottom_frame, text="Idle", anchor=tk.W, foreground='#555555')
        self.status_label.pack(fill=tk.X, padx=5, pady=2)

        # Start monitoring the queue for messages from the sniffer thread
        self.master.after(100, self.log_queue_monitor)
        
        # Load trusted DNS servers at startup
        self.trusted_dns_servers = load_config()
        if not self.trusted_dns_servers: # If config is empty, use default global list initially
            self.trusted_dns_servers = list(set(TRUSTED_DNS_SERVERS)) # Ensure unique
            self.log_message(f"No trusted DNS servers found in {CONFIG_FILE}. Using default global list. "
                             f"Please configure trusted DNS servers.", "info")
            self.update_sniffer_trusted_servers() # Update sniffer module if needed
            self.save_current_trusted_servers() # Save this initial list
        else:
            self.log_message(f"Loaded trusted DNS servers from {CONFIG_FILE}: {self.trusted_dns_servers}", "info")
            self.update_sniffer_trusted_servers() # Update sniffer module

        # Initial privilege check (moved here for early warning)
        self.check_privileges()

    def check_privileges(self):
        """Checks for root/administrator privileges and displays a warning if not present."""
        is_admin = False
        if platform.system() == "Linux" or platform.system() == "Darwin": # macOS is Darwin
            if os.geteuid() == 0:
                is_admin = True
        elif platform.system() == "Windows":
            try:
                # Check if Windows directory is writable (proxy for admin rights)
                # This is a common heuristic, but not foolproof. Real check needs pywin32.
                if os.access('C:\\Windows', os.W_OK):
                    is_admin = True
            except OSError:
                pass # If C:\Windows doesn't exist or is inaccessible early on
        
        if not is_admin:
            warning_msg = "\n[!] WARNING: Running SpoofSniff requires root/Administrator privileges to capture packets."
            if platform.system() == "Linux" or platform.system() == "Darwin":
                warning_msg += "\n    Please run with 'sudo python3 main.py'."
            elif platform.system() == "Windows":
                warning_msg += "\n    If you encounter issues, try running your command prompt/PowerShell as Administrator."
            self.log_message(warning_msg, "alert")


    def log_message(self, message, msg_type="info"):
        """Inserts a message into the log_text widget with a specific tag."""
        self.log_text.configure(state='normal') # Enable editing
        self.log_text.insert(tk.END, message + "\n", msg_type)
        self.log_text.configure(state='disabled') # Disable editing
        self.log_text.see(tk.END) # Auto-scroll to the end

    def set_status(self, message, msg_type="info"):
        """Updates the status bar."""
        self.status_label.config(text=message, foreground=self.log_text.tag_cget(msg_type, "foreground"))

    def log_queue_monitor(self):
        """Monitors the message queue for updates from the sniffer thread."""
        while not self.message_queue.empty():
            message, msg_type = self.message_queue.get_nowait()
            self.log_message(message, msg_type)
            if msg_type == "error":
                self.set_status("Error occurred!", "error")
        
        # Reschedule itself to run again after 100ms
        self.master.after(100, self.log_queue_monitor)

    def start_monitoring(self):
        if not self.sniffer_running:
            self.log_message("Loading DNS cache...", "info")
            load_dns_cache() # Load cache at start
            self.log_message("DNS cache loaded.", "info")

            self.sniffer_running = True
            stop_sniffer_event.clear() # Ensure event is clear for new start

            self.sniffer_thread = threading.Thread(target=start_sniffer, args=(self.message_queue,), daemon=True)
            self.sniffer_thread.start()

            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.set_status("Monitoring started.", "status")
            self.log_message("Monitoring started.", "status")
            self.log_message(f"Trusted Local DNS Servers for monitoring: {self.trusted_dns_servers}", "info")


    def stop_monitoring(self):
        if self.sniffer_running:
            self.log_message("Attempting to stop SpoofSniff gracefully...", "info")
            self.set_status("Stopping monitoring...", "info")
            stop_sniffer_event.set() # Signal the sniffer to stop

            # Wait for the thread to finish (with a timeout)
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(timeout=2) # Give it 2 seconds to stop
            
            # Save cache before truly stopping and resetting state
            save_dns_cache()
            self.log_message("DNS cache saved.", "info")

            self.sniffer_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.set_status("Monitoring stopped.", "status")
            self.log_message("SpoofSniff has stopped.", "status")

    def clear_log(self):
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')
        self.log_message("Log cleared.", "info")

    def on_closing(self):
        """Called when the user clicks the window's close button."""
        if self.sniffer_running:
            self.stop_monitoring() # Gracefully stop sniffer first
            # Give it a moment to ensure the thread finishes and messages are processed
            time.sleep(0.5) 
        self.master.destroy() # Close the GUI window

    # --- DNS Configuration Window ---
    def open_dns_config_window(self):
        config_window = tk.Toplevel(self.master)
        config_window.title("Configure Trusted DNS Servers")
        config_window.geometry("500x400")
        config_window.transient(self.master) # Make it appear on top of the main window
        config_window.grab_set() # Make it modal

        # Frame for entry and add button
        entry_frame = ttk.Frame(config_window, padding="10")
        entry_frame.pack(fill=tk.X)

        ttk.Label(entry_frame, text="Add new DNS IP:").pack(side=tk.LEFT, padx=5)
        self.new_dns_entry = ttk.Entry(entry_frame, width=30)
        self.new_dns_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(entry_frame, text="Add", command=self.add_trusted_dns).pack(side=tk.LEFT, padx=5)

        # Frame for listbox
        list_frame = ttk.Frame(config_window, padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(list_frame, text="Current Trusted DNS Servers:").pack(anchor=tk.W, pady=5)
        self.dns_listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE, height=10,
                                       font=('Consolas', 10), bg='#ffffff', fg='#333333',
                                       relief=tk.FLAT, bd=2)
        self.dns_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        dns_list_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.dns_listbox.yview)
        dns_list_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.dns_listbox.config(yscrollcommand=dns_list_scrollbar.set)

        self.populate_dns_listbox()

        # Remove button
        remove_button_frame = ttk.Frame(config_window, padding="10")
        remove_button_frame.pack(fill=tk.X)
        ttk.Button(remove_button_frame, text="Remove Selected", command=self.remove_trusted_dns).pack(pady=5)

        # Instructions/Info
        info_label = ttk.Label(config_window, text="Changes apply after monitoring restart.", font=('Segoe UI', 9, 'italic'))
        info_label.pack(pady=5)


    def populate_dns_listbox(self):
        self.dns_listbox.delete(0, tk.END)
        for dns_ip in self.trusted_dns_servers:
            self.dns_listbox.insert(tk.END, dns_ip)

    def add_trusted_dns(self):
        new_ip = self.new_dns_entry.get().strip()
        if new_ip and new_ip not in self.trusted_dns_servers:
            # Basic validation (can be enhanced)
            if self.is_valid_ip(new_ip):
                self.trusted_dns_servers.append(new_ip)
                self.populate_dns_listbox()
                self.save_current_trusted_servers()
                self.update_sniffer_trusted_servers()
                self.new_dns_entry.delete(0, tk.END)
                self.log_message(f"Added '{new_ip}' to trusted DNS servers. Restart monitoring for changes to apply.", "info")
            else:
                messagebox.showwarning("Invalid IP", "Please enter a valid IPv4 or IPv6 address.")
        elif new_ip in self.trusted_dns_servers:
            messagebox.showinfo("Duplicate", "This IP is already in the list.")

    def remove_trusted_dns(self):
        selected_indices = self.dns_listbox.curselection()
        if selected_indices:
            index = selected_indices[0]
            removed_ip = self.trusted_dns_servers.pop(index)
            self.populate_dns_listbox()
            self.save_current_trusted_servers()
            self.update_sniffer_trusted_servers()
            self.log_message(f"Removed '{removed_ip}' from trusted DNS servers. Restart monitoring for changes to apply.", "info")
        else:
            messagebox.showwarning("No Selection", "Please select an IP to remove.")

    def is_valid_ip(self, ip_string):
        """Basic validation for IPv4 and IPv6 addresses."""
        import ipaddress
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    def save_current_trusted_servers(self):
        # Update the trusted DNS servers in the sniffer module directly
        # so that it uses the latest list when monitoring starts
        save_config(self.trusted_dns_servers)
        
    def update_sniffer_trusted_servers(self):
        # This is crucial: update the sniffer module's global list
        # It needs to be a flat list of unique strings
        import sniffer
        sniffer.TRUSTED_LOCAL_DNS_SERVERS = list(set(self.trusted_dns_servers))
        self.log_message(f"Sniffer module's trusted DNS list updated internally. "
                         f"Current sniffer list: {sniffer.TRUSTED_LOCAL_DNS_SERVERS}", "info")


def run_gui():
    root = tk.Tk()
    app = SpoofSniffGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()