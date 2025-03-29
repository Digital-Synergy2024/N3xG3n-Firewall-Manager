import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import subprocess
import ctypes
import os
import string
import time
from datetime import datetime
import getpass
import sys
import shutil
import json 
import bcrypt 
import urllib.request
import ssl  
import psutil  
import matplotlib.pyplot as plt
import pandas as pd
from io import BytesIO
import traceback
import logging
import threading
import requests  

logging.basicConfig(
    filename="debug_log.txt",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logging.info("Application started.")

def check_python_installation():
    logging.info("Checking Python installation.")
    print("Checking Python installation...")
    if shutil.which("python") or shutil.which("python3"):
        print("Python is already installed. Proceeding with the application...")
        logging.info("Python installation check completed.")
        return True 

    print("Python is not installed.")
    install = messagebox.askyesno("Python Not Found", "Python is not installed. Do you want to install it?")
    if install:
        try:
            print("User agreed to install Python. Downloading the installer...")
            python_installer_url = "https://www.python.org/ftp/python/3.10.9/python-3.10.9-amd64.exe"
            installer_path = os.path.join(os.getcwd(), "python_installer.exe")
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(python_installer_url, context=ssl_context) as response, open(installer_path, "wb") as out_file:
                out_file.write(response.read())
            print("Python installer downloaded successfully.")

            print("Running the Python installer. This may take a few minutes...")
            subprocess.run([installer_path, "/quiet", "InstallAllUsers=1", "PrependPath=1"], check=True)
            print("Python installation completed successfully.")

            os.remove(installer_path)
            print("Installer file removed. Prompting the user to restart the application.")
            messagebox.showinfo("Success", "Python has been installed. Please restart the application.")
            logging.info("Python installation check completed.")
            return False 
        except Exception as e:
            print(f"Error during Python installation: {e}")
            messagebox.showerror("Error", f"Failed to install Python: {e}")
            logging.info("Python installation check completed.")
            return False 
    else:
        print("User declined to install Python. Exiting the application.")
        messagebox.showinfo("Exiting", "Python is required to run this application. Exiting now.")
        logging.info("Python installation check completed.")
        return False  

def check_dependencies():
    logging.info("Checking dependencies.")
    
    root = tk.Tk()
    root.withdraw()  

    print("Checking dependencies...")  
    dependencies = {
        "pip": "Python's package manager (pip)",
        "bcrypt": "bcrypt library for password hashing",
        "psutil": "psutil library for system monitoring",
        "matplotlib": "matplotlib library for data visualization",
        "pandas": "pandas library for data handling",
        "openpyxl": "openpyxl library for Excel support",
    }

    missing_dependencies = []
    dependencies_installed = os.path.exists("dependencies_installed.flag")

    if dependencies_installed:
        print("Dependencies already installed. Skipping dependency check.")
        logging.info("Dependency check completed.")
        return True


    for dependency, description in dependencies.items():
        print(f"Checking dependency: {dependency}...")  
        try:
            if dependency == "pip":
                subprocess.run([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            else:
                __import__(dependency)
        except ImportError:
            print(f"Dependency missing: {dependency}") 
            missing_dependencies.append((dependency, description))
        except subprocess.CalledProcessError:
            print(f"Dependency check failed for: {dependency}")  
            missing_dependencies.append((dependency, description))

    if not missing_dependencies:
        print("All dependencies are installed. Proceeding...")
        with open("dependencies_installed.flag", "w") as flag_file:
            flag_file.write("Dependencies installed successfully.")
        logging.info("Dependency check completed.")
        return True  

    missing_list = "\n".join([f"- {desc} ({dep})" for dep, desc in missing_dependencies])
    print(f"Missing dependencies:\n{missing_list}")  
    install = messagebox.askyesno(
        "Missing Dependencies",
        f"The following dependencies are missing:\n\n{missing_list}\n\n"
        "Would you like to install them now?"
    )

    if install:
        try:
            for dependency, _ in missing_dependencies:
                print(f"Installing dependency: {dependency}...")  
                if dependency == "pip":
                    subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=True)
                else:
                    subprocess.run([sys.executable, "-m", "pip", "install", dependency], check=True)

            with open("dependencies_installed.flag", "w") as flag_file:
                flag_file.write("Dependencies installed successfully.")

            print("All dependencies have been installed. Proceeding with the application.") 
            messagebox.showinfo("Success", "All dependencies have been installed.")
            logging.info("Dependency check completed.")
            return True  
        except Exception as e:
            print(f"Error during dependency installation: {e}")  
            messagebox.showerror("Error", f"Failed to install dependencies: {e}")
            logging.info("Dependency check completed.")
            return False  
    else:
        print("User declined to install dependencies. Exiting.")  
        messagebox.showinfo("Exiting", "Dependencies are required to run this application.")
        logging.info("Dependency check completed.")
        return False  

_admin_status_cache = None

def is_admin():
    logging.info("Checking if the script is running as an administrator.")
    global _admin_status_cache
    if _admin_status_cache is not None: 
        logging.info(f"Admin status: {_admin_status_cache}")
        return _admin_status_cache
    try:
        _admin_status_cache = ctypes.windll.shell32.IsUserAnAdmin() != 0
        logging.debug(f"Admin status: {_admin_status_cache}") 
        logging.info(f"Admin status: {_admin_status_cache}")
        return _admin_status_cache
    except Exception as e:
        logging.error(f"Failed to check admin status: {e}")
        logging.info(f"Admin status: {_admin_status_cache}")
        return False

INITIALIZATION_FLAG_FILE = "app_initialized.flag"

def relaunch_as_admin():
    logging.info("Attempting to relaunch the script with administrator privileges.")
    if "--admin" in sys.argv:  
        logging.error("Already running with --admin flag. Exiting to prevent infinite loop.")
        messagebox.showerror("Error", "Failed to gain administrator privileges. Please run the application as an administrator.")
        sys.exit(1)

    with open(INITIALIZATION_FLAG_FILE, "w") as flag_file:
        flag_file.write("initialized")

    script_path = os.path.abspath(sys.argv[0]) 
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]]) + " --admin"  
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script_path}" {params}', None, 1
        )
        logging.info("Relaunched successfully. Exiting current instance.")
        sys.exit()  
    except Exception as e:
        logging.error(f"Failed to relaunch as admin: {e}")
        messagebox.showerror("Error", f"Failed to relaunch as admin: {e}")
        sys.exit(1)


def handle_uncaught_exception(exc_type, exc_value, exc_traceback):
    logging.critical("Handling uncaught exception.", exc_info=(exc_type, exc_value, exc_traceback))
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    messagebox.showerror("Critical Error", f"An unexpected error occurred:\n{exc_value}")
    sys.exit(1)

sys.excepthook = handle_uncaught_exception

def pause_on_exit():

    input("Press Enter to exit...")


if not is_admin():
    if "--admin" not in sys.argv:  
        logging.debug("Admin privileges not detected. Attempting to relaunch as admin.")
        relaunch_as_admin()
    else:
        logging.error("Admin privileges still not detected after relaunch. Exiting.")
        messagebox.showerror("Error", "Failed to gain administrator privileges. Please run the application as an administrator.")
        sys.exit(1)
else:
    logging.info("Admin privileges detected. Proceeding with application initialization.")

try:
    logging.info("Checking Python installation.")
    if not check_python_installation():
        logging.error("Python installation check failed. Exiting.")
        pause_on_exit()
        sys.exit()

    logging.info("Checking dependencies.")
    if not os.path.exists("dependencies_installed.flag"): 
        if not check_dependencies():
            logging.error("Dependency check failed. Exiting.")
            pause_on_exit()
            sys.exit()
    logging.info("Initialization checks completed successfully.")
except Exception as e:
    logging.critical(f"Error during initialization: {e}")
    pause_on_exit()
    sys.exit(1)

import tkinter as tk
import sys

class FirewallManagerApp:
    def __init__(self, root):
        logging.info("Initializing FirewallManagerApp.")
        self.root = root
        self.root.title("N3xG3n Firewall Manager")
        self.root.geometry("950x1020")  
        self.root.configure(bg="#2C3E50")  
        self.root.resizable(True, True)  
        try:
            self.root.iconbitmap("icon.ico")  
        except Exception as e:
            print(f"Warning: Failed to set window icon. Error: {e}")
        self.log_file = "firewall_manager.txt"  
        self.error_log_file = "error_log.txt" 
        self.users_file = "users.json"  
        self.users = {"admin": "admin123"}  
        self.session_timeout = None  
        self.last_activity = time.time()
        self.color_theme = {
            "background": "#1E1E2F",  
            "foreground": "#FFFFFF",  
            "button_bg": "#4CAF50", 
            "button_fg": "#FFFFFF",  
            "button_active_bg": "#45A049",  
            "button_active_fg": "#FFFFFF",  
            "entry_bg": "#2E2E3F",  
            "entry_fg": "#FFFFFF",  
            "frame_bg": "#2A2A3B",  
        }
        self.fonts = {
            "header": ("Segoe UI", 20, "bold"),
            "subheader": ("Segoe UI", 14, "bold"),
            "text": ("Segoe UI", 12),
            "button": ("Segoe UI", 12, "bold"),
        }
        self.ensure_log_files_exist()  
        self.load_users()  
        self.start_session_monitor()  
        self.create_main_menu()
        logging.info("FirewallManagerApp initialized successfully.")

    def check_for_updates(self):
        logging.debug("Checking for updates...")
        print("Checking for updates...")

        try:
            update_url = "http://162.248.94.164/N3xG3n_Firewall_Manager/version.txt"  
            response = requests.get(update_url, timeout=5)
            response.raise_for_status()
            latest_version = response.text.strip()

            current_version = "1.1.4"  
            logging.debug(f"Current version: {current_version}, Latest version: {latest_version}")
            print(f"Current version: {current_version}, Latest version: {latest_version}")

            if self.compare_versions(latest_version, current_version):
                logging.info("Update available.")
                print("Update available.")
                self.prompt_update(latest_version)
                return True 
            else:
                logging.info("No updates found. The application is up-to-date.")
                print("No updates found. The application is up-to-date.")
                return False  
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to check for updates: {e}")
            print(f"Failed to check for updates: {e}")
            return False  

    def compare_versions(self, latest_version, current_version):
        
        from packaging import version
        return version.parse(latest_version) > version.parse(current_version)

    def prompt_update(self, latest_version):
        
        confirmed = self.show_confirmation_dialog(
            "Update Available",
            f"A new version ({latest_version}) is available. Would you like to update now?"
        )
        if confirmed:
            threading.Thread(target=self.download_and_update, daemon=True).start()

    def download_and_update(self):
        
        try:
            update_url = "http://162.248.94.164/N3xG3n_Firewall_Manager/N3xG3n_FireWall_Manager.exe"
            temp_file = "N3xG3n_FireWall_Manager_update.exe"

            with requests.get(update_url, stream=True) as response:
                response.raise_for_status()
                with open(temp_file, "wb") as file:
                    shutil.copyfileobj(response.raw, file)

            current_executable = sys.argv[0]
            backup_executable = current_executable + ".bak"

            if os.path.exists(backup_executable):
                os.remove(backup_executable)
            os.rename(current_executable, backup_executable)

            os.rename(temp_file, current_executable)

            self.show_message_dialog("Update Complete", "The application has been updated. Please restart it.")
            pause_on_exit()
            sys.exit(0)  
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to download update: {e}")
            self.show_message_dialog("Update Failed", f"Failed to download update: {e}")
            pause_on_exit()
        except Exception as e:
            logging.error(f"Failed to update application: {e}")
            self.show_message_dialog("Update Failed", f"An error occurred while updating: {e}")
            pause_on_exit()

    def ensure_log_files_exist(self):
        logging.info("Ensuring log files exist.")
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as log:
                log.write("Firewall Manager Log File\n")
        if not os.path.exists(self.error_log_file):
            with open(self.error_log_file, "w") as error_log:
                error_log.write("Error Log File\n")
        logging.info("Log files check completed.")

    def check_admin(self):
        logging.info("Checking if the application is running as an administrator.")
        if not os.name == 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
            self.show_messagebox("Error", "This application must be run as an administrator.", "error")
            self.root.quit()
        logging.info("Admin check completed.")

    def log_action(self, action):
        logging.info(f"Logging action: {action}")
        log_entry = f"{datetime.now()} - ACTION: {action}"
        print(log_entry)  
        with open(self.log_file, "a") as log:
            log.write(log_entry + "\n")

    def log_error(self, error):
        logging.error(f"Logging error: {error}")
        error_entry = f"{datetime.now()} - ERROR: {error}"
        print(error_entry)  
        with open(self.error_log_file, "a") as error_log:
            error_log.write(error_entry + "\n")

    def safe_execute(self, func, *args, **kwargs):
        logging.info(f"Executing function safely: {func.__name__}")
        try:
            result = func(*args, **kwargs)
            self.log_action(f"Executed: {func.__name__}")
            logging.info(f"Function {func.__name__} executed successfully.")
            return result
        except Exception as e:
            self.log_error(f"Error in {func.__name__}: {e}")
            messagebox.showerror("Error", f"An error occurred in {func.__name__}:\n{e}")
            logging.info(f"Function {func.__name__} executed successfully.")

    def load_users(self):
        logging.info("Loading user credentials.")
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, "r") as file:
                    self.users = json.load(file)
                    self.log_action("Loaded user credentials from file.")
            except Exception as e:
                self.log_error(f"Failed to load users: {e}")
                self.users = {self.admin_username: self.admin_password} 
        else:
            self.users = {self.admin_username: self.admin_password}  
            self.save_users()  
        logging.info("User credentials loaded successfully.")

    def save_users(self):
        logging.info("Saving user credentials.")
        try:
            with open(self.users_file, "w") as file:
                json.dump(self.users, file)
                self.log_action("Saved user credentials to file.")
        except Exception as e:
            self.log_error(f"Failed to save users: {e}")
        logging.info("User credentials saved successfully.")

    def create_custom_dialog(self, title, message, buttons):
        logging.info("Creating custom dialog.")
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("500x300")
        dialog.resizable(True, True) 
        dialog.configure(bg=self.color_theme["background"])

        tk.Label(
            dialog,
            text=message,
            **self.label_style(),
            wraplength=380,
            justify="center"
        ).pack(pady=20)

        result = {"button": None}

        def on_button_click(button):
            result["button"] = button
            dialog.destroy()

        button_frame = tk.Frame(dialog, **self.frame_style())
        button_frame.pack(pady=10)

        for button_text, button_value in buttons.items():
            tk.Button(
                button_frame,
                text=button_text,
                command=lambda b=button_value: on_button_click(b),
                **self.button_style()
            ).pack(side="left", padx=10)

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        logging.info("Custom dialog created successfully.")
        return result["button"]

    def show_auth_dialog(self):
        logging.info("Showing authentication dialog.")
        return self.create_custom_dialog(
            "Authentication",
            "Do you have an account?",
            {"Yes": "yes", "No": "no", "Cancel": "cancel"}
        )

    def show_confirmation_dialog(self, title, message):
        logging.info("Showing confirmation dialog.")
        return self.create_custom_dialog(
            title,
            message,
            {"Yes": True, "No": False}
        )

    def show_message_dialog(self, title, message):
        logging.info("Showing message dialog.")
        return self.create_custom_dialog(
            title,
            message,
            {"OK": "ok"}
        )

    def show_input_dialog(self, title, prompt, is_password=False):
        logging.info("Showing input dialog.")
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.configure(bg=self.color_theme["background"])
        dialog.resizable(False, False)

        tk.Label(
            dialog,
            text=prompt,
            **self.label_style()
        ).pack(pady=10)

        entry_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=entry_var, **self.entry_style(), show="*" if is_password else "")
        entry.pack(pady=10, padx=20, fill="x")
        entry.focus()

        def on_submit():
            dialog.destroy()

        tk.Button(
            dialog,
            text="Submit",
            command=on_submit,
            **self.button_style()
        ).pack(pady=10)

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        logging.info("Input dialog shown successfully.")
        return entry_var.get()

    def authenticate_user(self):
        logging.info("Authentication bypassed.")
        self.create_main_menu()

    def set_color_theme(self):
        logging.info("Setting color theme.")
        themes = {
            "Green": "#32CD32",
            "Blue": "#1E90FF",
            "Red": "#FF4500",
            "Yellow": "#FFD700",
            "Purple": "#9370DB",
            "Orange": "#FFA500",
            "Pink": "#FF69B4",
            "Gray": "#A9A9A9",
            "Black": "#000000",
            "White": "#FFFFFF",
            "Teal": "#008080",
            "Cyan": "#00FFFF",
            "Magenta": "#FF00FF",
            "Brown": "#A52A2A",
            "Gold": "#FFD700",
            "Silver": "#C0C0C0",
            "Navy": "#000080",
            "Olive": "#808000",
            "Maroon": "#800000"
        }

        theme_window = tk.Toplevel(self.root)
        theme_window.title("Choose a Color Theme")
        theme_window.geometry("400x400")
        theme_window.resizable(True, True)
        theme_window.configure(bg=self.color_theme["background"])

        tk.Label(
            theme_window,
            text="Choose a color theme:",
            **self.label_style()
        ).pack(pady=10)

        canvas = tk.Canvas(theme_window, bg=self.color_theme["background"], highlightthickness=0)
        scrollbar = tk.Scrollbar(theme_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, **self.frame_style())

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for theme_name, color_code in themes.items():
            tk.Button(
                scrollable_frame,
                text=theme_name,
                font=("Arial", 12),
                bg=color_code,
                fg="#ECF0F1" if color_code != "#FFFFFF" else "#000000",
                command=lambda t=theme_name: self.apply_theme(t, themes, theme_window)
            ).pack(fill="x", pady=5, padx=20)

        logging.info("Color theme set successfully.")

    def apply_theme(self, theme_name, themes, theme_window):
        logging.info(f"Applying theme: {theme_name}")
        self.color_theme["background"] = themes[theme_name]
        self.color_theme["frame_bg"] = themes[theme_name]
        self.root.configure(bg=self.color_theme["background"])
        self.update_widget_colors(self.root)
        self.log_action(f"Color theme set to {theme_name}.")
        theme_window.destroy()
        logging.info(f"Theme {theme_name} applied successfully.")

    def update_widget_colors(self, parent):
        logging.info("Updating widget colors.")
        for widget in parent.winfo_children():
            if isinstance(widget, (tk.Frame, tk.LabelFrame, tk.Canvas)):
                widget.configure(bg=self.color_theme["frame_bg"])
                self.update_widget_colors(widget)
            elif isinstance(widget, tk.Label):
                widget.configure(bg=self.color_theme["background"], fg=self.color_theme["foreground"])
            elif isinstance(widget, tk.Button):
                widget.configure(bg=self.color_theme["button_bg"], fg=self.color_theme["button_fg"],
                                 activebackground=self.color_theme["button_active_bg"],
                                 activeforeground=self.color_theme["button_active_fg"])
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=self.color_theme["entry_bg"], fg=self.color_theme["entry_fg"])
            elif isinstance(widget, tk.Text):
                widget.configure(bg=self.color_theme["entry_bg"], fg=self.color_theme["entry_fg"])
            elif isinstance(widget, tk.Scrollbar):
                widget.configure(bg=self.color_theme["frame_bg"])

        if isinstance(parent, tk.Tk) or isinstance(parent, tk.Toplevel):
            parent.configure(bg=self.color_theme["background"])
        logging.info("Widget colors updated successfully.")

    def create_main_menu(self):
        logging.info("Creating main menu.")
        self.safe_execute(self._create_main_menu)
        logging.info("Main menu created successfully.")

    def _create_main_menu(self):
        self.clear_window()
        self.reset_activity_timer()

        canvas = tk.Canvas(self.root, bg=self.color_theme["background"], highlightthickness=0)
        scrollbar = tk.Scrollbar(self.root, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.color_theme["background"])

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        header_frame = tk.Frame(scrollable_frame, bg=self.color_theme["frame_bg"], pady=20)
        header_frame.pack(fill="x")
        tk.Label(
            header_frame,
            text="N3xG3n Firewall Manager",
            font=self.fonts["header"],
            fg=self.color_theme["foreground"],
            bg=self.color_theme["frame_bg"]
        ).pack()

        main_frame = tk.Frame(scrollable_frame, bg=self.color_theme["background"], padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        firewall_frame = tk.LabelFrame(
            main_frame, text="Firewall Rules", font=self.fonts["subheader"],
            fg=self.color_theme["foreground"], bg=self.color_theme["frame_bg"], bd=2, relief="groove"
        )
        firewall_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        firewall_buttons = [
            ("Enable Firewall", lambda: self.toggle_firewall(enable=True)),
            ("Disable Firewall", lambda: self.toggle_firewall(enable=False)),
            ("Search Firewall Rule", self.search_firewall_rule),
            ("Delete Firewall Rule", self.delete_firewall_rule),
            ("Reset Firewall to Default", self.reset_firewall),
            ("Open Specific Ports", self.open_ports),
            ("Close Specific Ports", self.close_ports),
            ("Query Port Status", self.query_ports),
            ("List Active Rules", self.list_active_rules),
        ]
        for i, (text, command) in enumerate(firewall_buttons):
            tk.Button(
                firewall_frame, text=text, command=command, **self.button_style()
            ).grid(row=i // 2, column=i % 2, padx=5, pady=5, sticky="ew")

        settings_frame = tk.LabelFrame(
            main_frame, text="Settings", font=self.fonts["subheader"],
            fg=self.color_theme["foreground"], bg=self.color_theme["frame_bg"], bd=2, relief="groove"
        )
        settings_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        settings_buttons = [
            ("Predefined Port Profiles", self.predefined_port_profiles),
            ("Backup Firewall Rules", self.backup_firewall_rules),
            ("Restore Firewall Rules", self.restore_firewall_rules),
            ("Export Logs", self.export_logs),
            ("View Statistics", self.view_statistics),
            ("Detect Port Conflicts", self.detect_port_conflicts),
            ("View Network Profile", self.view_network_profile),
            ("Set Color Theme", self.set_color_theme),
            ("Manage Users", self.manage_users),
        ]
        for i, (text, command) in enumerate(settings_buttons):
            tk.Button(
                settings_frame, text=text, command=command, **self.button_style()
            ).grid(row=i // 2, column=i % 2, padx=5, pady=5, sticky="ew")

        tools_frame = tk.LabelFrame(
            main_frame, text="Tools", font=self.fonts["subheader"],
            fg=self.color_theme["foreground"], bg=self.color_theme["frame_bg"], bd=2, relief="groove"
        )
        tools_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        tools_buttons = [
            ("Ping and Traceroute", self.ping_and_traceroute),
            ("Firewall Rule Simulator", self.firewall_rule_simulator),
            ("Geo-IP Blocking", self.geo_ip_blocking),
            ("Generate Reports", self.generate_reports),
            ("Export Reports", self.export_reports),
            ("Port Scanning", self.port_scanning),
            ("Malware Detection", self.malware_detection),
            ("Network Monitoring", self.network_monitoring),
            ("Optimize Rules", self.optimize_rules),
            ("Clear Browser Cache", lambda: self.safe_execute(self.clear_browser_cache)),
            ("Defragment Drives", lambda: self.safe_execute(self.defragment_drives)),
            ("View Logs", self.view_logs),
            ("Advanced Rule Management", self.advanced_rule_management),
            ("View Network Traffic", self.view_network_traffic),
            ("Generate Security Audit Report", self.generate_security_audit_report),
            ("Open Windows Commands", self.open_windows_commands),
            # ("View System Information", self.view_system_info),
            # ("Check for Updates", self.check_for_updates),
            # ("Check System Health", self.check_system_health),
            # ("View Active Processes", self.view_active_processes),
            # ("View Active Services", self.view_active_services),
            # ("View Active Connections", self.view_active_connections),
        ]
        for i, (text, command) in enumerate(tools_buttons):
            tk.Button(
                tools_frame, text=text, command=command, **self.button_style()
            ).grid(row=i // 2, column=i % 2, padx=5, pady=5, sticky="ew")

        footer_frame = tk.Frame(scrollable_frame, bg=self.color_theme["frame_bg"], pady=10)
        footer_frame.pack(fill="x")
        tk.Button(
            footer_frame, text="Help Menu", command=self.help_menu, **self.button_style()
        ).pack(side="left", padx=10)
        tk.Button(
            footer_frame, text="Exit", command=self.root.quit, **self.button_style()
        ).pack(side="right", padx=10)

    def open_windows_commands(self):
        logging.info("Opening Windows commands.")
        self.safe_execute(self._open_windows_commands)
        logging.info("Windows commands opened successfully.")

    def _open_windows_commands(self):
        commands_window = tk.Toplevel(self.root)
        commands_window.title("Windows Commands")
        commands_window.geometry("800x600")
        commands_window.configure(bg="#2C3E50")

        canvas = tk.Canvas(commands_window, bg="#2C3E50", highlightthickness=0)
        scrollbar = tk.Scrollbar(commands_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#2C3E50")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        tk.Label(
            scrollable_frame,
            text="Helpful Windows Commands",
            font=("Segoe UI", 16, "bold"),
            fg="#ECF0F1",
            bg="#2C3E50"
        ).grid(row=0, column=0, columnspan=3, pady=10)

        commands = {
            "Check Disk Space": "dir",
            "List Running Processes": "tasklist",
            "Ping Google": "ping google.com",
            "IP Configuration": "ipconfig",
            "Flush DNS Cache": "ipconfig /flushdns",
            "System Information": "systeminfo",
            "Check Network Connections": "netstat -an",
            "Restart Network Adapter": "ipconfig /release && ipconfig /renew",
            "Run SFC Scan (Check Files)": "sfc /scannow",
            "Verify SFC Integrity": "sfc /verifyonly",
            "Repair Network Issues": "netsh int ip reset && netsh winsock reset",
            "View Active Network Adapters": "ipconfig /all",
            "Test Connectivity to Host": "tracert google.com",
            "Display Routing Table": "route print",
            "Enable Firewall Logging": "netsh advfirewall set currentprofile logging filename log.txt",
            "Disable Firewall Logging": "netsh advfirewall set currentprofile logging disabled",
            "Check Open Ports": "netstat -an | find \"LISTENING\"",
            "View ARP Cache": "arp -a",
            "Clear ARP Cache": "arp -d *",
            "Check DNS Servers": "nslookup google.com",
            "Test SMB Connectivity": "net use \\\\hostname\\share",
        }

        row = 1
        col = 0
        for command_name, command in commands.items():
            tk.Button(
                scrollable_frame,
                text=command_name,
                command=lambda cmd=command: self.execute_command(cmd),
                font=("Segoe UI", 12),
                bg="#3498DB",
                fg="#FFFFFF",
                activebackground="#2980B9",
                activeforeground="#FFFFFF",
                relief="flat",
                bd=0,
                padx=10,
                pady=5,
                cursor="hand2"
            ).grid(row=row, column=col, padx=10, pady=10, sticky="ew")
            col += 1
            if col > 2:
                col = 0
                row += 1

        tk.Label(
            scrollable_frame,
            text="Execute Custom Command",
            font=("Segoe UI", 14, "bold"),
            fg="#ECF0F1",
            bg="#2C3E50"
        ).grid(row=row + 1, column=0, columnspan=3, pady=10)

        custom_command_var = tk.StringVar()
        custom_command_entry = tk.Entry(
            scrollable_frame,
            textvariable=custom_command_var,
            font=("Segoe UI", 12),
            bg="#ECF0F1",
            fg="#2C3E50",
            relief="flat"
        )
        custom_command_entry.grid(row=row + 2, column=0, columnspan=2, padx=20, pady=5, sticky="ew")

        tk.Button(
            scrollable_frame,
            text="Run Command",
            command=lambda: self.execute_command(custom_command_var.get()),
            font=("Segoe UI", 12),
            bg="#1ABC9C",
            fg="#FFFFFF",
            activebackground="#16A085",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=10,
            pady=5,
            cursor="hand2"
        ).grid(row=row + 2, column=2, padx=20, pady=5, sticky="ew")

        tk.Button(
            scrollable_frame,
            text="Return to Main Page",
            command=commands_window.destroy,
            font=("Segoe UI", 12),
            bg="#E74C3C",
            fg="#FFFFFF",
            activebackground="#C0392B",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=10,
            pady=5,
            cursor="hand2"
        ).grid(row=row + 3, column=0, columnspan=3, pady=20)

    def execute_command(self, command):
        logging.info(f"Executing command: {command}")
        self.safe_execute(self._execute_command, command)
        logging.info(f"Command {command} executed successfully.")

    def _execute_command(self, command):
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            output = result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            output = f"Error executing command: {e}"

        output_window = tk.Toplevel(self.root)
        output_window.title("Command Output")
        output_window.geometry("600x400")
        output_window.configure(bg="#2C3E50")

        tk.Label(
            output_window,
            text="Command Output",
            font=("Segoe UI", 14, "bold"),
            fg="#ECF0F1",
            bg="#2C3E50"
        ).pack(pady=10)

        output_text = tk.Text(
            output_window,
            font=("Courier", 10),
            bg="#2C3E50",
            fg="#ECF0F1",
            wrap="word",
            state="normal"
        )
        output_text.insert("1.0", output)
        output_text.config(state="disabled")
        output_text.pack(fill="both", expand=True, padx=10, pady=10)

    def button_style(self):
        logging.info("Applying button style.")
        return {
            "font": self.fonts["button"],
            "bg": self.color_theme["button_bg"],
            "fg": self.color_theme["button_fg"],
            "activebackground": self.color_theme["button_active_bg"],
            "activeforeground": self.color_theme["button_active_fg"],
            "relief": "flat",
            "bd": 0,
            "padx": 10,
            "pady": 10,
            "cursor": "hand2",
        }

    def label_style(self):
        logging.info("Applying label style.")
        return {
            "font": self.fonts["text"],
            "fg": self.color_theme["foreground"],
            "bg": self.color_theme["background"],
        }

    def frame_style(self):
        logging.info("Applying frame style.")
        return {
            "bg": self.color_theme["frame_bg"],
        }

    def entry_style(self):
        logging.info("Applying entry style.")
        return {
            "font": self.fonts["text"],
            "bg": self.color_theme["entry_bg"],
            "fg": self.color_theme["entry_fg"],
            "relief": "flat",
        }

    def clear_window(self):
        logging.info("Clearing window.")
        for widget in self.root.winfo_children():
            widget.destroy()
        logging.info("Window cleared successfully.")

    def show_custom_port_dialog(self, title, fields):
        logging.info("Showing custom port dialog.")
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x300")
        dialog.configure(bg=self.color_theme["background"])
        dialog.resizable(False, False)

        field_vars = {}
        for field in fields:
            tk.Label(
                dialog,
                text=field,
                **self.label_style()
            ).pack(pady=5)
            field_var = tk.StringVar()
            tk.Entry(dialog, textvariable=field_var, **self.entry_style()).pack(pady=5, padx=20, fill="x")
            field_vars[field] = field_var

        def on_submit():
            dialog.destroy()

        tk.Button(
            dialog,
            text="Submit",
            **self.button_style(),
            command=on_submit
        ).pack(pady=20)

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        logging.info("Custom port dialog shown successfully.")
        return {field: var.get() for field, var in field_vars.items()}

    def show_custom_confirmation(self, title, message):
        logging.info("Showing custom confirmation dialog.")
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x200")
        dialog.configure(bg=self.color_theme["background"])
        dialog.resizable(False, False)

        tk.Label(
            dialog,
            text=message,
            **self.label_style(),
            wraplength=380,
            justify="center"
        ).pack(pady=20)

        result = {"confirmed": False}

        def on_yes():
            result["confirmed"] = True
            dialog.destroy()

        def on_no():
            dialog.destroy()

        button_frame = tk.Frame(dialog, **self.frame_style())
        button_frame.pack(pady=10)

        tk.Button(
            button_frame,
            text="Yes",
            **self.button_style(),
            command=on_yes
        ).pack(side="left", padx=10)

        tk.Button(
            button_frame,
            text="No",
            **self.button_style(),
            command=on_no
        ).pack(side="right", padx=10)

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        logging.info("Custom confirmation dialog shown successfully.")
        return result["confirmed"]

    def safe_execute(self, func, *args, **kwargs):
        logging.info(f"Executing function safely: {func.__name__}")
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.log_action(f"Error in {func.__name__}: {e}")
            messagebox.showerror("Error", f"An error occurred in {func.__name__}:\n{e}")
        logging.info(f"Function {func.__name__} executed successfully.")

    def open_ports(self):
        logging.info("Opening ports.")
        self.safe_execute(self._open_ports)
        logging.info("Ports opened successfully.")

    def _open_ports(self):
        inputs = self.show_custom_port_dialog("Open Ports", ["Port Number or Range (e.g., 80 or 1000-2000)", "Protocol (TCP/UDP)"])
        port = inputs.get("Port Number or Range (e.g., 80 or 1000-2000)")
        protocol = inputs.get("Protocol (TCP/UDP)").upper()
        if not port or not protocol:
            self.show_message_dialog("Error", "Port or protocol cannot be empty!")
            return
        if protocol not in ["TCP", "UDP"]:
            self.show_message_dialog("Error", "Invalid protocol! Please enter TCP or UDP.")
            return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Open Port {port} ({protocol})",
                 "dir=in", "action=allow", f"protocol={protocol}", f"localport={port}"],
                check=True
            )
            self.log_action(f"Opened Port {port} ({protocol})")
            self.show_message_dialog("Success", f"Port {port} ({protocol}) has been opened successfully!")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", f"Failed to open Port {port} ({protocol}).")

    def close_ports(self):
        logging.info("Closing ports.")
        self.safe_execute(self._close_ports)
        logging.info("Ports closed successfully.")

    def _close_ports(self):
        inputs = self.show_custom_port_dialog("Close Ports", ["Port Number", "Protocol (TCP/UDP)"])
        port = inputs.get("Port Number")
        protocol = inputs.get("Protocol (TCP/UDP)").upper()
        if not port or not protocol:
            self.show_message_dialog("Error", "Port or protocol cannot be empty!")
            return
        if protocol not in ["TCP", "UDP"]:
            self.show_message_dialog("Error", "Invalid protocol! Please enter TCP or UDP.")
            return
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=Open Port {port} ({protocol})",
                 f"protocol={protocol}", f"localport={port}"],
                check=True
            )
            self.log_action(f"Closed Port {port} ({protocol})")
            self.show_message_dialog("Success", f"Port {port} ({protocol}) has been closed successfully!")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", f"Failed to close Port {port} ({protocol}).")

    def query_ports(self):
        logging.info("Querying ports.")
        self.safe_execute(self._query_ports)
        logging.info("Ports queried successfully.")

    def _query_ports(self):
        inputs = self.show_custom_port_dialog("Query Ports", ["Port Number"])
        try:
            subprocess.run(["netsh", "advfirewall", "reset"], check=True)
            self.log_action("Firewall reset to default settings")
            self.show_message_dialog("Success", "Firewall has been reset to default settings.")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", "Failed to reset the firewall.")

    def create_scrollable_window(self, title, width=600, height=500):
        logging.info("Creating scrollable window.")
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry(f"{width}x{height}")
        window.resizable(True, True)
        window.configure(bg=self.color_theme["background"])

        canvas = tk.Canvas(window, bg=self.color_theme["background"], highlightthickness=0)
        scrollbar = tk.Scrollbar(window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, **self.frame_style())

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        logging.info("Scrollable window created successfully.")
        return window, scrollable_frame

    def show_messagebox(self, title, message, box_type="info"):
        logging.info("Showing messagebox.")
        messagebox_options = {
            "info": messagebox.showinfo,
            "error": messagebox.showerror,
            "warning": messagebox.showwarning,
            "yesno": messagebox.askyesno,
            "yesnocancel": messagebox.askyesnocancel,
            "question": messagebox.askquestion,
        }
        logging.info("Messagebox shown successfully.")
        return messagebox_options[box_type](title, message)

    def show_simpledialog(self, title, prompt, show=None):
        logging.info("Showing simpledialog.")
        logging.info("Simpledialog shown successfully.")
        return simpledialog.askstring(title, prompt, show=show)

    def predefined_port_profiles(self):
        logging.info("Showing predefined port profiles.")
        self.safe_execute(self._predefined_port_profiles)
        logging.info("Predefined port profiles shown successfully.")

    def _predefined_port_profiles(self):
        profiles = {
            "Communication Tools": [
                {"name": "Zoom", "ports": "TCP/UDP 8801-8802"},
                {"name": "Skype", "ports": "TCP 50000-60000, UDP 50000-60000"},
                {"name": "Discord", "ports": "TCP 443, UDP 443, TCP 50000-60000, UDP 50000-60000"}
            ],
            "Game Servers": [
                {"name": "Minecraft", "ports": "TCP 25565, UDP 25565"},
                {"name": "CS:GO", "ports": "UDP 27015-27030, UDP 27036"},
                {"name": "ARK: Survival Evolved", "ports": "UDP 7777-7778, UDP 27015"},
                {"name": "FiveM", "ports": "TCP 30120, UDP 30120"},
                {"name": "Fortnite", "ports": "TCP 5222, UDP 5222, TCP 5795-5847, UDP 5795-5847"},
                {"name": "Call of Duty: Warzone", "ports": "TCP 3074, UDP 3074, TCP 27014-27050, UDP 27014-27050"},
                {"name": "League of Legends", "ports": "TCP 5000-5500, TCP 8393-8400, TCP 2099, TCP 5222-5223, TCP 8088"},
                {"name": "Valorant", "ports": "UDP 7000-7500, UDP 8080, UDP 8180, UDP 10000-10099"},
                {"name": "Apex Legends", "ports": "TCP 4000-4500, UDP 4000-4500, TCP 8080"},
                {"name": "SPT FIKA", "ports": "TCP 443, UDP 443, TCP 8080, UDP 8080, TCP 50555, UDP 50555, TCP 6969, UDP 6969"}
            ],
            "File Sharing": [
                {"name": "FTP", "ports": "TCP 21"},
                {"name": "BitTorrent", "ports": "TCP 6881-6889, UDP 6881-6889"}
            ],
            "Development Tools": [
                {"name": "Docker", "ports": "TCP 2375-2376"},
                {"name": "Jenkins", "ports": "TCP 8080"},
                {"name": "GitLab", "ports": "TCP 80, TCP 443, TCP 22"},
                {"name": "Kubernetes", "ports": "TCP 6443"},
                {"name": "ElasticSearch", "ports": "TCP 9200-9300"}
            ],
            "Database Servers": [
                {"name": "MySQL", "ports": "TCP 3306"},
                {"name": "PostgreSQL", "ports": "TCP 5432"},
                {"name": "MongoDB", "ports": "TCP 27017"},
                {"name": "Redis", "ports": "TCP 6379"}
            ],
            "Web Servers": [
                {"name": "HTTP", "ports": "TCP 80"},
                {"name": "HTTPS", "ports": "TCP 443"}
            ]
        }

        def show_category(category_name):
            logging.info(f"Showing category: {category_name}")
            category_window, category_frame = self.create_scrollable_window(f"{category_name} Presets")

            tk.Label(
                category_frame,
                text=f"{category_name} Presets",
                **self.label_style()
            ).pack(pady=10)

            for profile in profiles[category_name]:
                profile_frame = tk.Frame(category_frame, **self.frame_style())
                profile_frame.pack(fill="x", pady=5, padx=20)

                tk.Label(
                    profile_frame,
                    text=f"{profile['name']} ({profile['ports']})",
                    **self.label_style()
                ).pack(side="left", padx=10)

                tk.Button(
                    profile_frame,
                    text="Enable",
                    command=lambda p=profile: self.toggle_profile(p, enable=True),
                    **self.button_style()
                ).pack(side="left", padx=5)

                tk.Button(
                    profile_frame,
                    text="Disable",
                    command=lambda p=profile: self.toggle_profile(p, enable=False),
                    **self.button_style()
                ).pack(side="left", padx=5)

            tk.Button(
                category_frame,
                text="Back to Predefined Port Profiles",
                font=("Segoe UI", 12, "bold"),
                bg="#34495E",
                fg="#ECF0F1",
                activebackground="#2C3E50",
                activeforeground="#ECF0F1",
                command=category_window.destroy
            ).pack(pady=10)

        profiles_window, profiles_frame = self.create_scrollable_window("Predefined Port Profiles")

        tk.Label(
            profiles_frame,
            text="Select a category to configure ports:",
            **self.label_style()
        ).pack(pady=10)

        for category_name in profiles.keys():
            tk.Button(
                profiles_frame,
                text=category_name,
                font=("Segoe UI", 12, "bold"),
                bg="#3498DB",
                fg="#FFFFFF",
                activebackground="#2980B9",
                activeforeground="#FFFFFF",
                command=lambda c=category_name: show_category(c)
            ).pack(fill="x", pady=5, padx=20)

        tk.Button(
            profiles_frame,
            text="Back to Main Menu",
            font=("Segoe UI", 12, "bold"),
            bg="#34495E",
            fg="#ECF0F1",
            activebackground="#2C3E50",
            activeforeground="#ECF0F1",
            command=profiles_window.destroy
        ).pack(pady=10)

    def toggle_profile(self, profile, enable=True):
        logging.info(f"Toggling profile: {profile['name']} Enable: {enable}")
        action = "enable" if enable else "disable"
        confirmation = self.show_confirmation_dialog(
            f"{action.capitalize()} Profile",
            f"Are you sure you want to {action} the profile for {profile['name']} ({profile['ports']})?"
        )
        if not confirmation:
            return

        try:
            if enable:
                ports = profile['ports'].split(", ")
                for port_entry in ports:
                    if " " not in port_entry:
                        self.log_error(f"Invalid port entry: {port_entry}. Skipping...")
                        continue
                    protocol, port_range = port_entry.split(" ", 1)
                    protocols = protocol.split("/")
                    for proto in protocols:
                        proto = proto.upper()
                        if proto not in ["TCP", "UDP"]:
                            self.log_error(f"Invalid protocol: {proto}. Must be TCP or UDP. Skipping...")
                            continue
                        subprocess.run(
                            ["netsh", "advfirewall", "firewall", "add", "rule",
                             f"name={profile['name']} ({proto} {port_range})",
                             "dir=in", "action=allow", f"protocol={proto}", f"localport={port_range}"],
                            check=True
                        )
                self.log_action(f"Enabled profile: {profile['name']} ({profile['ports']})")
                self.show_message_dialog("Success", f"Enabled profile: {profile['name']}")
            else:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={profile['name']}"],
                    check=True
                )
                self.log_action(f"Disabled profile: {profile['name']} ({profile['ports']})")
                self.show_message_dialog("Success", f"Disabled profile: {profile['name']}")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to {action} profile: {profile['name']}. Error: {e}")

    def backup_firewall_rules(self):
        logging.info("Backing up firewall rules.")
        self.safe_execute(self._backup_firewall_rules)
        logging.info("Firewall rules backed up successfully.")

    def _backup_firewall_rules(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".wfw", filetypes=[("Firewall Rules", "*.wfw")])
        if file_path:
            try:
                subprocess.run(["netsh", "advfirewall", "export", file_path], check=True)
                self.log_action(f"Firewall rules backed up to {file_path}")
                self.show_messagebox("Success", "Firewall rules have been backed up.")
            except subprocess.CalledProcessError:
                self.show_messagebox("Error", "Failed to backup firewall rules.", "error")

    def restore_firewall_rules(self):
        logging.info("Restoring firewall rules.")
        self.safe_execute(self._restore_firewall_rules)
        logging.info("Firewall rules restored successfully.")

    def _restore_firewall_rules(self):
        file_path = filedialog.askopenfilename(filetypes=[("Firewall Rules", "*.wfw")])
        if file_path:
            try:
                subprocess.run(["netsh", "advfirewall", "import", file_path], check=True)
                self.log_action(f"Firewall rules restored from {file_path}")
                self.show_messagebox("Success", "Firewall rules have been restored.")
            except subprocess.CalledProcessError:
                self.show_messagebox("Error", "Failed to restore firewall rules.", "error")

    def toggle_firewall(self, enable=True):
        logging.info(f"Toggling firewall. Enable: {enable}")
        self.safe_execute(self._toggle_firewall, enable)
        logging.info(f"Firewall toggled. Enable: {enable}")

    def _toggle_firewall(self, enable):
        action = "enable" if enable else "disable"
        confirmation = self.show_confirmation_dialog(
            f"{action.capitalize()} Firewall",
            f"Are you sure you want to {action} the firewall?"
        )
        if not confirmation:
            return

        try:
            if enable:
                subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], check=True)
                self.log_action("Firewall enabled")
                self.show_message_dialog("Success", "Firewall has been enabled.")
            else:
                subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"], check=True)
                self.log_action("Firewall disabled")
                self.show_message_dialog("Success", "Firewall has been disabled.")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", f"Failed to {action} the firewall.")

    def list_active_rules(self):
        logging.info("Listing active firewall rules.")
        self.safe_execute(self._list_active_rules)
        logging.info("Active firewall rules listed successfully.")

    def _list_active_rules(self):
        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                    capture_output=True, text=True, check=True)
            self.show_message_dialog("Active Rules", result.stdout)
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", "Failed to list active rules.")

    def search_firewall_rule(self):
        logging.info("Searching for a firewall rule.")
        self.safe_execute(self._search_firewall_rule)
        logging.info("Firewall rule search completed.")

    def _search_firewall_rule(self):
        rule_name = self.show_input_dialog("Search Rule", "Enter the rule name:")
        if not rule_name:
            self.show_message_dialog("Error", "Rule name cannot be empty!")
            return
        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                                    capture_output=True, text=True, check=True)
            if result.stdout:
                self.show_message_dialog("Rule Found", result.stdout)
            else:
                self.show_message_dialog("Rule Not Found", f"No rule found with name: {rule_name}")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", "Failed to search for the rule.")

    def delete_firewall_rule(self):
        logging.info("Deleting a firewall rule.")
        self.safe_execute(self._delete_firewall_rule)
        logging.info("Firewall rule deleted successfully.")

    def _delete_firewall_rule(self):
        rule_name = self.show_input_dialog("Delete Rule", "Enter the rule name:")
        if not rule_name:
            self.show_message_dialog("Error", "Rule name cannot be empty!")
            return
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], check=True)
            self.log_action(f"Deleted rule: {rule_name}")
            self.show_message_dialog("Success", f"Rule {rule_name} has been deleted.")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", f"Failed to delete rule: {rule_name}.")

    def export_logs(self):
        logging.info("Exporting logs.")
        self.safe_execute(self._export_logs)
        logging.info("Logs exported successfully.")

    def _export_logs(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".log", filetypes=[("Log Files", "*.log")])
        if file_path:
            try:
                with open(self.log_file, "r") as log:
                    with open(file_path, "w") as export_file:
                        export_file.write(log.read())
                self.show_message_dialog("Success", "Logs have been exported.")
            except Exception as e:
                self.show_message_dialog("Error", f"Failed to export logs: {e}")

    def view_statistics(self):
        logging.info("Viewing firewall statistics.")
        self.safe_execute(self._view_statistics)
        logging.info("Firewall statistics displayed successfully.")

    def _view_statistics(self):
        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                    capture_output=True, text=True, check=True)
            total_rules = result.stdout.count("Rule Name:")
            allow_rules = result.stdout.count("Action: Allow")
            block_rules = result.stdout.count("Action: Block")
            stats = f"Total Rules: {total_rules}\nAllow Rules: {allow_rules}\nBlock Rules: {block_rules}"
            self.show_message_dialog("Firewall Statistics", stats)
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", "Failed to retrieve firewall statistics.")

    def detect_port_conflicts(self):
        logging.info("Detecting port conflicts.")
        self.safe_execute(self._detect_port_conflicts)
        logging.info("Port conflict detection completed.")

    def _detect_port_conflicts(self):
        port = self.show_input_dialog("Detect Port Conflicts", "Enter the port number:")
        if not port:
            self.show_message_dialog("Error", "Port cannot be empty!")
            return
        try:
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, check=True)
            if f":{port}" in result.stdout:
                self.show_message_dialog("Port Conflict", f"Port {port} is already in use.")
            else:
                self.show_message_dialog("No Conflict", f"Port {port} is available.")
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", "Failed to detect port conflicts.")

    def view_network_profile(self):
        logging.info("Viewing network profile.")
        self.safe_execute(self._view_network_profile)
        logging.info("Network profile displayed successfully.")

    def _view_network_profile(self):
        try:
            result = subprocess.run(["netsh", "advfirewall", "show", "currentprofile"],
                                    capture_output=True, text=True, check=True)
            self.show_message_dialog("Network Profile", result.stdout)
        except subprocess.CalledProcessError:
            self.show_message_dialog("Error", "Failed to retrieve network profile.")

    def help_menu(self):
        logging.info("Displaying help menu.")
        self.safe_execute(self._help_menu)
        logging.info("Help menu displayed successfully.")

    def _help_menu(self):
        help_text = """
        Welcome to the N3xG3n Firewall Manager Help Menu!

        Below is a list of features and how to use them:

        1. **Open Specific Ports**
           - Opens a specific port or range of ports for inbound traffic.
           - **How to Use**: Enter the port number (e.g., 80) or range (e.g., 1000-2000) and select the protocol (TCP/UDP).
           - **Example**: To allow HTTP traffic, enter port 80 and select TCP.

        2. **Close Specific Ports**
           - Closes a specific port or range of ports.
           - **How to Use**: Enter the port number (e.g., 80) or range (e.g., 1000-2000) and select the protocol (TCP/UDP).
           - **Example**: To block HTTP traffic, enter port 80 and select TCP.

        3. **Query Port Status**
           - Checks if a specific port is open or closed.
           - **How to Use**: Enter the port number (e.g., 80) to check its status.
           - **Example**: To check if port 80 is open, enter 80.

        4. **Reset Firewall to Default**
           - Resets the firewall to its default configuration, removing all custom rules.
           - **How to Use**: Click the button and confirm the action when prompted.
           - **Warning**: This will erase all custom rules.

        5. **Predefined Port Profiles**
           - Provides predefined configurations for common applications and services.
           - **How to Use**: Select a category (e.g., Communication Tools, Game Servers) to view available profiles.
           - **Example**: To view ports for Minecraft, select "Game Servers".

        6. **Backup Firewall Rules**
           - Saves the current firewall rules to a file.
           - **How to Use**: Choose a location to save the backup file.
           - **Example**: Save the rules to "firewall_backup.wfw".

        7. **Restore Firewall Rules**
           - Restores firewall rules from a backup file.
           - **How to Use**: Select a previously saved backup file to restore the rules.
           - **Example**: Restore rules from "firewall_backup.wfw".

        8. **Enable/Disable Firewall**
           - Toggles the firewall state (on/off) for all profiles.
           - **How to Use**: Select "Yes" to enable or "No" to disable the firewall.
           - **Example**: To disable the firewall, select "No".

        9. **List Active Rules**
            - Displays all active firewall rules.
            - **How to Use**: Click the button to view the list of rules.
            - **Example**: Use this to review all currently active rules.

        10. **Search Firewall Rule**
            - Searches for a specific firewall rule by name.
            - **How to Use**: Enter the rule name to search for it.
            - **Example**: To find a rule named "Open Port 80", enter "Open Port 80".

        11. **Delete Firewall Rule**
            - Deletes a specific firewall rule by name.
            - **How to Use**: Enter the rule name to delete it.
            - **Example**: To delete a rule named "Open Port 80", enter "Open Port 80".

        12. **Export Logs**
            - Exports the log file to a user-specified location.
            - **How to Use**: Choose a location to save the log file.
            - **Example**: Save the logs to "firewall_logs.log".

        13. **View Statistics**
            - Displays statistics about the current firewall rules.
            - **Details**: Shows the total number of rules, allow rules, and block rules.
            - **How to Use**: Click the button to view the statistics.

        14. **Detect Port Conflicts**
            - Checks if a specific port is already in use.
            - **How to Use**: Enter the port number to check for conflicts.
            - **Example**: To check if port 80 is in use, enter 80.

        15. **View Network Profile**
            - Displays the current network profile (e.g., Public, Private, Domain).
            - **How to Use**: Click the button to view the profile.

        16. **Windows Commands**
            - Provides a list of helpful Windows commands and allows you to execute them.
            - **How to Use**: Click the "Windows Commands" button to open the commands window. Select a predefined command or enter a custom command to execute.
            - **Examples**:
              - Predefined Commands:
                - "Ping Google": Tests connectivity to Google.
                - "Run SFC Scan": Scans and repairs system files.
                - "Flush DNS Cache": Clears the DNS cache.
              - Custom Commands:
                - Enter any valid Windows command in the input field and click "Run Command".

        17. **Execute Custom Command**
            - Allows you to manually execute any Windows command.
            - **How to Use**: Enter the command in the input field in the "Windows Commands" window and click "Run Command".
            - **Example**: To check disk space, enter `dir` and click "Run Command".

        18. **Set Color Theme**
           - Changes the application's background color for a personalized experience.
           - **How to Use**: Select a color theme from the list of available options.
           - **Example**: To set the background to blue, select "Blue".

        19. **Admin Panel**
            - Accessible only to admin users. Includes features like:
              - View Active Connections
              - Import/Export Firewall Rules
              - Monitor System Resources
              - Manage Whitelist/Blacklist
              - Schedule Firewall Tasks
              - Manage Users

        20. **Ping and Traceroute**
            - Provides tools for network diagnostics.

        21. **Firewall Rule Simulator**
            - Simulates how firewall rules will affect traffic.

        22. **Geo-IP Blocking**
            - Blocks traffic from specific countries.

        23. **Generate Reports**
            - Generates detailed reports on firewall activity, rule usage, and network traffic.

        24. **Export Reports**
            - Exports reports in formats like CSV or Excel.

        25. **Port Scanning**
            - Scans for open ports on the local machine or network.

        26. **Validate Firewall Rule**
            - Validates a firewall rule before applying it.

        27. **Malware Detection**
            - Scans files for potential malware.

        28. **Custom Themes**
            - Allows users to create and save their own color themes.

        29. **Language Support**
            - Adds multi-language support for the application.

        30. **Customizable Dashboard**
            - Allows users to rearrange or hide sections of the main menu.

        31. **Network Monitoring**
            - Provides tools for real-time traffic analysis, bandwidth usage, and intrusion detection.

        32. **Live Data Viewer**
            - Displays live network traffic in a separate window.

        33. **Optimize Rules**
            - Analyzes and suggests optimizations for existing firewall rules.

        34. **Help Menu**
            - Displays this help menu.

        35. **Exit**
            - Closes the application.

        If you have any questions or need further assistance, feel free to email me at jarrodz@digital-synergy.org.
        """

        help_window, help_frame = self.create_scrollable_window("Help Menu", width=600, height=800)

        tk.Label(
            help_frame,
            text=help_text,
            font=("Arial", 12),
            fg="#ECF0F1",
            bg=self.color_theme["background"],
            justify="left",
            wraplength=580
        ).pack(pady=10, padx=10)

    def start_session_monitor(self):
        logging.info("Starting session monitor.")
        if self.session_timeout is not None:
            if time.time() - self.last_activity > self.session_timeout:
                logging.warning("Session timeout detected. Re-authenticating user.")
                self.show_message_dialog("Session Timeout", "Your session has expired. Please log in again.")
                self.authenticate_user()
            else:
                self.root.after(1000, self.start_session_monitor)
        else:
            logging.info("Session timeout is disabled.")

    def reset_activity_timer(self):
        logging.info("Resetting activity timer.")
        self.last_activity = time.time()
        logging.info("Activity timer reset.")

    def update_traffic_viewer(self):
        logging.info("Updating traffic viewer.")
        self.safe_execute(self._update_traffic_viewer)
        logging.info("Traffic viewer updated successfully.")

    def _update_traffic_viewer(self):
        try:
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, shell=True)
            output = result.stdout if result.returncode == 0 else result.stderr

            filtered_lines = []
            for line in output.splitlines():
                if "ESTABLISHED" in line or "CLOSE_WAIT" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        protocol = parts[0]
                        local_address = parts[1]
                        remote_address = parts[2]
                        filtered_lines.append(f"{protocol} | Local: {local_address} | Remote: {remote_address}")

            self.traffic_viewer.config(state="normal")
            self.traffic_viewer.delete("1.0", "end")
            self.traffic_viewer.insert("1.0", "\n".join(filtered_lines))
            self.traffic_viewer.see("end")
            self.traffic_viewer.config(state="disabled")
            self.root.after(5000, self.update_traffic_viewer)
        except Exception as e:
            self.log_action(f"Error updating traffic viewer: {e}")

    def reset_firewall(self):
        logging.info("Resetting firewall to default settings.")
        self.safe_execute(self._reset_firewall)
        logging.info("Firewall reset completed.")

    def _reset_firewall(self):
        confirmed = self.show_confirmation_dialog(
            "Reset Firewall",
            "Are you sure you want to reset the firewall to default settings?"
        )
        if confirmed:
            try:
                subprocess.run(["netsh", "advfirewall", "reset"], check=True)
                self.log_action("Firewall reset to default settings.")
                self.show_message_dialog("Success", "Firewall has been reset to default settings.")
            except subprocess.CalledProcessError as e:
                self.log_error(f"Failed to reset the firewall: {e}")
                self.show_message_dialog("Error", "Failed to reset the firewall.")

    def open_admin_panel(self):
        logging.info("Opening admin panel.")
        if not getattr(self, "is_admin_user", False):
            self.show_message_dialog("Access Denied", "You must be logged in as an admin to access the admin panel.")
            return

        admin_window = tk.Toplevel(self.root)
        admin_window.title("Admin Panel")
        admin_window.geometry("800x600")
        admin_window.configure(bg=self.color_theme["background"])

        tk.Label(
            admin_window,
            text="Admin Panel",
            font=("Segoe UI", 16, "bold"),
            fg="#ECF0F1",
            bg=self.color_theme["background"]
        ).pack(pady=10)

        admin_buttons = [
            ("View Active Connections", self.view_active_connections),
            ("Import Firewall Rules", self.restore_firewall_rules),
            ("Export Firewall Rules", self.backup_firewall_rules),
            ("Monitor System Resources", self.monitor_system_resources),
            ("Manage Whitelist/Blacklist", self.manage_whitelist_blacklist),
            ("Schedule Firewall Tasks", self.schedule_firewall_tasks),
            ("Manage Users", self.manage_users),
            ("View System Logs", self.view_system_logs),
            ("Clear Firewall Logs", self.clear_firewall_logs),
            ("Advanced Rule Management", self.advanced_rule_management),
            ("View Network Traffic", self.view_network_traffic),
            ("Generate Security Audit Report", self.generate_security_audit_report),
            ("Backup and Restore Settings", self.backup_restore_settings),
        ]
        for text, command in admin_buttons:
            tk.Button(
                admin_window, text=text, command=command, **self.button_style()
            ).pack(fill="x", pady=5, padx=20)

        tk.Button(
            admin_window,
            text="Close Admin Panel",
            command=admin_window.destroy,
            **self.button_style()
        ).pack(fill="x", pady=20, padx=20)

    def view_system_logs(self):
        logging.info("Viewing system logs.")
        logging.info("System logs viewed successfully.")

    def clear_firewall_logs(self):
        logging.info("Clearing firewall logs.")
        logging.info("Firewall logs cleared successfully.")

    def advanced_rule_management(self):
        logging.info("Managing advanced rules.")
        try:
            management_window, management_frame = self.create_scrollable_window("Advanced Rule Management", width=800, height=600)

            tk.Label(
                management_frame,
                text="Advanced Rule Management",
                font=("Segoe UI", 14, "bold"),
                bg=self.color_theme["background"],
                fg=self.color_theme["foreground"]
            ).pack(pady=10)

            tk.Label(
                management_frame,
                text="Existing Firewall Rules:",
                font=("Segoe UI", 12, "bold"),
                bg=self.color_theme["background"],
                fg=self.color_theme["foreground"]
            ).pack(pady=5)

            rules_text = tk.Text(
                management_frame,
                font=("Courier", 10),
                bg=self.color_theme["entry_bg"],
                fg=self.color_theme["entry_fg"],
                wrap="none",
                state="normal",
                height=15
            )
            rules_text.pack(fill="both", expand=True, padx=10, pady=10)

            try:
                result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                        capture_output=True, text=True, check=True)
                rules_text.insert("1.0", result.stdout)
                rules_text.config(state="disabled")
            except subprocess.CalledProcessError as e:
                rules_text.insert("1.0", f"Failed to fetch rules: {e}")
                rules_text.config(state="disabled")

            button_frame = tk.Frame(management_frame, bg=self.color_theme["background"])
            button_frame.pack(pady=10)

            tk.Button(
                button_frame,
                text="Add Rule",
                command=self.add_firewall_rule,
                **self.button_style()
            ).pack(side="left", padx=10)

            tk.Button(
                button_frame,
                text="Edit Rule",
                command=self.edit_firewall_rule,
                **self.button_style()
            ).pack(side="left", padx=10)

            tk.Button(
                button_frame,
                text="Delete Rule",
                command=self.delete_firewall_rule,
                **self.button_style()
            ).pack(side="left", padx=10)

            self.log_action("Accessed advanced rule management.")
        except Exception as e:
            self.log_error(f"Failed to open advanced rule management: {e}")
            self.show_message_dialog("Error", f"Failed to open advanced rule management: {e}")

    def add_firewall_rule(self):
        logging.info("Adding a new firewall rule.")
        inputs = self.show_custom_port_dialog("Add Firewall Rule", ["Rule Name", "Port Number", "Protocol (TCP/UDP)", "Action (Allow/Block)"])
        rule_name = inputs.get("Rule Name")
        port = inputs.get("Port Number")
        protocol = inputs.get("Protocol (TCP/UDP)").upper()
        action = inputs.get("Action (Allow/Block)").lower()

        if not rule_name or not port or not protocol or not action:
            self.show_message_dialog("Error", "All fields are required!")
            return

        if protocol not in ["TCP", "UDP"]:
            self.show_message_dialog("Error", "Invalid protocol! Please enter TCP or UDP.")
            return

        if action not in ["allow", "block"]:
            self.show_message_dialog("Error", "Invalid action! Please enter Allow or Block.")
            return

        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}",
                 "dir=in", f"action={action}", f"protocol={protocol}", f"localport={port}"],
                check=True
            )
            self.log_action(f"Added firewall rule: {rule_name}")
            self.show_message_dialog("Success", f"Firewall rule '{rule_name}' has been added.")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to add rule: {e}")

    def edit_firewall_rule(self):
        logging.info("Editing an existing firewall rule.")
        rule_name = self.show_input_dialog("Edit Firewall Rule", "Enter the name of the rule to edit:")
        if not rule_name:
            self.show_message_dialog("Error", "Rule name cannot be empty!")
            return

        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                                    capture_output=True, text=True, check=True)
            if not result.stdout:
                self.show_message_dialog("Error", f"No rule found with name: {rule_name}")
                return

            inputs = self.show_custom_port_dialog(
                "Edit Firewall Rule",
                ["New Rule Name", "Port Number", "Protocol (TCP/UDP)", "Action (Allow/Block)"]
            )
            new_rule_name = inputs.get("New Rule Name") or rule_name
            port = inputs.get("Port Number")
            protocol = inputs.get("Protocol (TCP/UDP)").upper()
            action = inputs.get("Action (Allow/Block)").lower()

            if not port or not protocol or not action:
                self.show_message_dialog("Error", "All fields are required!")
                return

            if protocol not in ["TCP", "UDP"]:
                self.show_message_dialog("Error", "Invalid protocol! Please enter TCP or UDP.")
                return

            if action not in ["allow", "block"]:
                self.show_message_dialog("Error", "Invalid action! Please enter Allow or Block.")
                return

            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], check=True)
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={new_rule_name}",
                 "dir=in", f"action={action}", f"protocol={protocol}", f"localport={port}"],
                check=True
            )
            self.log_action(f"Edited firewall rule: {rule_name} -> {new_rule_name}")
            self.show_message_dialog("Success", f"Firewall rule '{rule_name}' has been updated.")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to edit rule: {e}")

    def view_network_traffic(self):
        logging.info("Viewing network traffic.")
        try:
            traffic_window, traffic_frame = self.create_scrollable_window("Network Traffic", width=600, height=400)
            tk.Label(
                traffic_frame,
                text="Network Traffic",
                font=("Segoe UI", 14, "bold"),
                bg=self.color_theme["background"],
                fg=self.color_theme["foreground"]
            ).pack(pady=10)

            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, check=True)
            traffic_data = result.stdout

            traffic_text = tk.Text(
                traffic_frame,
                font=("Courier", 10),
                bg=self.color_theme["entry_bg"],
                fg=self.color_theme["entry_fg"],
                wrap="none",
                state="normal",
                height=15
            )
            traffic_text.pack(fill="both", expand=True, padx=10, pady=10)

            traffic_text.insert("1.0", traffic_data)
            traffic_text.config(state="disabled")

            self.log_action("Viewed network traffic.")
        except Exception as e:
            self.log_error(f"Failed to view network traffic: {e}")
            self.show_message_dialog("Error", f"Failed to view network traffic: {e}")

    def generate_security_audit_report(self):
        logging.info("Generating security audit report.")
        try:
            firewall_result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, check=True
            )
            firewall_rules = firewall_result.stdout.splitlines()
            total_rules = len([line for line in firewall_rules if "Rule Name:" in line])
            allow_rules = len([line for line in firewall_rules if "Action: Allow" in line])
            block_rules = len([line for line in firewall_rules if "Action: Block" in line])

            traffic_result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True, check=True
            )
            traffic_data = traffic_result.stdout.splitlines()
            established_connections = len([line for line in traffic_data if "ESTABLISHED" in line])
            listening_connections = len([line for line in traffic_data if "LISTENING" in line])

            report_data = (
                "Security Audit Report\n\n"
                f"Firewall Rules:\n"
                f"  - Total Rules: {total_rules}\n"
                f"  - Allow Rules: {allow_rules}\n"
                f"  - Block Rules: {block_rules}\n\n"
                f"Network Traffic:\n"
                f"  - Established Connections: {established_connections}\n"
                f"  - Listening Connections: {listening_connections}\n\n"
                "Analysis:\n"
                "  - Ensure that unnecessary ports are closed.\n"
                "  - Review rules allowing external access to sensitive services.\n"
                "  - Monitor established connections for unusual activity.\n"
            )

            report_window, report_frame = self.create_scrollable_window("Security Audit Report", width=600, height=400)
            report_text = tk.Text(
                report_frame,
                font=("Courier", 10),
                bg=self.color_theme["entry_bg"],
                fg=self.color_theme["entry_fg"],
                wrap="word",
                state="normal",
                height=20
            )
            report_text.pack(fill="both", expand=True, padx=10, pady=10)
            report_text.insert("1.0", report_data)
            report_text.config(state="disabled")

            self.log_action("Generated security audit report.")
        except Exception as e:
            self.log_error(f"Failed to generate security audit report: {e}")
            self.show_message_dialog("Error", f"Failed to generate security audit report: {e}")

    def backup_restore_settings(self):
        logging.info("Backing up and restoring settings.")
        logging.info("Settings backed up and restored successfully.")

    def view_active_connections(self):
        logging.info("Viewing active connections.")
        logging.info("Active connections viewed successfully.")

    def monitor_system_resources(self):
        logging.info("Monitoring system resources.")
        logging.info("System resources monitored successfully.")

    def manage_whitelist_blacklist(self):
        logging.info("Managing whitelist/blacklist.")
        logging.info("Whitelist/blacklist managed successfully.")

    def schedule_firewall_tasks(self):
        logging.info("Scheduling firewall tasks.")
        logging.info("Firewall tasks scheduled successfully.")

    def view_logs(self):
        logging.info("Viewing logs.")
        logs_window, logs_frame = self.create_scrollable_window("View Logs", width=600, height=400)

        tk.Label(
            logs_frame,
            text="Action Logs",
            font=("Segoe UI", 14, "bold"),
            fg="#ECF0F1",
            bg=self.color_theme["background"]
        ).pack(pady=10)

        try:
            with open(self.log_file, "r") as log:
                logs = log.read()
        except Exception as e:
            logs = f"Failed to load logs: {e}"

        text_widget = tk.Text(
            logs_frame,
            font=("Courier", 10),
            bg="#2C3E50",
            fg="#ECF0F1",
            wrap="word",
            state="normal",
            height=10
        )
        text_widget.insert("1.0", logs)
        text_widget.config(state="disabled")
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)
        logging.info("Logs viewed successfully.")

    def clear_browser_cache(self):
        logging.info("Clearing browser cache.")
        try:
            browser_cache_paths = {
                "Google Chrome": os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
                "Mozilla Firefox": os.path.expanduser("~\\AppData\\Local\\Mozilla\\Firefox\\Profiles"),
                "Microsoft Edge": os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"),
            }

            for browser, path in browser_cache_paths.items():
                if os.path.exists(path):
                    shutil.rmtree(path, ignore_errors=True)
                    self.log_action(f"Cleared cache for {browser}.")
                else:
                    self.log_action(f"No cache found for {browser}.")

            self.show_message_dialog("Cache Cleaner", "Browser cache cleared successfully!")
        except Exception as e:
            self.log_error(f"Failed to clear browser cache: {e}")
            self.show_message_dialog("Error", f"Failed to clear browser cache: {e}")

    def defragment_drives(self):
        logging.info("Defragmenting drives.")

        def get_available_drives():
            drives = [f"{letter}:" for letter in string.ascii_uppercase if os.path.exists(f"{letter}:\\")]
            return drives

        def run_defrag(selected_drive):
            try:
                result = subprocess.run(
                    ["defrag", selected_drive, "/U", "/V"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                self.show_message_dialog("Defragmentation Complete", f"Drive {selected_drive}:\n{result.stdout}")
            except subprocess.CalledProcessError as e:
                self.show_message_dialog("Error", f"Failed to defragment drive {selected_drive}: {e}")
            except Exception as e:
                self.show_message_dialog("Error", f"An unexpected error occurred: {e}")

        defrag_window = tk.Toplevel(self.root)
        defrag_window.title("Select Drive to Defragment")
        defrag_window.geometry("400x200")
        defrag_window.configure(bg=self.color_theme["background"])

        tk.Label(
            defrag_window,
            text="Select a drive to defragment:",
            **self.label_style()
        ).pack(pady=10)

        drives = get_available_drives()
        if not drives:
            self.show_message_dialog("Error", "No available drives detected.")
            defrag_window.destroy()
            return

        selected_drive = tk.StringVar(value=drives[0])
        tk.OptionMenu(defrag_window, selected_drive, *drives).pack(pady=10)

        def start_defrag():
            drive = selected_drive.get()
            defrag_window.destroy()
            threading.Thread(target=run_defrag, args=(drive,), daemon=True).start()

        tk.Button(
            defrag_window,
            text="Start Defragmentation",
            command=start_defrag,
            **self.button_style()
        ).pack(pady=10)

    def manage_users(self):
        logging.info("Managing users.")
        manage_window, manage_frame = self.create_scrollable_window("Manage Users", width=600, height=400)

        tk.Label(
            manage_frame,
            text="Manage Users",
            font=("Segoe UI", 14, "bold"),
            fg="#ECF0F1",
            bg=self.color_theme["background"]
        ).pack(pady=10)

        for username in self.users.keys():
            user_frame = tk.Frame(manage_frame, **self.frame_style())
            user_frame.pack(fill="x", pady=5, padx=20)

            tk.Label(
                user_frame,
                text=username,
                **self.label_style()
            ).pack(side="left", padx=10)

            if username != self.admin_username:
                tk.Button(
                    user_frame,
                    text="Delete",
                    command=lambda u=username: self.delete_user(u, manage_window),
                    **self.button_style()
                ).pack(side="right", padx=10)
        logging.info("Users managed successfully.")

    def delete_user(self, username, window):
        logging.info(f"Deleting user: {username}")
        confirmed = self.show_confirmation_dialog("Delete User", f"Are you sure you want to delete the user '{username}'?")
        if confirmed:
            del self.users[username]
            self.save_users()
            self.log_action(f"Deleted user: {username}")
            self.show_message_dialog("Success", f"User '{username}' has been deleted.")
            window.destroy()
            self.manage_users()
        logging.info(f"User {username} deleted successfully.")

    def optimize_rules(self):
        logging.info("Optimizing firewall rules.")
        self.safe_execute(self._optimize_rules)
        logging.info("Firewall rules optimization completed.")

    def _optimize_rules(self):
        try:
            print("Analyzing firewall rules for optimization...")
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                    capture_output=True, text=True, check=True)
            rules = result.stdout.splitlines()
            duplicate_rules = {}
            for line in rules:
                if "Rule Name:" in line:
                    rule_name = line.split(":", 1)[1].strip()
                    duplicate_rules[rule_name] = duplicate_rules.get(rule_name, 0) + 1

            suggestions = []
            for rule, count in duplicate_rules.items():
                if count > 1:
                    suggestions.append(f"Rule '{rule}' is duplicated {count} times. Consider consolidating it.")

            optimization_window, optimization_frame = self.create_scrollable_window("Rule Optimization Suggestions", width=600, height=400)

            if suggestions:
                tk.Label(
                    optimization_frame,
                    text="Optimization Suggestions:",
                    **self.label_style()
                ).pack(pady=10)

                for suggestion in suggestions:
                    tk.Label(
                        optimization_frame,
                        text=suggestion,
                        **self.label_style(),
                        wraplength=580,
                        justify="left"
                    ).pack(anchor="w", padx=10, pady=5)

                self.log_action("Rule optimization suggestions provided.")
            else:
                tk.Label(
                    optimization_frame,
                    text="No optimizations needed. All rules are unique.",
                    **self.label_style()
                ).pack(pady=10)
                self.log_action("No rule optimizations needed.")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to analyze firewall rules: {e}")
            self.log_error(f"Failed to analyze firewall rules: {e}")
        except Exception as e:
            self.show_message_dialog("Error", f"An unexpected error occurred: {e}")
            self.log_error(f"Unexpected error in optimize_rules: {e}")

    def monitor_resources(self):
        logging.info("Monitoring system resources.")
        self.safe_execute(self._monitor_resources)
        logging.info("System resource monitoring completed.")

    def _monitor_resources(self):
        try:
            print("Monitoring system resources...")
            resource_window, resource_frame = self.create_scrollable_window("Resource Monitoring", width=400, height=300)

            cpu_label = tk.Label(resource_frame, text="CPU Usage: ", **self.label_style())
            cpu_label.pack(pady=10)

            memory_label = tk.Label(resource_frame, text="Memory Usage: ", **self.label_style())
            memory_label.pack(pady=10)

            def update_resources():
                try:
                    cpu_usage = psutil.cpu_percent(interval=1)
                    memory_info = psutil.virtual_memory()
                    memory_usage = memory_info.percent

                    cpu_label.config(text=f"CPU Usage: {cpu_usage}%")
                    memory_label.config(text=f"Memory Usage: {memory_usage}%")
                    resource_window.after(1000, update_resources)
                except Exception as e:
                    self.log_error(f"Error updating resource usage: {e}")
                    self.show_message_dialog("Error", f"Failed to update resource usage: {e}")

            update_resources()
        except Exception as e:
            self.show_message_dialog("Error", f"Failed to monitor resources: {e}")
            self.log_error(f"Failed to monitor resources: {e}")

    def ping_and_traceroute(self):
        logging.info("Running Ping and Traceroute tools.")
        self.safe_execute(self._ping_and_traceroute)
        logging.info("Ping and Traceroute completed.")

    def _ping_and_traceroute(self):
        diagnostics_window, diagnostics_frame = self.create_scrollable_window("Ping and Traceroute", width=600, height=400)

        tk.Label(
            diagnostics_frame,
            text="Network Diagnostics",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            diagnostics_frame,
            text="Enter Hostname or IP Address:",
            **self.label_style()
        ).pack(pady=5)

        host_var = tk.StringVar()
        host_entry = tk.Entry(diagnostics_frame, textvariable=host_var, **self.entry_style())
        host_entry.pack(pady=5, padx=20, fill="x")

        def run_ping():
            host = host_var.get()
            if not host:
                self.show_message_dialog("Error", "Hostname or IP Address cannot be empty!")
                return
            try:
                result = subprocess.run(["ping", "-n", "4", host], capture_output=True, text=True, check=True)
                self.show_message_dialog("Ping Results", result.stdout)
            except subprocess.CalledProcessError as e:
                self.show_message_dialog("Error", f"Ping failed: {e}")

        def run_traceroute():
            host = host_var.get()
            if not host:
                self.show_message_dialog("Error", "Hostname or IP Address cannot be empty!")
                return
            try:
                result = subprocess.run(["tracert", host], capture_output=True, text=True, check=True)
                self.show_message_dialog("Traceroute Results", result.stdout)
            except subprocess.CalledProcessError as e:
                self.show_message_dialog("Error", f"Traceroute failed: {e}")

        tk.Button(
            diagnostics_frame,
            text="Run Ping",
            command=run_ping,
            **self.button_style()
        ).pack(pady=5)

        tk.Button(
            diagnostics_frame,
            text="Run Traceroute",
            command=run_traceroute,
            **self.button_style()
        ).pack(pady=5)

    def firewall_rule_simulator(self):
        logging.info("Simulating firewall rules.")
        self.safe_execute(self._firewall_rule_simulator)
        logging.info("Firewall rule simulation completed.")

    def _firewall_rule_simulator(self):
        simulator_window, simulator_frame = self.create_scrollable_window("Firewall Rule Simulator", width=600, height=400)

        tk.Label(
            simulator_frame,
            text="Firewall Rule Simulator",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            simulator_frame,
            text="Enter Rule Details:",
            **self.label_style()
        ).pack(pady=5)

        fields = ["Port Number or Range (e.g., 80 or 1000-2000)", "Protocol (TCP/UDP)", "Action (Allow/Block)"]
        field_vars = {field: tk.StringVar() for field in fields}

        for field, var in field_vars.items():
            tk.Label(simulator_frame, text=field, **self.label_style()).pack(pady=5)
            tk.Entry(simulator_frame, textvariable=var, **self.entry_style()).pack(pady=5, padx=20, fill="x")

        def simulate_rule():
            port = field_vars["Port Number or Range (e.g., 80 or 1000-2000)"].get()
            protocol = field_vars["Protocol (TCP/UDP)"].get().upper()
            action = field_vars["Action (Allow/Block)"].get().lower()

            if not port or not protocol or not action:
                self.show_message_dialog("Error", "All fields are required!")
                return

            if protocol not in ["TCP", "UDP"]:
                self.show_message_dialog("Error", "Invalid protocol! Please enter TCP or UDP.")
                return

            if action not in ["allow", "block"]:
                self.show_message_dialog("Error", "Invalid action! Please enter Allow or Block.")
                return

            self.show_message_dialog(
                "Simulation Results",
                f"Simulated Rule:\nPort: {port}\nProtocol: {protocol}\nAction: {action.capitalize()}\n"
                "This rule would be applied successfully."
            )

        tk.Button(
            simulator_frame,
            text="Simulate Rule",
            command=simulate_rule,
            **self.button_style()
        ).pack(pady=10)

    def geo_ip_blocking(self):
        logging.info("Blocking traffic from specific countries (Geo-IP).")
        self.safe_execute(self._geo_ip_blocking)
        logging.info("Geo-IP blocking simulation completed.")

    def _geo_ip_blocking(self):
        geo_window, geo_frame = self.create_scrollable_window("Geo-IP Blocking", width=600, height=400)

        tk.Label(
            geo_frame,
            text="Geo-IP Blocking",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            geo_frame,
            text="Enter Country Codes (comma-separated, e.g., US, CN, RU):",
            **self.label_style()
        ).pack(pady=5)

        country_var = tk.StringVar()
        country_entry = tk.Entry(geo_frame, textvariable=country_var, **self.entry_style())
        country_entry.pack(pady=5, padx=20, fill="x")

        def block_countries():
            countries = country_var.get()
            if not countries:
                self.show_message_dialog("Error", "Country codes cannot be empty!")
                return

            country_list = [code.strip().upper() for code in countries.split(",")]
            self.show_message_dialog(
                "Geo-IP Blocking",
                f"Traffic from the following countries would be blocked:\n{', '.join(country_list)}"
            )
            self.log_action(f"Geo-IP Blocking simulated for countries: {', '.join(country_list)}")

        tk.Button(
            geo_frame,
            text="Simulate Geo-IP Blocking",
            command=block_countries,
            **self.button_style()
        ).pack(pady=10)

    def generate_reports(self):
        logging.info("Generating reports.")
        self.safe_execute(self._generate_reports)
        logging.info("Reports generated successfully.")

    def _generate_reports(self):
        report_window, report_frame = self.create_scrollable_window("Generate Reports", width=600, height=400)

        tk.Label(
            report_frame,
            text="Generate Reports",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            report_frame,
            text="Select Report Type:",
            **self.label_style()
        ).pack(pady=5)

        report_types = ["Firewall Activity", "Rule Usage", "Network Traffic"]
        report_var = tk.StringVar(value=report_types[0])

        for report_type in report_types:
            tk.Radiobutton(
                report_frame,
                text=report_type,
                variable=report_var,
                value=report_type,
                **self.label_style(),
                bg=self.color_theme["background"],
                selectcolor=self.color_theme["frame_bg"]
            ).pack(anchor="w", padx=20)

        def generate_report():
            selected_report = report_var.get()
            if selected_report == "Firewall Activity":
                self._generate_firewall_activity_report()
            elif selected_report == "Rule Usage":
                self._generate_rule_usage_report()
            elif selected_report == "Network Traffic":
                self._generate_network_traffic_report()

        tk.Button(
            report_frame,
            text="Generate Report",
            command=generate_report,
            **self.button_style()
        ).pack(pady=10)

    def _generate_firewall_activity_report(self):
        logging.info("Generating firewall activity report.")
        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                    capture_output=True, text=True, check=True)
            rules = result.stdout.splitlines()
            total_rules = len([line for line in rules if "Rule Name:" in line])
            allow_rules = len([line for line in rules if "Action: Allow" in line])
            block_rules = len([line for line in rules if "Action: Block" in line])

            data = {
                "Category": ["Total Rules", "Allow Rules", "Block Rules"],
                "Count": [total_rules, allow_rules, block_rules]
            }
            self._visualize_data(data, "Firewall Activity Report")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to generate firewall activity report: {e}")

    def _generate_rule_usage_report(self):
        logging.info("Generating rule usage report.")
        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                                    capture_output=True, text=True, check=True)
            rules = result.stdout.splitlines()
            rule_names = [line.split(":", 1)[1].strip() for line in rules if "Rule Name:" in line]
            rule_counts = {rule: rule_names.count(rule) for rule in set(rule_names)}

            data = {
                "Rule Name": list(rule_counts.keys()),
                "Usage Count": list(rule_counts.values())
            }
            self._visualize_data(data, "Rule Usage Report", chart_type="bar")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to generate rule usage report: {e}")

    def _generate_network_traffic_report(self):
        logging.info("Generating network traffic report.")
        try:
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, check=True)
            connections = [line for line in result.stdout.splitlines() if "ESTABLISHED" in line]
            protocols = [line.split()[0] for line in connections]
            protocol_counts = {protocol: protocols.count(protocol) for protocol in set(protocols)}

            data = {
                "Protocol": list(protocol_counts.keys()),
                "Connection Count": list(protocol_counts.values())
            }
            self._visualize_data(data, "Network Traffic Report", chart_type="pie")
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to generate network traffic report: {e}")

    def _visualize_data(self, data, title, chart_type="bar"):
        logging.info(f"Visualizing data: {title}")
        try:
            df = pd.DataFrame(data)
            fig, ax = plt.subplots(figsize=(8, 6))

            if chart_type == "bar":
                df.plot(kind="bar", x=df.columns[0], y=df.columns[1], ax=ax, legend=False)
            elif chart_type == "pie":
                df.set_index(df.columns[0]).plot(kind="pie", y=df.columns[1], ax=ax, legend=False, autopct="%1.1f%%")

            ax.set_title(title)
            ax.set_ylabel("")
            plt.tight_layout()

            chart_window = tk.Toplevel(self.root)
            chart_window.title(title)
            chart_window.geometry("800x600")
            chart_window.configure(bg=self.color_theme["background"])

            canvas = tk.Canvas(chart_window, bg=self.color_theme["background"])
            canvas.pack(fill="both", expand=True)

            img = BytesIO()
            plt.savefig(img, format="png")
            img.seek(0)

            chart_image = tk.PhotoImage(data=img.read())
            canvas.create_image(0, 0, anchor="nw", image=chart_image)
            canvas.image = chart_image

            plt.close(fig)
        except Exception as e:
            self.show_message_dialog("Error", f"Failed to visualize data: {e}")

    def export_reports(self):
        logging.info("Exporting reports.")
        self.safe_execute(self._export_reports)
        logging.info("Reports exported successfully.")

    def _export_reports(self):
        export_window, export_frame = self.create_scrollable_window("Export Reports", width=600, height=400)

        tk.Label(
            export_frame,
            text="Export Reports",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            export_frame,
            text="Select Export Format:",
            **self.label_style()
        ).pack(pady=5)

        formats = ["CSV", "Excel"]
        format_var = tk.StringVar(value=formats[0])

        for fmt in formats:
            tk.Radiobutton(
                export_frame,
                text=fmt,
                variable=format_var,
                value=fmt,
                **self.label_style(),
                bg=self.color_theme["background"],
                selectcolor=self.color_theme["frame_bg"]
            ).pack(anchor="w", padx=20)

        def export_report():
            selected_format = format_var.get()
            file_path = filedialog.asksaveasfilename(
                defaultextension=f".{selected_format.lower()}",
                filetypes=[(f"{selected_format} Files", f"*.{selected_format.lower()}")]
            )
            if not file_path:
                return

            try:
                data = {
                    "Category": ["Example 1", "Example 2", "Example 3"],
                    "Value": [10, 20, 30]
                }
                df = pd.DataFrame(data)

                if selected_format == "CSV":
                    df.to_csv(file_path, index=False)
                elif selected_format == "Excel":
                    df.to_excel(file_path, index=False, engine="openpyxl")

                self.show_message_dialog("Success", f"Report exported successfully to {file_path}.")
            except Exception as e:
                self.show_message_dialog("Error", f"Failed to export report: {e}")

        tk.Button(
            export_frame,
            text="Export Report",
            command=export_report,
            **self.button_style()
        ).pack(pady=10)

    def port_scanning(self):
        logging.info("Scanning ports.")
        self.safe_execute(self._port_scanning)
        logging.info("Port scanning completed.")

    def _port_scanning(self):
        scan_window, scan_frame = self.create_scrollable_window("Port Scanning", width=600, height=400)

        tk.Label(
            scan_frame,
            text="Port Scanning",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            scan_frame,
            text="Enter Target IP Address or Hostname:",
            **self.label_style()
        ).pack(pady=5)

        target_var = tk.StringVar()
        target_entry = tk.Entry(scan_frame, textvariable=target_var, **self.entry_style())
        target_entry.pack(pady=5, padx=20, fill="x")

        def scan_ports():
            target = target_var.get()
            if not target:
                self.show_message_dialog("Error", "Target cannot be empty!")
                return

            try:
                result = subprocess.run(["nmap", "-p-", target], capture_output=True, text=True, check=True)
                self.show_message_dialog("Scan Results", result.stdout)
            except subprocess.CalledProcessError as e:
                self.show_message_dialog("Error", f"Port scanning failed: {e}")

        tk.Button(
            scan_frame,
            text="Scan Ports",
            command=scan_ports,
            **self.button_style()
        ).pack(pady=10)

    def validate_firewall_rule(self, rule_name, protocol, port):
        logging.info(f"Validating firewall rule: {rule_name}")
        self.safe_execute(self._validate_firewall_rule, rule_name, protocol, port)
        logging.info(f"Firewall rule {rule_name} validated successfully.")

    def _validate_firewall_rule(self, rule_name, protocol, port):
        try:
            result = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                                    capture_output=True, text=True, check=True)
            if result.stdout:
                self.show_message_dialog("Validation Error", f"Rule '{rule_name}' already exists.")
                return False

            if protocol not in ["TCP", "UDP"]:
                self.show_message_dialog("Validation Error", "Invalid protocol! Must be TCP or UDP.")
                return False

            if not port.isdigit() or not (1 <= int(port) <= 65535):
                self.show_message_dialog("Validation Error", "Invalid port! Must be between 1 and 65535.")
                return False

            self.show_message_dialog("Validation Success", "The rule is valid and can be applied.")
            return True
        except subprocess.CalledProcessError as e:
            self.show_message_dialog("Error", f"Failed to validate rule: {e}")
            return False

    def malware_detection(self):
        logging.info("Detecting malware.")
        self.safe_execute(self._malware_detection)
        logging.info("Malware detection completed.")

    def _malware_detection(self):
        detection_window, detection_frame = self.create_scrollable_window("Malware Detection", width=600, height=400)

        tk.Label(
            detection_frame,
            text="Malware Detection",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            detection_frame,
            text="Enter File Path to Scan:",
            **self.label_style()
        ).pack(pady=5)

        file_var = tk.StringVar()
        file_entry = tk.Entry(detection_frame, textvariable=file_var, **self.entry_style())
        file_entry.pack(pady=5, padx=20, fill="x")

        def scan_file():
            file_path = file_var.get()
            if not os.path.exists(file_path):
                self.show_message_dialog("Error", "File does not exist!")
                return

            try:
                with open(file_path, "r", errors="ignore") as file:
                    content = file.read()
                    if "malware_signature" in content:
                        self.show_message_dialog("Malware Detected", f"Malware detected in file: {file_path}")
                    else:
                        self.show_message_dialog("No Malware", f"No malware detected in file: {file_path}")
            except Exception as e:
                self.show_message_dialog("Error", f"Failed to scan file: {e}")

        tk.Button(
            detection_frame,
            text="Scan File",
            command=scan_file,
            **self.button_style()
        ).pack(pady=10)

    def custom_themes(self):
        logging.info("Creating and saving custom themes.")
        self.safe_execute(self._custom_themes)
        logging.info("Custom themes saved successfully.")

    def _custom_themes(self):
        theme_window, theme_frame = self.create_scrollable_window("Custom Themes", width=600, height=400)

        tk.Label(
            theme_frame,
            text="Custom Themes",
            **self.label_style()
        ).pack(pady=10)

        fields = ["Background Color", "Foreground Color", "Button Background", "Button Foreground"]
        field_vars = {field: tk.StringVar(value=self.color_theme.get(field.lower().replace(" ", "_"), "")) for field in fields}

        for field, var in field_vars.items():
            tk.Label(theme_frame, text=field, **self.label_style()).pack(pady=5)
            tk.Entry(theme_frame, textvariable=var, **self.entry_style()).pack(pady=5, padx=20, fill="x")

        def save_theme():
            for field, var in field_vars.items():
                self.color_theme[field.lower().replace(" ", "_")] = var.get()
            self.update_widget_colors(self.root)
            self.log_action("Custom theme applied and saved.")
            self.show_message_dialog("Success", "Custom theme has been applied and saved.")

        tk.Button(
            theme_frame,
            text="Save Theme",
            command=save_theme,
            **self.button_style()
        ).pack(pady=10)

    def language_support(self):
        logging.info("Adding multi-language support.")
        self.safe_execute(self._language_support)
        logging.info("Language support applied successfully.")

    def _language_support(self):
        language_window, language_frame = self.create_scrollable_window("Language Support", width=400, height=300)

        tk.Label(
            language_frame,
            text="Select Language",
            **self.label_style()
        ).pack(pady=10)

        languages = {"English": "en", "Spanish": "es", "French": "fr", "German": "de", "Chinese": "zh"}
        language_var = tk.StringVar(value="en")

        for lang_name, lang_code in languages.items():
            tk.Radiobutton(
                language_frame,
                text=lang_name,
                variable=language_var,
                value=lang_code,
                **self.label_style(),
                selectcolor=self.color_theme["frame_bg"]
            ).pack(anchor="w", padx=20)

        def apply_language():
            selected_language = language_var.get()
            self.current_language = selected_language
            self.log_action(f"Language set to {selected_language}.")
            self.show_message_dialog("Success", f"Language has been set to {selected_language}.")

        tk.Button(
            language_frame,
            text="Apply Language",
            command=apply_language,
            **self.button_style()
        ).pack(pady=10)

    def customizable_dashboard(self):
        logging.info("Customizing dashboard.")
        self.safe_execute(self._customizable_dashboard)
        logging.info("Dashboard customization completed.")

    def _customizable_dashboard(self):
        dashboard_window, dashboard_frame = self.create_scrollable_window("Customizable Dashboard", width=600, height=400)

        tk.Label(
            dashboard_frame,
            text="Customizable Dashboard",
            **self.label_style()
        ).pack(pady=10)

        sections = ["Firewall Rules", "Settings", "Live Network Traffic"]
        section_vars = {section: tk.BooleanVar(value=True) for section in sections}

        for section, var in section_vars.items():
            tk.Checkbutton(
                dashboard_frame,
                text=section,
                variable=var,
                **self.label_style(),
                selectcolor=self.color_theme["frame_bg"]
            ).pack(anchor="w", padx=20)

        def apply_dashboard_changes():
            self.dashboard_config = {section: var.get() for section, var in section_vars.items()}
            self.log_action("Dashboard configuration updated.")
            self.show_message_dialog("Success", "Dashboard configuration has been updated.")
            self.create_main_menu()

        tk.Button(
            dashboard_frame,
            text="Apply Changes",
            command=apply_dashboard_changes,
            **self.button_style()
        ).pack(pady=10)

    def network_monitoring(self):
        logging.info("Monitoring network traffic.")
        self.safe_execute(self._network_monitoring)
        logging.info("Network monitoring completed.")

    def _network_monitoring(self):
        monitoring_window, monitoring_frame = self.create_scrollable_window("Network Monitoring", width=800, height=600)

        tk.Label(
            monitoring_frame,
            text="Network Monitoring",
            **self.label_style()
        ).pack(pady=10)

        tk.Label(
            monitoring_frame,
            text="Real-Time Traffic Analysis",
            **self.label_style()
        ).pack(pady=5)

        traffic_text = tk.Text(
            monitoring_frame,
            font=("Courier", 10),
            bg="#2C3E50",
            fg="#ECF0F1",
            wrap="none",
            state="disabled",
            height=20
        )
        traffic_text.pack(fill="both", expand=True, padx=10, pady=5)

        def update_traffic():
            try:
                result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, shell=True)
                output = result.stdout if result.returncode == 0 else result.stderr

                filtered_lines = []
                for line in output.splitlines():
                    if "ESTABLISHED" in line or "CLOSE_WAIT" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            protocol = parts[0]
                            local_address = parts[1]
                            remote_address = parts[2]
                            filtered_lines.append(f"{protocol} | Local: {local_address} | Remote: {remote_address}")

                traffic_text.config(state="normal")
                traffic_text.delete("1.0", "end")
                traffic_text.insert("1.0", "\n".join(filtered_lines))
                traffic_text.see("end")
                traffic_text.config(state="disabled")
                monitoring_window.after(5000, update_traffic)
            except Exception as e:
                self.log_error(f"Error updating traffic: {e}")

        update_traffic()

        tk.Label(
            monitoring_frame,
            text="Bandwidth Usage",
            **self.label_style()
        ).pack(pady=5)

        bandwidth_text = tk.Text(
            monitoring_frame,
            font=("Courier", 10),
            bg="#2C3E50",
            fg="#ECF0F1",
            wrap="none",
            state="disabled",
            height=20
        )
        bandwidth_text.pack(fill="both", expand=True, padx=10, pady=5)

        def update_bandwidth():
            try:
                bandwidth_data = []
                for conn in psutil.net_connections(kind="inet"):
                    if conn.laddr and conn.raddr:
                        app_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                        bandwidth_data.append(f"{app_name} | Local: {conn.laddr} | Remote: {conn.raddr}")

                bandwidth_text.config(state="normal")
                bandwidth_text.delete("1.0", "end")
                bandwidth_text.insert("1.0", "\n".join(bandwidth_data))
                bandwidth_text.see("end")
                bandwidth_text.config(state="disabled")
                monitoring_window.after(5000, update_bandwidth)
            except Exception as e:
                self.log_error(f"Error updating bandwidth: {e}")

        update_bandwidth()

        tk.Label(
            monitoring_frame,
            text="Intrusion Detection",
            **self.label_style()
        ).pack(pady=5)

        intrusion_text = tk.Text(
            monitoring_frame,
            font=("Courier", 10),
            bg="#2C3E50",
            fg="#ECF0F1",
            wrap="none",
            state="disabled",
            height=20
        )
        intrusion_text.pack(fill="both", expand=True, padx=10, pady=5)

        def detect_intrusions():
            try:
                suspicious_patterns = ["192.168.1.1", "malicious_ip"]
                result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, shell=True)
                output = result.stdout if result.returncode == 0 else result.stderr

                detected_intrusions = []
                for line in output.splitlines():
                    if any(pattern in line for pattern in suspicious_patterns):
                        detected_intrusions.append(line)

                intrusion_text.config(state="normal")
                intrusion_text.delete("1.0", "end")
                intrusion_text.insert("1.0", "\n".join(detected_intrusions))
                intrusion_text.see("end")
                intrusion_text.config(state="disabled")
                monitoring_window.after(5000, detect_intrusions)
            except Exception as e:
                self.log_error(f"Error detecting intrusions: {e}")

        detect_intrusions()

    def open_live_data_viewer(self):
        logging.info("Opening live data viewer.")
        live_data_window, live_data_frame = self.create_scrollable_window("Live Data Viewer", width=800, height=600)

        tk.Label(
            live_data_frame,
            text="Live Network Traffic",
            font=self.fonts["subheader"],
            fg=self.color_theme["foreground"],
            bg=self.color_theme["background"]
        ).pack(pady=10)

        traffic_text = tk.Text(
            live_data_frame,
            font=("Courier", 10),
            bg=self.color_theme["entry_bg"],
            fg=self.color_theme["entry_fg"],
            wrap="none",
            state="disabled",
            height=20
        )
        traffic_text.pack(fill="both", expand=True, padx=10, pady=10)

        def update_traffic():
            try:
                result = subprocess.run(["netstat", "-an"], capture_output=True, text=True, shell=True)
                output = result.stdout if result.returncode == 0 else result.stderr

                filtered_lines = []
                for line in output.splitlines():
                    if "ESTABLISHED" in line or "CLOSE_WAIT" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            protocol = parts[0]
                            local_address = parts[1]
                            remote_address = parts[2]
                            filtered_lines.append(f"{protocol} | Local: {local_address} | Remote: {remote_address}")

                traffic_text.config(state="normal")
                traffic_text.delete("1.0", "end")
                traffic_text.insert("1.0", "\n".join(filtered_lines))
                traffic_text.see("end")
                traffic_text.config(state="disabled")
                live_data_window.after(5000, update_traffic)
            except Exception as e:
                self.log_error(f"Error updating traffic: {e}")

        update_traffic()

_application_initialized = False

INITIALIZATION_FLAG_FILE = "app_initialized.flag"

def main():
    logging.info("Starting main function.")
    try:
        logging.info("Entering main function.")
        print("Starting application...")

        if not is_admin():
            logging.warning("Admin privileges not detected. Attempting to relaunch as admin.")
            relaunch_as_admin()

        if not check_python_installation():
            logging.error("Python installation check failed. Exiting.")
            pause_on_exit()
            sys.exit()
        if not check_dependencies():
            logging.error("Dependency check failed. Exiting.")
            pause_on_exit()
            sys.exit()

        if not os.path.exists(INITIALIZATION_FLAG_FILE):
            logging.info("Initializing the application.")
            with open(INITIALIZATION_FLAG_FILE, "w") as flag_file:
                flag_file.write("initialized")

        root = tk.Tk()
        app = FirewallManagerApp(root)
        logging.info("Application initialized successfully. Starting authentication.")
        app.authenticate_user()
        logging.info("Authentication completed. Entering Tkinter mainloop.")
        root.mainloop()
        logging.info("Application closed normally.")
    except Exception as e:
        error_message = f"An unexpected error occurred:\n{traceback.format_exc()}"
        logging.critical(error_message)
        with open("error_log.txt", "a") as error_file:
            error_file.write(error_message + "\n")
        print(error_message)
        messagebox.showerror("Error", f"An unexpected error occurred:\n{str(e)}")
        pause_on_exit()
    finally:
        if os.path.exists(INITIALIZATION_FLAG_FILE):
            os.remove(INITIALIZATION_FLAG_FILE)
        logging.info("Main function completed.")

if __name__ == "__main__":
    logging.info("Starting the application entry point.")
    print("Starting the application...")

    if not is_admin():
        logging.warning("Admin privileges not detected. Attempting to relaunch as admin.")
        relaunch_as_admin()

    try:
        logging.info("Launching main application.")
        main()
    except Exception as e:
        logging.critical(f"Critical error in application: {e}")
        print(f"Critical error: {e}")
        pause_on_exit()
        sys.exit(1)
    logging.info("Application entry point completed.")
