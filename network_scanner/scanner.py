#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROYECTO: CyberScanner v4.9.2 - Auditoría de Redes
ESTUDIANTE: Jose Tapia, Martin Cortes
DESCRIPCIÓN: Herramienta profesional de auditoría para identificar hosts y 
servicios, optimizada para ejecución silenciosa en Windows y Linux.
"""

import socket
import subprocess
import threading
import platform
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
from datetime import datetime, timedelta, timezone
import multiprocessing  # <--- CRUCIAL PARA EL .EXE

# --- CONFIGURACIÓN DE IDENTIDAD VISUAL ---
COLOR_BG = "#0A0F1E"
COLOR_CARD = "#16213E"
COLOR_ACCENT = "#00D2FF"
COLOR_TEXT = "#E1E8EB"
COLOR_SUCCESS = "#00FFC2"
COLOR_ERROR = "#FF4B2B"
COLOR_WARN = "#FFD700"

# --- LÓGICA DE AUDITORÍA TÉCNICA ---

def get_chile_time():
    """Calcula la hora exacta de Chile (UTC-4) para validez técnica local."""
    tz_chile = timezone(timedelta(hours=-4))
    return datetime.now(tz_chile).strftime("%Y-%m-%d %H:%M:%S")

def ping_analisis(host):
    """
    Realiza un 'Ping Sweep' invisible.
    Se utiliza startupinfo para evitar que se abran ventanas de ping.exe en Windows.
    """
    import platform
    sistema = platform.system().lower()
    
    # Configuración para que el ping sea SILENCIOSO en Windows
    startupinfo = None
    if sistema == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        param = '-n'
        wait = '-w'
    else:
        param = '-c'
        wait = '-W'

    comando = ['ping', param, '1', wait, '1000', host]
    
    # startupinfo=startupinfo es lo que evita las múltiples ventanas de consola
    return subprocess.call(comando, startupinfo=startupinfo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def scan_puerto_avanzado(host, port):
    """Analiza el estado de un puerto TCP y la fidelidad de la respuesta."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.6) 
    try:
        start_t = datetime.now()
        result = s.connect_ex((host, port)) 
        end_t = datetime.now()
        latencia = (end_t - start_t).total_seconds() * 1000

        if result == 0:
            return "ABIERTO", f"Servicio Activo ({latencia:.1f}ms)"
        elif result in [11, 35, 110, 10060]: # 10060 es el error de timeout en Windows
            return "FILTRADO", "[!] Alerta: Paquete DROP (Firewall detectado)."
        else:
            return "CERRADO", "Puerto cerrado."
    except:
        return "ERROR", "Error de conexión."
    finally:
        s.close() 

class ScannerChileV49:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberScanner v4.9.2 - Auditoría Telecom INACAP")
        self.root.geometry("1000x750")
        self.root.configure(bg=COLOR_BG)
        
        self.host_database = {}
        self.db_lock = threading.Lock() 

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(self.tab, text=" PANEL DE AUDITORÍA ")

        ctrl_frame = tk.Frame(self.tab, bg=COLOR_CARD, pady=10)
        ctrl_frame.pack(fill=tk.X)
        
        tk.Label(ctrl_frame, text="RED:", bg=COLOR_CARD, fg=COLOR_ACCENT, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)
        self.entry_net = tk.Entry(ctrl_frame, width=12, font=("Consolas", 12))
        self.entry_net.insert(0, "10.0.2") 
        self.entry_net.pack(side=tk.LEFT, padx=5)
        
        self.btn_run = tk.Button(ctrl_frame, text="INICIAR SCAN", bg=COLOR_ACCENT, command=self.iniciar)
        self.btn_run.pack(side=tk.LEFT, padx=10)
        
        tk.Button(ctrl_frame, text="💾 GUARDAR", bg=COLOR_SUCCESS, command=self.guardar).pack(side=tk.RIGHT, padx=10)

        pw = tk.PanedWindow(self.tab, orient=tk.HORIZONTAL, bg=COLOR_BG, bd=0)
        pw.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.listbox = tk.Listbox(pw, bg=COLOR_CARD, fg=COLOR_SUCCESS, font=("Consolas", 11))
        self.listbox.bind("<<ListboxSelect>>", self.ver_detalle)
        pw.add(self.listbox, width=250)

        self.txt_audit = scrolledtext.ScrolledText(pw, bg=COLOR_CARD, fg=COLOR_TEXT, font=("Consolas", 10))
        self.txt_audit.tag_config("ALERTA", foreground=COLOR_ERROR, font=("Consolas", 10, "bold"))
        self.txt_audit.tag_config("INFO", foreground=COLOR_WARN)
        self.txt_audit.tag_config("SUCCESS", foreground=COLOR_SUCCESS)
        pw.add(self.txt_audit)

    def iniciar(self):
        net = self.entry_net.get()
        self.listbox.delete(0, tk.END)
        self.host_database.clear()
        self.btn_run.config(state=tk.DISABLED, text="Escaneando...")
        threading.Thread(target=self.hilo_maestro, args=(net,), daemon=True).start()

    def hilo_maestro(self, net):
        threads = []
        for i in range(1, 255):
            t = threading.Thread(target=self.auditar_host, args=(f"{net}.{i}",), daemon=True)
            threads.append(t)
            t.start()
        for t in threads: t.join()
        self.root.after(0, lambda: self.btn_run.config(state=tk.NORMAL, text="INICIAR SCAN"))

    def auditar_host(self, ip):
        if ping_analisis(ip):
            reporte = [(f"--- AUDITORÍA TÉCNICA: {ip} ---\n", "SUCCESS"), (f"FECHA: {get_chile_time()}\n", "INFO")]
            
            servicios = {22:"SSH", 53:"DNS", 80:"HTTP", 443:"HTTPS"}
            for p, srv in servicios.items():
                estado, desc = scan_puerto_avanzado(ip, p)
                tag = "SUCCESS" if estado == "ABIERTO" else "ALERTA" if estado == "FILTRADO" else "INFO"
                reporte.append((f"Port {p} ({srv}): {estado} - {desc}\n", tag))

            with self.db_lock:
                self.host_database[ip] = reporte
                self.root.after(0, lambda: self.listbox.insert(tk.END, ip))

    def ver_detalle(self, event):
        sel = self.listbox.curselection()
        if sel:
            ip = self.listbox.get(sel[0])
            self.txt_audit.delete(1.0, tk.END)
            for texto, tag in self.host_database[ip]:
                self.txt_audit.insert(tk.END, texto, tag)

    def guardar(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w") as f:
                f.write(f"REPORTE AUDITORÍA CHILE - {get_chile_time()}\n\n")
                for ip in sorted(self.host_database.keys()):
                    for texto, tag in self.host_database[ip]: f.write(texto)
                    f.write("\n" + "#"*50 + "\n")
            messagebox.showinfo("Éxito", "Reporte guardado correctamente.")

if __name__ == "__main__":
    # --- ARREGLO PARA WINDOWS (DETIENE EL BUCLE DE VENTANAS) ---
    multiprocessing.freeze_support()
    
    root = tk.Tk()
    app = ScannerChileV49(root)
    root.mainloop()