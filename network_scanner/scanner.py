#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROYECTO: CyberScanner v4.9.5 - Versión de Alto Rendimiento
ESTUDIANTES: Jose Tapia, Martin Cortes (Telecomunicaciones)
ESTADO: Optimizado para Windows (.exe) y Linux (LabVM)
"""

import socket
import subprocess
import threading
import platform
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
from datetime import datetime, timedelta, timezone
import multiprocessing

# --- CONFIGURACIÓN VISUAL ---
COLOR_BG = "#0A0F1E"
COLOR_CARD = "#16213E"
COLOR_ACCENT = "#00D2FF"
COLOR_TEXT = "#E1E8EB"
COLOR_SUCCESS = "#00FFC2"
COLOR_ERROR = "#FF4B2B"
COLOR_WARN = "#FFD700"

def get_chile_time():
    """Hora local para validez de auditoría."""
    tz_chile = timezone(timedelta(hours=-4))
    return datetime.now(tz_chile).strftime("%Y-%m-%d %H:%M:%S")

def ping_analisis(host):
    """Ping invisible y de alta velocidad."""
    sistema = platform.system().lower()
    startupinfo = None
    
    if sistema == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        # -n 1 (un paquete), -w 500 (espera 0.5 seg)
        comando = ['ping', '-n', '1', '-w', '500', host]
    else:
        # -c 1 (un paquete), -W 1 (espera 1 seg)
        comando = ['ping', '-c', '1', '-W', '1', host]
        
    try:
        return subprocess.call(comando, startupinfo=startupinfo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def scan_puerto_avanzado(host, port):
    """Escaneo de capa 4 con detección de firewall."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4) # Timeout corto para fluidez
    try:
        result = s.connect_ex((host, port))
        if result == 0:
            return "ABIERTO", "Servicio Activo"
        elif result in [11, 35, 110, 10060]: # Códigos de DROP/Firewall
            return "FILTRADO", "[!] Firewall Detectado"
        return "CERRADO", "Cerrado"
    except:
        return "ERROR", "Sin respuesta"
    finally:
        s.close()

class ScannerChileV49:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberScanner v4.9.5 - Power Rangers Telecom")
        self.root.geometry("1000x750")
        self.root.configure(bg=COLOR_BG)
        
        self.host_database = {}
        self.db_lock = threading.Lock()
        # Semáforo: Solo 50 escaneos simultáneos para no trabar el PC
        self.escaneo_semaphore = threading.Semaphore(50)

        # Interfaz
        self.tab = tk.Frame(self.root, bg=COLOR_BG)
        self.tab.pack(fill=tk.BOTH, expand=True)

        ctrl_frame = tk.Frame(self.tab, bg=COLOR_CARD, pady=10)
        ctrl_frame.pack(fill=tk.X)
        
        tk.Label(ctrl_frame, text="SUBRED:", bg=COLOR_CARD, fg=COLOR_ACCENT, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)
        self.entry_net = tk.Entry(ctrl_frame, width=12, font=("Consolas", 12))
        self.entry_net.insert(0, "10.0.2")
        self.entry_net.pack(side=tk.LEFT, padx=5)
        
        self.btn_run = tk.Button(ctrl_frame, text="INICIAR SCAN", bg=COLOR_ACCENT, font=("Arial", 10, "bold"), command=self.iniciar)
        self.btn_run.pack(side=tk.LEFT, padx=10)
        
        tk.Button(ctrl_frame, text="💾 GUARDAR", bg=COLOR_SUCCESS, command=self.guardar).pack(side=tk.RIGHT, padx=10)

        pw = tk.PanedWindow(self.tab, orient=tk.HORIZONTAL, bg=COLOR_BG, bd=0)
        pw.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.listbox = tk.Listbox(pw, bg=COLOR_CARD, fg=COLOR_SUCCESS, font=("Consolas", 11), bd=0)
        self.listbox.bind("<<ListboxSelect>>", self.ver_detalle)
        pw.add(self.listbox, width=280)

        self.txt_audit = scrolledtext.ScrolledText(pw, bg=COLOR_CARD, fg=COLOR_TEXT, font=("Consolas", 10), bd=0)
        self.txt_audit.tag_config("ALERTA", foreground=COLOR_ERROR)
        self.txt_audit.tag_config("INFO", foreground=COLOR_WARN)
        self.txt_audit.tag_config("SUCCESS", foreground=COLOR_SUCCESS)
        pw.add(self.txt_audit)

    def iniciar(self):
        net = self.entry_net.get()
        self.listbox.delete(0, tk.END)
        self.host_database.clear()
        self.txt_audit.delete(1.0, tk.END)
        self.btn_run.config(state=tk.DISABLED, text="Escaneando...")
        # Hilo maestro para que la ventana no se ponga "No responde"
        threading.Thread(target=self.hilo_maestro, args=(net,), daemon=True).start()

    def hilo_maestro(self, net):
        threads = []
        for i in range(1, 255):
            ip = f"{net}.{i}"
            # Ejecutar con límite de hilos
            t = threading.Thread(target=self.worker_limitado, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        
        for t in threads: t.join()
        self.root.after(0, lambda: self.btn_run.config(state=tk.NORMAL, text="INICIAR SCAN"))
        self.root.after(0, lambda: messagebox.showinfo("Fin", "Escaneo de subred completado."))

    def worker_limitado(self, ip):
        """Usa el semáforo para controlar la carga del CPU."""
        with self.escaneo_semaphore:
            self.auditar_host(ip)

    def auditar_host(self, ip):
        if ping_analisis(ip):
            reporte = [(f"--- AUDITORÍA: {ip} ---\n", "SUCCESS"), (f"HORA: {get_chile_time()}\n", "INFO")]
            puertos = {22:"SSH", 53:"DNS", 80:"HTTP", 443:"HTTPS"}
            for p, srv in puertos.items():
                estado, desc = scan_puerto_avanzado(ip, p)
                tag = "SUCCESS" if estado == "ABIERTO" else "ALERTA" if estado == "FILTRADO" else "INFO"
                reporte.append((f"Perto {p} ({srv}): {estado} - {desc}\n", tag))
            
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
                f.write(f"REPORTE CYBERSCANNER - {get_chile_time()}\n\n")
                for ip in sorted(self.host_database.keys()):
                    for texto, _ in self.host_database[ip]: f.write(texto)
                    f.write("\n" + "="*45 + "\n")
            messagebox.showinfo("Éxito", "Archivo guardado.")

if __name__ == "__main__":
    # Crucial para evitar bucles en el .exe
    multiprocessing.freeze_support()
    
    root = tk.Tk()
    app = ScannerChileV49(root)
    root.mainloop()