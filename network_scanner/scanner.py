#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROYECTO: CyberScanner v4.9 - Auditoría de Redes
ESTUDIANTE: Jose Tapia, Martin Cortes
DESCRIPCIÓN: Herramienta profesional de auditoría para identificar hosts y 
servicios, con análisis de latencia y detección de Firewalls (Capa 4).
"""

import socket
import subprocess
import threading
import platform
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
from datetime import datetime, timedelta, timezone
import multiprocessing  # <--- AGREGADO PARA COMPATIBILIDAD CON WINDOWS .EXE

# --- CONFIGURACIÓN DE IDENTIDAD VISUAL ---
COLOR_BG = "#0A0F1E"      # Fondo oscuro profundo
COLOR_CARD = "#16213E"    # Fondo de contenedores
COLOR_ACCENT = "#00D2FF"  # Celeste para títulos y botones
COLOR_TEXT = "#E1E8EB"    # Texto claro para lectura
COLOR_SUCCESS = "#00FFC2" # Verde para servicios activos y éxito
COLOR_ERROR = "#FF4B2B"   # Rojo para alertas de Firewall [!]
COLOR_WARN = "#FFD700"    # Amarillo para notas técnicas e infraestructura

# --- LÓGICA DE AUDITORÍA TÉCNICA ---

def get_chile_time():
    """
    Calcula la hora exacta de Chile (UTC-4).
    Se utiliza timedelta para asegurar compatibilidad con Python 3.8+ en la VM.
    Esto permite que los reportes tengan validez legal y técnica local.
    """
    tz_chile = timezone(timedelta(hours=-4))
    return datetime.now(tz_chile).strftime("%Y-%m-%d %H:%M:%S")

def ping_analisis(host):
    """
    Realiza un 'Ping Sweep' (ICMP) para verificar si un host está vivo.
    -c 1: Envía un solo paquete.
    -W 1: Espera máximo 1 segundo la respuesta.
    """
    import platform
    # Ajuste de parámetros según sistema operativo para mayor estabilidad
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    wait = '-w' if platform.system().lower() == 'windows' else '-W'
    comando = ['ping', param, '1', wait, '1000', host]
    return subprocess.call(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def scan_puerto_avanzado(host, port):
    """
    Analiza el estado de un puerto TCP y la fidelidad de la respuesta.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.6) 
    try:
        start_t = datetime.now()
        result = s.connect_ex((host, port)) 
        end_t = datetime.now()
        latencia = (end_t - start_t).total_seconds() * 1000

        if result == 0:
            try:
                s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                banner = s.recv(512).decode(errors='ignore').strip()[:40]
                return "ABIERTO", f"Banner: {banner if banner else 'Servicio Activo'} ({latencia:.1f}ms)"
            except:
                return "ABIERTO", f"Servicio detectado (Sin banner) ({latencia:.1f}ms)"
        
        elif result in [11, 35, 110, 10060]: # Agregado 10060 para errores de Windows
            return "FILTRADO", "[!] Alerta: Paquete DROP (Posible Firewall/ACL bloqueando el paso)."
        elif result == 111:
            return "CERRADO", "Host rechazó la conexión (Puerto cerrado)."
        else:
            return "TIMEOUT", "[!] Sin respuesta: El host ignoró la petición TCP."
    finally:
        s.close() 

# --- INTERFAZ GRÁFICA DE USUARIO (GUI) ---

class ScannerChileV49:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberScanner v4.9 - Auditoría Telecom INACAP")
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
            hora = get_chile_time()
            reporte = []
            reporte.append((f"--- AUDITORÍA TÉCNICA: {ip} ---\n", "SUCCESS"))
            reporte.append((f"FECHA LOCAL: {hora} (CLT)\n", "INFO"))
            reporte.append((f"{'='*45}\n\n", "INFO"))
            
            servicios = {22:"SSH", 53:"DNS", 80:"HTTP", 443:"HTTPS"}
            encontrados = 0
            
            for p, srv in servicios.items():
                estado, desc = scan_puerto_avanzado(ip, p)
                if estado == "ABIERTO":
                    reporte.append((f"[*] Puerto {p} ({srv}): {desc}\n", "SUCCESS"))
                    encontrados += 1
                elif estado == "FILTRADO":
                    reporte.append((f"[!] Puerto {p} ({srv}): {desc}\n", "ALERTA"))

            if encontrados == 0:
                reporte.append(("\n[!] ANÁLISIS DE RESULTADOS:\n", "ALERTA"))
                if ip.endswith(".1") or ip.endswith(".2"):
                    reporte.append(("Tipo: Infraestructura Virtual (Gateway).\nNota: Este nodo descarta paquetes.\n", "INFO"))
                elif ip.endswith(".3"):
                    reporte.append(("Tipo: Servidor DNS Virtual.\n", "INFO"))
                elif ip.endswith(".15"):
                    reporte.append(("Tipo: Host Local (Tu VM).\n", "INFO"))
                else:
                    reporte.append(("Tipo: Nodo Activo Desconocido.\n", "INFO"))

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
    # --- ARREGLO PARA WINDOWS (MULTIPLE WINDOWS BUG FIX) ---
    multiprocessing.freeze_support() # <--- CRUCIAL PARA EL ARCHIVO .EXE
    
    root = tk.Tk()
    app = ScannerChileV49(root)
    root.mainloop()