#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROYECTO: CyberScanner v4.9.9 - Edición Auditoría Técnica
DESCRIPCIÓN: Escáner de red profesional optimizado para Windows (.exe)
             con diagnóstico de capas 3 y 4.
"""

import socket
import subprocess
import threading
import platform
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
from datetime import datetime, timedelta, timezone
import multiprocessing

# --- IDENTIDAD VISUAL ---
COLOR_BG = "#0A0F1E"
COLOR_CARD = "#16213E"
COLOR_ACCENT = "#00D2FF"
COLOR_TEXT = "#E1E8EB"
COLOR_SUCCESS = "#00FFC2"
COLOR_ERROR = "#FF4B2B"
COLOR_WARN = "#FFD700"

def get_chile_time():
    """Hora local Chile (UTC-4) para reportes oficiales."""
    tz_chile = timezone(timedelta(hours=-4))
    return datetime.now(tz_chile).strftime("%Y-%m-%d %H:%M:%S")

def ping_analisis(host):
    """Ping silencioso optimizado para no congelar el sistema en Windows."""
    sistema = platform.system().lower()
    startupinfo = None
    if sistema == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        comando = ['ping', '-n', '1', '-w', '600', host]
    else:
        comando = ['ping', '-c', '1', '-W', '1', host]
        
    try:
        return subprocess.call(comando, startupinfo=startupinfo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def scan_puerto_detallado(host, port):
    """
    Analiza el estado del puerto y genera un diagnóstico técnico.
    Distingue entre Abierto, Cerrado y Filtrado (Firewall).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        start_t = datetime.now()
        result = s.connect_ex((host, port))
        end_t = datetime.now()
        latencia = (end_t - start_t).total_seconds() * 1000

        if result == 0:
            # Intento de Banner Grabbing para identificar el servicio
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(512).decode().strip()[:40]
                info = f"ABIERTO | Resp: {banner}" if banner else "ABIERTO | Servicio Activo"
            except:
                info = "ABIERTO | Sin banner disponible"
            return "SUCCESS", f"{info} ({latencia:.1f}ms)"
        
        elif result in [11, 35, 110, 10060]: # Códigos de DROP/Timeout
            return "ALERTA", "FILTRADO | [!] Paquete descartado por Firewall (DROP)"
        
        else: # El host responde activamente que el puerto está cerrado
            return "INFO", "CERRADO | El host rechazó la conexión (No hay servicio)"
            
    except Exception as e:
        return "ERROR", f"ERROR | Fallo técnico: {str(e)}"
    finally:
        s.close()

class ScannerChileV49:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberScanner v4.9.9 - Auditoría Power Rangers Telecom")
        self.root.geometry("1100x800")
        self.root.configure(bg=COLOR_BG)
        
        self.host_database = {}
        self.db_lock = threading.Lock()
        # SEMÁFORO: Controla que el PC no se trabe (Máximo 40 hilos en paralelo)
        self.semaphore = threading.Semaphore(40)

        # Interfaz Gráfica
        header = tk.Frame(self.root, bg=COLOR_CARD, pady=15)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="RANGO DE RED:", bg=COLOR_CARD, fg=COLOR_ACCENT, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=15)
        self.entry_net = tk.Entry(header, width=15, font=("Consolas", 12), bg=COLOR_BG, fg=COLOR_TEXT, insertbackground="white")
        self.entry_net.insert(0, "192.168.0") # <--- Configurado para tu red WiFi actual
        self.entry_net.pack(side=tk.LEFT, padx=5)
        
        self.btn_run = tk.Button(header, text="INICIAR AUDITORÍA", bg=COLOR_ACCENT, fg=COLOR_BG, font=("Arial", 10, "bold"), 
                                 padx=20, command=self.iniciar, relief=tk.FLAT)
        self.btn_run.pack(side=tk.LEFT, padx=15)
        
        tk.Button(header, text="💾 GUARDAR .TXT", bg=COLOR_SUCCESS, font=("Arial", 9, "bold"), command=self.guardar).pack(side=tk.RIGHT, padx=15)

        # Paneles Divididos
        pw = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=COLOR_BG, bd=0, sashwidth=4)
        pw.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Lista de IPs encontradas
        self.listbox = tk.Listbox(pw, bg=COLOR_CARD, fg=COLOR_SUCCESS, font=("Consolas", 11), bd=0, highlightthickness=1, highlightcolor=COLOR_ACCENT)
        self.listbox.bind("<<ListboxSelect>>", self.ver_detalle)
        pw.add(self.listbox, width=300)

        # Consola de detalles técnicos
        self.txt_audit = scrolledtext.ScrolledText(pw, bg=COLOR_CARD, fg=COLOR_TEXT, font=("Consolas", 10), bd=0, padx=10, pady=10)
        self.txt_audit.tag_config("ALERTA", foreground=COLOR_ERROR, font=("Consolas", 10, "bold"))
        self.txt_audit.tag_config("INFO", foreground=COLOR_WARN)
        self.txt_audit.tag_config("SUCCESS", foreground=COLOR_SUCCESS, font=("Consolas", 10, "bold"))
        self.txt_audit.tag_config("HEADER", foreground=COLOR_ACCENT, font=("Consolas", 11, "bold"))
        pw.add(self.txt_audit)

    def iniciar(self):
        net = self.entry_net.get()
        self.listbox.delete(0, tk.END)
        self.host_database.clear()
        self.txt_audit.delete(1.0, tk.END)
        self.btn_run.config(state=tk.DISABLED, text="Analizando Red...")
        threading.Thread(target=self.hilo_maestro, args=(net,), daemon=True).start()

    def hilo_maestro(self, net):
        threads = []
        for i in range(1, 255):
            ip = f"{net}.{i}"
            t = threading.Thread(target=self.worker_limitado, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
        
        for t in threads: t.join()
        self.root.after(0, lambda: self.btn_run.config(state=tk.NORMAL, text="INICIAR AUDITORÍA"))
        self.root.after(0, lambda: messagebox.showinfo("Auditoría Finalizada", f"Escaneo en {net}.0/24 completo."))

    def worker_limitado(self, ip):
        with self.semaphore:
            self.auditar_host(ip)

    def auditar_host(self, ip):
        """Genera un análisis técnico exhaustivo si el host responde al ping."""
        if ping_analisis(ip):
            reporte = [
                (f"=== REPORTE DE AUDITORÍA: {ip} ===\n", "HEADER"),
                (f"Detección: {get_chile_time()}\n", "INFO"),
                (f"Capa 3: Host activo vía ICMP Echo Request.\n", "SUCCESS"),
                ("-" * 60 + "\n", "INFO")
            ]
            
            # Puertos críticos para auditoría de infraestructura y telecomunicaciones
            puertos = {21:"FTP", 22:"SSH", 23:"Telnet", 53:"DNS", 80:"HTTP", 443:"HTTPS", 3389:"RDP", 8080:"HTTP-ALT"}
            encontrados = 0
            
            for p, srv in puertos.items():
                tag, detalle = scan_puerto_detallado(ip, p)
                reporte.append((f"[*] Puerto {p:4} ({srv:8}): {detalle}\n", tag))
                if "ABIERTO" in detalle: encontrados += 1

            # --- DIAGNÓSTICO PROFESIONAL ---
            reporte.append(("\n--- DIAGNÓSTICO DE SEGURIDAD ---\n", "HEADER"))
            if encontrados > 0:
                reporte.append((f"ESTADO: Nodo Crítico Detectado ({encontrados} servicios).\n", "SUCCESS"))
                reporte.append(("TIPO: Probable Servidor o Equipo de Infraestructura.\n", "INFO"))
            else:
                reporte.append(("ESTADO: Nodo Silencioso / Blindado.\n", "ALERTA"))
                reporte.append(("TIPO: Dispositivo final (PC/Smartphone) con Firewall activo.\n", "INFO"))
                reporte.append(("NOTA: El host oculta su presencia a escaneos TCP.\n", "INFO"))

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
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"CYBERSCANNER AUDIT REPORT - CHILE\nGENEREADO: {get_chile_time()}\n")
                    f.write("="*50 + "\n\n")
                    for ip in sorted(self.host_database.keys()):
                        for texto, _ in self.host_database[ip]: f.write(texto)
                        f.write("\n" + "="*50 + "\n")
                messagebox.showinfo("Éxito", "Reporte guardado para entrega técnica.")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el archivo: {e}")

if __name__ == "__main__":
    multiprocessing.freeze_support() # Previene el error de múltiples ventanas en Windows
    root = tk.Tk()
    app = ScannerChileV49(root)
    root.mainloop()