import socket
import subprocess

def ping(host):
    # Envia un paquete ICMP (ping) al host. Devuelve True si responde.
    comando = ['ping', '-c', '1', '-W', '1', host]
    respuesta = subprocess.call(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return respuesta == 0

def ping_sweep(network):
    print(f"\n[*] Iniciando Ping Sweep en la subred: {network}.0/24")
    hosts_activos = []
    # Escanea desde la IP 1 hasta la 20 para hacer las pruebas rápido
    for i in range(1, 21):
        ip = f"{network}.{i}"
        if ping(ip):
            print(f"[+] Host activo encontrado: {ip}")
            hosts_activos.append(ip)
    return hosts_activos

def scan_port(host, port):
    # Intenta conectar a un puerto TCP específico
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    resultado = s.connect_ex((host, port))
    s.close()
    return resultado == 0

def main():
    print("-" * 60)
    print("Escáner de Red - Ingenieros en Telecomunicaciones INACAP")
    print("-" * 60)
    
    # Red base (ajusta si la de tu maquina virtual es distinta)
    red_base = "192.168.1" 
    
    activos = ping_sweep(red_base)
    
    puertos_comunes = [21, 22, 80, 443]
    
    for host in activos:
        print(f"\n[*] Escaneando puertos en {host}...")
        for puerto in puertos_comunes:
            if scan_port(host, puerto):
                print(f"  [>] Puerto {puerto} ABIERTO")

if __name__ == "__main__":
    main()
