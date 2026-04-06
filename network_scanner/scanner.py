import socket
import subprocess
import argparse

def ping(host):
    comando = ['ping', '-c', '1', '-W', '1', host]
    respuesta = subprocess.call(comando, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return respuesta == 0

def ping_sweep(network):
    print(f"\n[*] Iniciando Ping Sweep en la subred: {network}.0/24")
    hosts_activos = []
    for i in range(1, 21):
        ip = f"{network}.{i}"
        if ping(ip):
            print(f"[+] Host activo encontrado: {ip}")
            hosts_activos.append(ip)
    return hosts_activos

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    resultado = s.connect_ex((host, port))

    banner = ""
    if resultado == 0:
        # Banner Grabbing: intenta leer la respuesta del servicio
        try:
            if port == 80:
                s.send(b"GET / HTTP/1.1\r\n\r\n")
            banner = s.recv(1024).decode().strip()
        except:
            banner = "Servicio no devolvió banner"
    s.close()
    return resultado == 0, banner

def main():
    parser = argparse.ArgumentParser(description="Escáner de Red - INACAP Telecomunicaciones")
    parser.add_argument("-t", "--target", help="Subred a escanear (Ej: 192.168.1)", required=True)
    args = parser.parse_args()

    print("-" * 60)
    print("Escáner de Red - Ingenieros en Telecomunicaciones INACAP")
    print("-" * 60)

    activos = ping_sweep(args.target)
    puertos_comunes = [21, 22, 80, 443]

    for host in activos:
        print(f"\n[*] Escaneando puertos en {host}...")
        for puerto in puertos_comunes:
            abierto, banner = scan_port(host, puerto)
            if abierto:
                info_banner = f" | Banner: {banner[:30]}..." if banner else ""
                print(f"  [>] Puerto {puerto} ABIERTO{info_banner}")

if __name__ == "__main__":
    main()
