import socket

def test_socket_connection():
    """Prueba básica para verificar que el sistema puede abrir sockets."""
    try:
        # Intenta conectar al DNS de Google para validar salida a red
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        result = test_sock.connect_ex(('8.8.8.8', 53))
        test_sock.close()
        
        if result == 0:
            print("[TEST PASSED]: Conectividad de red básica OK.")
        else:
            print("[TEST FAILED]: Error de conexión de socket.")
    except Exception as e:
        print(f"[ERROR]: {e}")

if __name__ == "__main__":
    test_socket_connection()
