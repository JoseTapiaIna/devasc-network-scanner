# 🛡️ CyberScanner v4.9 - Escáner de Red (Estilo Nmap)

### Descripción del Proyecto
Proyecto desarrollado para la asignatura **DEVASC** de Ingeniería en Telecomunicaciones, **INACAP La Serena**. El objetivo es proporcionar una herramienta profesional capaz de auditar redes locales mediante el descubrimiento de hosts y servicios, con un enfoque en la fidelidad técnica y detección de Firewalls.

### Integrantes
* **José Tapia**: Líder de Proyecto (Coordinación y Repositorio)
* **Martín Cortes**: Desarrollador Principal (Lógica de Red en Python)
* **Pedro Roga Carvajal**: Documentador (README y Soporte Técnico)
* **Grupo**: Los Power Rangers

### Funcionalidades Técnicas
* **Ping Sweep**: Identificación de hosts activos en una subred mediante paquetes ICMP.
* **Escaneo de Puertos**: Verificación de puertos TCP críticos (22, 53, 80, 443).
* **Banner Grabbing**: Detección de servicios leyendo el mensaje inicial del servidor para identificar versiones.
* **Análisis de Capa 4**: Diferenciación entre puertos abiertos, cerrados y filtrados (DROP/Firewall).
* **Interfaz Gráfica (GUI)**: Panel intuitivo con reporte detallado y códigos de colores.

### Requisitos e Instalación
* **Python 3.8.2** o superior.
* Sistema operativo: Linux (optimizado para LabVM) o Windows.

**Ejecución en Linux:**
```bash
python3 scanner.py
