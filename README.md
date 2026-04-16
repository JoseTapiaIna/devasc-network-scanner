# CyberScanner v4.9.9 - Auditoría de Redes

## 📝 Descripción
CyberScanner es una herramienta de auditoría técnica desarrollada en Python, diseñada para la exploración y diagnóstico de seguridad en redes locales (LAN). El software permite identificar nodos activos y auditar la disponibilidad de servicios críticos, entregando un análisis detallado sobre la postura de seguridad de cada dispositivo encontrado.

---

## 🚀 Funciones Principales

El programa opera bajo una arquitectura de **Multi-threading** (multihilo) para garantizar velocidad sin comprometer la estabilidad del sistema:

* **Exploración de Capa 3 (Network):**
    * Detección de hosts activos mediante protocolo **ICMP (Ping)**.
    * Cálculo de presencia de nodos en tiempo real.
* **Auditoría de Capa 4 (Transporte):**
    * Escaneo de puertos TCP críticos (SSH, HTTP, HTTPS, Telnet, RDP, etc.).
    * Medición de **Latencia (ms)** por cada servicio contactado.
* **Diagnóstico de Seguridad Inteligente:**
    * **Detección de Firewall:** Identifica si un host está descartando paquetes (DROP/Filtrado).
    * **Banner Grabbing:** Intenta capturar la cabecera de respuesta de los servicios (ej. versiones de HTTP) para identificación de software.
    * **Clasificación Automática:** Clasifica el dispositivo como "Infraestructura/Servidor" o "Nodo Silencioso/Blindado" según su comportamiento.
* **Gestión de Reportes:**
    * Exportación de resultados a formato `.txt` con registro de fecha y hora local (Chile).

---

## 🛠️ Requisitos e Instalación

### Requisitos del Sistema
* **SO:** Windows 10/11 (Optimizado para arquitectura x64).
* **Lenguaje:** Python 3.10 o superior.

### Instrucciones para crear el Ejecutable (.exe)
Para asegurar que el programa funcione en cualquier PC sin necesidad de tener Python instalado:

1.  Instalar PyInstaller:
    ```bash
    pip install pyinstaller
    ```
2.  Generar el binario compatible:
    ```bash
    python -m PyInstaller --onefile --windowed "scanner_final.py"
    ```
*Nota: El código incluye `multiprocessing.freeze_support()` para evitar bucles de procesos en el kernel de Windows al ejecutarse como .exe.*

---

## 📖 Ejemplo de Uso
1.  Inicie el archivo `CyberScanner.exe`.
2.  En el campo **RANGO DE RED**, verifique su segmento (ej. `192.168.0`).
3.  Haga clic en **INICIAR AUDITORÍA**.
4.  Seleccione cualquier IP de la lista izquierda para desplegar el **Reporte Técnico** en el panel derecho.
5.  Use el botón **GUARDAR .TXT** para generar la evidencia de la auditoría.

---

## 👥 Integrantes	
* **Jose Tapia** - Estudiante de Ingeniería en Telecomunicaciones
* **Martin Cortes** - Estudiante de Ingeniería en Telecomunicaciones
* **Pedro Roga Carvajal** - Estudiante de Ingeniería en Telecomunicaciones
