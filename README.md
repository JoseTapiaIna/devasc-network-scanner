# Escáner de Red en Python (Estilo Nmap)



Proyecto desarrollado para la asignatura **DEVASC** de Ingeniería en Telecomunicaciones, INACAP La Serena. El objetivo es proporcionar una herramienta capaz de auditar redes locales mediante el descubrimiento de hosts y servicios.



##  Integrantes

* **José Tapia**: Líder de Proyecto (Coordinación y Repositorio)

* **Martín [Apellido]**: Desarrollador Principal (Lógica de Red en Python)

* **Pedro Roga Carvajal**: Documentador (README y Soporte Técnico)



##  Funcionalidades

El script implementa las siguientes capacidades técnicas:

1. **Ping Sweep:** Identificación de hosts activos en una subred mediante paquetes ICMP.

2. **Escaneo de Puertos:** Verificación de puertos TCP abiertos en un host específico.

3. **Banner Grabbing:** Detección de servicios (ej. SSH, HTTP) leyendo el mensaje inicial del servidor.

4. **Interfaz de Línea de Comandos:** Uso de la librería `argparse` para definir objetivos y opciones.



##  Uso del Script

Para ejecutar el escaneo, utiliza el siguiente comando en la terminal:

```bash

python3 scanner.py -t 10.0.2
