# Escáner de Red - Python (Estilo Nmap)
[cite_start]Proyecto desarrollado para la asignatura DESVAC de Ingeniería en Telecomunicaciones, INACAP La Serena[cite: 1, 87].

## Integrantes
- [cite_start]**Jose Tapia**: Líder de Proyecto (Coordinación) [cite: 11, 12]
- [cite_start]**Martín [Apellido]**: Desarrollador Principal (Código) [cite: 11, 13]
- [cite_start]**Pedro Roga Carvajal**: Documentador (README y soporte técnico) [cite: 11, 14]

## Funcionalidades del Script
1. [cite_start]**Ping Sweep**: Identificación de hosts activos en una subred mediante ICMP[cite: 25].
2. [cite_start]**Escaneo de Puertos**: Verificación de puertos TCP abiertos en un host específico[cite: 26].
3. [cite_start]**Banner Grabbing**: Detección de servicios (ej. SSH, HTTP) leyendo el mensaje inicial del servidor[cite: 55].
4. [cite_start]**Interfaz de Línea de Comandos**: Uso de `argparse` para definir objetivos y opciones[cite: 53].

## Uso del Script
Para ejecutar el escaneo, usa el siguiente comando en la terminal:
[cite_start]`python scanner.py -t 192.168.1.0/24` [cite: 37, 51]

## Investigación Técnica
### 1. Uso de .gitignore
Se configuró un archivo `.gitignore` para evitar que Git suba archivos innecesarios como:
- Carpeta `__pycache__/` (archivos temporales de Python).
- Carpeta `dist/` y `build/` (archivos pesados de la compilación).
[cite_start]Esto mantiene el repositorio limpio y profesional[cite: 16, 74].

### 2. Cómo crear el ejecutable (.exe) para Windows
Para que el script funcione en cualquier PC sin instalar Python, investigamos el uso de **PyInstaller**:
1. [cite_start]Instalar con: `pip install pyinstaller` 
2. [cite_start]Compilar con: `pyinstaller --onefile scanner.py` 
3. [cite_start]El archivo final queda en la carpeta `dist/`.
