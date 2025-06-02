# UnityDex

<p align="center">
  <img src="logo.svg" alt="UnityDex Logo" width="200" height="200">
</p>

UnityDex es una herramienta multifuncional para análisis de seguridad en redes, diseñada para entornos de prueba controlados y uso especializado en Kali Linux, Windows y otras distribuciones. Combina múltiples funcionalidades de seguridad en una interfaz unificada para facilitar tareas de análisis de seguridad, pentesting y hacking ético.

## Características

- **Escaneo de red**: Detección de hosts, servicios y vulnerabilidades
- **Captura de paquetes**: Monitoreo y análisis de tráfico de red
- **Análisis de vulnerabilidades web**: Identificación de fallos de seguridad en aplicaciones web
- **Ataques de diccionario**: Pruebas de fuerza bruta contra servicios comunes
- **Escaneo de redes inalámbricas**: Detección y análisis de redes WiFi
- **Ataques Man-in-the-Middle**: Interceptación y análisis de tráfico entre hosts
- **Análisis SSL/TLS**: Evaluación de implementaciones de cifrado
- **Escaneo de puertos avanzado**: Detección detallada de servicios y versiones
- **Análisis de seguridad IoT**: Identificación y evaluación de dispositivos IoT vulnerables
- **Análisis avanzado de malware**: Detección y clasificación de software malicioso
- **Hacking ético avanzado**: Inspección HTTPS, detección de inyección de scripts, API fuzzing, detección de secuestro de sesión
- **Seguridad de contenedores y nube**: Análisis de contenedores Docker/Kubernetes y configuraciones en la nube
- **Pruebas de seguridad IoT**: Análisis de firmware, pruebas de credenciales por defecto, escaneo MQTT/CoAP
- **Pruebas de infraestructura**: VLAN hopping, visualización de vectores de ataque
- **Informes de cumplimiento**: Generación de informes según estándares OWASP, NIST o ISO27001
- **Generación de informes**: Documentación de resultados en formato legible con recomendaciones automáticas

## Requisitos

- Kali Linux o distribución similar (Parrot OS, BlackArch)
- Python 3.x
- Privilegios de administrador (root)
- Dependencias: nmap, tcpdump, wireshark, tshark, aircrack-ng, yara, libpcap-dev, libfuzzy-dev
- Módulos Python: requests, scapy, paramiko, python-nmap, pyOpenSSL, colorama, pefile, yara-python, ssdeep

## Instalación

### En Kali Linux (Recomendado)

Para Kali Linux, se proporciona un script de instalación automatizado:

```bash
chmod +x install_kali.sh
sudo ./install_kali.sh
```

Este script instalará todas las dependencias necesarias del sistema y los módulos Python requeridos. Para más detalles, consulta [README_KALI.md](README_KALI.md).

### Instalación Manual

1. Clonar el repositorio o descargar los archivos de UnityDex
2. Instalar las dependencias requeridas:
   ```bash
   pip install -r requirements.txt
   ```
3. En sistemas Linux, dar permisos de ejecución:
   ```bash
   chmod +x unitydex.py
   ```
4. Ejecutar la herramienta (como administrador en Windows o root en Linux):
   ```bash
   # En Linux
   sudo ./unitydex.py
   
   # En Windows (PowerShell como administrador)
   python unitydex.py
   ```

## Uso

UnityDex ofrece dos modos de operación principales:

### Modo Interactivo (Recomendado)

El modo interactivo proporciona una interfaz de línea de comandos con autocompletado, historial y ayuda contextual:

```bash
# En Linux
sudo ./unitydex.py -i

# En Windows (PowerShell como administrador)
python unitydex.py -i
```

Características del modo interactivo:
- **Autocompletado**: Presiona TAB para completar comandos
- **Historial**: Usa el comando `history` para ver comandos anteriores
- **Ayuda integrada**: Escribe `help` para ver todos los comandos disponibles
- **Interfaz de red**: Usa `interfaces` para ver las interfaces de red disponibles
- **Limpieza de pantalla**: Usa `clear` para limpiar la terminal

### Modo Línea de Comandos

UnityDex también puede ejecutarse directamente desde la línea de comandos para tareas específicas. Opciones generales disponibles para todos los modos:

```bash
# Mostrar versión
sudo ./unitydex.py -v

# Omitir verificación de dependencias
sudo ./unitydex.py --no-check [comandos]

# Forzar ejecución incluso si faltan dependencias
sudo ./unitydex.py --force [comandos]

# Detectar interfaz automáticamente
sudo ./unitydex.py --auto-interface [comandos]
```

### Escaneo de red

```bash
sudo ./unitydex.py scan -t 192.168.1.0/24 -m quick
```

Opciones:
- `-t, --target`: Objetivo (IP, rango o dominio)
- `-m, --method`: Método de escaneo (quick, full, vuln)

### Captura de paquetes

```bash
sudo ./unitydex.py capture -i eth0 -d 120 -o captura.pcap -f "port 80"
```

Opciones:
- `-i, --interface`: Interfaz de red
- `-d, --duration`: Duración en segundos (predeterminado: 60)
- `-o, --output`: Archivo de salida
- `-f, --filter`: Expresión de filtro BPF

### Análisis de vulnerabilidades web

```bash
sudo ./unitydex.py web -u http://ejemplo.com
```

Opciones:
- `-u, --url`: URL objetivo

### Ataque de diccionario

```bash
sudo ./unitydex.py dict -t 192.168.1.10 -s ssh -u admin -w /usr/share/wordlists/rockyou.txt
```

Opciones:
- `-t, --target`: Objetivo (IP o dominio)
- `-s, --service`: Servicio objetivo (ssh, ftp, smb)
- `-u, --username`: Nombre de usuario
- `-w, --wordlist`: Archivo de diccionario

### Escaneo de redes inalámbricas

```bash
sudo ./unitydex.py wireless -i wlan0
```

Opciones:
- `-i, --interface`: Interfaz inalámbrica
- `-t, --time`: Tiempo de escaneo en segundos

### Ataque Man-in-the-Middle

```bash
sudo ./unitydex.py mitm -i eth0 -t 192.168.1.10 -g 192.168.1.1
```

Opciones:
- `-i, --interface`: Interfaz de red
- `-t, --target`: IP objetivo
- `-g, --gateway`: IP del gateway
- `-a, --attack`: Tipo de ataque (arpspoof, ettercap, bettercap)
- `--ssl-strip`: Habilitar SSL Strip
- `--dns-spoof`: Habilitar DNS Spoofing
- `--pcap`: Habilitar captura de paquetes
- `--https-inspection`: Habilitar inspección de tráfico HTTPS
- `--script-injection`: Habilitar detección de inyección de scripts
- `--api-fuzzing`: Habilitar fuzzing de APIs
- `--session-hijacking`: Habilitar detección de secuestro de sesión
- `--mqtt-coap`: Habilitar escaneo de dispositivos MQTT/CoAP
- `--default-creds`: Habilitar prueba de credenciales por defecto
- `--firmware-analysis`: Habilitar análisis de firmware
- `--container-scan`: Habilitar escaneo de seguridad de contenedores
- `--cloud-scan`: Habilitar escaneo de configuraciones erróneas en la nube
- `--vlan-hopping`: Habilitar prueba de VLAN hopping
- `--compliance`: Tipo de informe de cumplimiento (owasp, nist, iso27001)
- `--attack-vector`: Habilitar visualización de vectores de ataque
- `--auto-recommendations`: Habilitar recomendaciones automáticas

### Análisis SSL/TLS

```bash
sudo ./unitydex.py ssl -i eth0 -t 192.168.1.10
```

Opciones:
- `-i, --interface`: Interfaz de red
- `-t, --target`: IP objetivo
- `-g, --gateway`: IP del gateway
- `-a, --attack`: Herramienta para MITM (ettercap, bettercap, arpspoof)

### Escaneo de puertos avanzado

```bash
sudo ./unitydex.py port -t 192.168.1.10 -p 1-1000 --timing 4
```

Opciones:
- `-t, --target`: Objetivo (IP o dominio)
- `-p, --ports`: Puertos a escanear (ej: 22,80,443 o 1-1000)
- `--timing`: Velocidad de escaneo (0-5)
- `--scan-type`: Tipo de escaneo (tcp, udp, both)
- `--service`: Habilitar detección de servicios
- `--os`: Habilitar detección de sistema operativo

### Generación de informes

```bash
sudo ./unitydex.py report -o informe.html
```

Opciones:
- `-o, --output`: Archivo de salida (HTML o JSON)
- `--system`: Incluir información del sistema
- `--network`: Incluir información de red
- `--scans`: Incluir resultados de escaneos
- `--vulns`: Incluir análisis de vulnerabilidades

## Ejemplos de uso

### Modo interactivo (recomendado)

```bash
# Iniciar el modo interactivo
sudo ./unitydex.py -i

# En Windows
python unitydex.py -i
```

### Escaneo rápido de una red local

```bash
sudo ./unitydex.py scan -t 192.168.1.0/24 -m quick
```

### Captura de tráfico HTTP durante 5 minutos

```bash
sudo ./unitydex.py capture -i eth0 -d 300 -f "port 80 or port 443"
```

### Análisis de vulnerabilidades en un servidor web

```bash
sudo ./unitydex.py web -u https://objetivo.com
```

### Ataque de diccionario a un servidor SSH

```bash
sudo ./unitydex.py dict -t servidor.com -s ssh -u root -w /usr/share/wordlists/rockyou.txt
```

### Análisis avanzado de malware

```bash
# En Linux
sudo ./unitydex.py malware -f archivo_sospechoso.exe --virustotal --format html --output informe_malware.html

# En Windows
python unitydex.py malware -f archivo_sospechoso.exe --virustotal --format json --output informe_malware.json
```

Opciones:
- `-f, --file`: Archivo a analizar
- `--virustotal`: Consultar VirusTotal (requiere API key configurada)
- `--format`: Formato del informe (text, json, html)
- `--output`: Archivo de salida para el informe

### Análisis de seguridad IoT

```bash
# En Linux
sudo ./unitydex.py iot -n 192.168.1.0/24 --scan-type full --protocols all

# En Windows
python unitydex.py iot -n 192.168.1.0/24 --scan-type quick --protocols mqtt,coap
```

Opciones:
- `-n, --network`: Red a escanear
- `--scan-type`: Tipo de escaneo (quick, full, vuln)
- `--protocols`: Protocolos a analizar (all, mqtt, coap, zigbee, zwave)
- `--output`: Archivo de salida para el informe

### Ataque MITM con funcionalidades avanzadas de hacking ético

```bash
# En Linux
sudo ./unitydex.py mitm -i eth0 -t 192.168.1.10 -g 192.168.1.1 --https-inspection --script-injection --session-hijacking --container-scan --cloud-scan --compliance owasp --attack-vector --auto-recommendations

# En Windows
python unitydex.py mitm -i eth0 -t 192.168.1.10 -g 192.168.1.1 --https-inspection --api-fuzzing --mqtt-coap --default-creds --firmware-analysis --vlan-hopping --compliance nist --auto-recommendations
```

Este ejemplo muestra cómo utilizar las nuevas funcionalidades de hacking ético en un ataque MITM, incluyendo inspección HTTPS, detección de inyecciones de scripts, análisis de contenedores, generación de informes de cumplimiento y más.

## Solución de Problemas

### Dependencias Faltantes

Si encuentras errores relacionados con dependencias faltantes:

1. En Kali Linux, ejecuta nuevamente el script de instalación:
   ```bash
   sudo ./install_kali.sh
   ```

2. Para forzar la ejecución a pesar de dependencias faltantes:
   ```bash
   sudo ./unitydex.py --force [comandos]
   ```

3. Para problemas con módulos específicos:
   ```bash
   # Para problemas con pypcap
   sudo apt-get install python3-dev libpcap-dev
   pip3 install pypcap

   # Para problemas con yara-python
   sudo apt-get install yara python3-yara
   pip3 install yara-python

   # Para problemas con ssdeep
   sudo apt-get install libfuzzy-dev
   pip3 install ssdeep
   ```

Para más detalles sobre solución de problemas en Kali Linux, consulta [README_KALI.md](README_KALI.md).

## Advertencia

Esta herramienta está diseñada exclusivamente para fines educativos y pruebas de seguridad autorizadas. El uso indebido de esta herramienta puede constituir un delito. El usuario es el único responsable de cualquier uso ilegal o no ético de esta herramienta.

## Contribuciones

Las contribuciones son bienvenidas. Si desea contribuir, por favor:

1. Haga un fork del repositorio
2. Cree una rama para su característica (`git checkout -b feature/nueva-caracteristica`)
3. Haga commit de sus cambios (`git commit -am 'Añadir nueva característica'`)
4. Haga push a la rama (`git push origin feature/nueva-caracteristica`)
5. Cree un nuevo Pull Request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - vea el archivo LICENSE para más detalles.