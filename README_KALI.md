# UnityDex para Kali Linux

Este documento proporciona instrucciones específicas para instalar y ejecutar UnityDex en Kali Linux.

## Instalación

UnityDex ha sido optimizado para funcionar en Kali Linux, que incluye muchas de las herramientas necesarias preinstaladas. Para asegurar que todas las dependencias estén correctamente instaladas, sigue estos pasos:

1. Clona el repositorio o descarga los archivos de UnityDex:

```bash
git clone https://github.com/tu-usuario/UnityDex.git
cd UnityDex
```

2. Ejecuta el script de instalación para Kali Linux:

```bash
chmod +x install_kali.sh
sudo ./install_kali.sh
```

Este script instalará todas las dependencias necesarias, incluyendo:

- Herramientas del sistema: nmap, tcpdump, wireshark, tshark, aircrack-ng, etc.
- Módulos de Python: requests, scapy, paramiko, python-nmap, etc.

## Ejecución

Una vez instaladas todas las dependencias, puedes ejecutar UnityDex de varias formas:

### Modo Interactivo

El modo interactivo proporciona una interfaz de menús para acceder a todas las funcionalidades:

```bash
sudo ./unitydex.py -i
```

### Modo Línea de Comandos

Puedes ejecutar funciones específicas directamente desde la línea de comandos:

```bash
# Escaneo rápido de red
sudo ./unitydex.py scan -t 192.168.1.0/24 --quick

# Análisis de vulnerabilidades web
sudo ./unitydex.py web -t http://ejemplo.com --full

# Captura de paquetes
sudo ./unitydex.py capture -i wlan0 -o captura.pcap

# Ataque MITM con funcionalidades avanzadas
sudo ./unitydex.py mitm -t 192.168.1.10 -g 192.168.1.1 --https-inspect --script-injection
```

## Solución de Problemas

Si encuentras problemas al ejecutar UnityDex en Kali Linux, verifica lo siguiente:

1. **Permisos de root**: La mayoría de las funcionalidades requieren privilegios de root. Asegúrate de ejecutar con `sudo`.

2. **Dependencias faltantes**: Si ves mensajes sobre dependencias faltantes, ejecuta nuevamente el script de instalación:

```bash
sudo ./install_kali.sh
```

3. **Problemas con módulos específicos**: Algunos módulos pueden requerir instalación manual:

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

4. **Forzar ejecución**: Si necesitas ejecutar la herramienta a pesar de dependencias faltantes:

```bash
sudo ./unitydex.py --force [comandos]
```

## Compatibilidad con Otras Distribuciones Linux

Aunque UnityDex está optimizado para Kali Linux, también puede funcionar en otras distribuciones basadas en Debian/Ubuntu. El script de instalación intentará adaptar las dependencias según sea necesario.

## Notas Adicionales

- Las herramientas de análisis de redes inalámbricas requieren una interfaz WiFi compatible con modo monitor.
- Algunas funcionalidades avanzadas pueden requerir herramientas adicionales específicas de Kali Linux.
- Para obtener los mejores resultados, mantén tu sistema Kali Linux actualizado con `sudo apt update && sudo apt upgrade`.

## Soporte

Si encuentras problemas específicos con la instalación o ejecución en Kali Linux, por favor reporta el problema incluyendo:

- Versión de Kali Linux
- Salida completa del error
- Resultado de `./unitydex.py --no-check --version`