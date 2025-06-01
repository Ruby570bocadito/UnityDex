#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de escaneo de redes para RedTrigger
'''

import os
import sys
import socket
import struct
import time
import random
import ipaddress
import subprocess
import logging
import threading
import queue
from datetime import datetime

# Importar módulo de utilidades
try:
    from utils import (
        is_valid_ip, is_valid_ip_range, is_valid_port, is_valid_port_range,
        get_network_interfaces, get_interface_ip, run_command, COLORS,
        ip_to_int, int_to_ip, is_port_open, scan_ports, resolve_domain
    )
except ImportError:
    print("Error: No se pudo importar el módulo de utilidades")
    sys.exit(1)

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('redtrigger.network_scanner')

# Clase para el escaneo de redes
class NetworkScanner:
    '''
    Clase para el escaneo de redes y hosts
    '''
    def __init__(self, config=None):
        '''
        Inicializa el escáner de redes
        '''
        self.config = config or {}
        self.results = {}
        self.stop_scan = False
        self.scan_thread = None
        self.scan_queue = queue.Queue()
        self.scan_results = queue.Queue()
        self.worker_threads = []
        self.num_workers = self.config.get('num_workers', 10)
        self.timeout = self.config.get('timeout', 1)
        self.verbose = self.config.get('verbose', False)
    
    def ping_sweep(self, target, count=1, timeout=1):
        '''
        Realiza un barrido de ping en un rango de direcciones IP
        '''
        if not is_valid_ip(target) and not is_valid_ip_range(target):
            logger.error(f"Objetivo no válido: {target}")
            return []
        
        try:
            # Convertir a objeto de red IP
            network = ipaddress.ip_network(target, strict=False)
            total_hosts = network.num_addresses
            
            if total_hosts > 1000 and not self.config.get('allow_large_scans', False):
                logger.warning(f"El rango de IP es demasiado grande ({total_hosts} hosts). Use allow_large_scans=True para permitir escaneos grandes.")
                return []
            
            logger.info(f"Iniciando barrido de ping en {target} ({total_hosts} hosts)")
            
            alive_hosts = []
            for ip in network.hosts():
                if self.stop_scan:
                    logger.info("Escaneo detenido por el usuario")
                    break
                
                ip_str = str(ip)
                if self.verbose:
                    logger.info(f"Haciendo ping a {ip_str}...")
                
                # Usar el comando ping del sistema
                if sys.platform.startswith('linux'):
                    cmd = ['ping', '-c', str(count), '-W', str(timeout), ip_str]
                else:  # Windows
                    cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip_str]
                
                try:
                    subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                    alive_hosts.append(ip_str)
                    logger.info(f"Host activo: {ip_str}")
                except subprocess.CalledProcessError:
                    if self.verbose:
                        logger.debug(f"Host inactivo: {ip_str}")
                except Exception as e:
                    logger.error(f"Error al hacer ping a {ip_str}: {str(e)}")
            
            return alive_hosts
        except Exception as e:
            logger.error(f"Error en barrido de ping: {str(e)}")
            return []
    
    def arp_scan(self, interface=None, target=None):
        '''
        Realiza un escaneo ARP en la red local
        '''
        if not interface:
            interfaces = get_network_interfaces()
            if not interfaces:
                logger.error("No se encontraron interfaces de red")
                return []
            interface = interfaces[0]
        
        logger.info(f"Iniciando escaneo ARP en la interfaz {interface}")
        
        try:
            # Usar arping si está disponible
            if os.path.exists('/usr/sbin/arp-scan'):
                cmd = ['sudo', 'arp-scan', '--interface', interface]
                if target:
                    cmd.append(target)
                else:
                    cmd.append('--localnet')
                
                output = run_command(cmd)
                if not output:
                    logger.error("Error al ejecutar arp-scan")
                    return []
                
                # Parsear la salida
                hosts = []
                for line in output.split('\n'):
                    if line and not line.startswith('Interface') and not line.startswith('Starting') and not line.startswith('Ending'):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            if is_valid_ip(ip):
                                hosts.append({'ip': ip, 'mac': mac})
                
                return hosts
            else:
                logger.warning("arp-scan no está instalado, usando método alternativo")
                # Método alternativo usando Python
                if target:
                    network = ipaddress.ip_network(target, strict=False)
                else:
                    # Obtener la red local
                    ip = get_interface_ip(interface)
                    if not ip:
                        logger.error(f"No se pudo obtener la IP de la interfaz {interface}")
                        return []
                    
                    # Asumir una máscara de red /24
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                
                hosts = []
                for ip in network.hosts():
                    if self.stop_scan:
                        logger.info("Escaneo detenido por el usuario")
                        break
                    
                    ip_str = str(ip)
                    if self.verbose:
                        logger.info(f"Escaneando {ip_str}...")
                    
                    # Usar el comando arping si está disponible
                    if os.path.exists('/usr/sbin/arping'):
                        cmd = ['sudo', 'arping', '-c', '1', '-I', interface, ip_str]
                        try:
                            output = run_command(cmd)
                            if output and 'bytes from' in output:
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', output)
                                if mac_match:
                                    mac = mac_match.group(0)
                                    hosts.append({'ip': ip_str, 'mac': mac})
                                    logger.info(f"Host encontrado: {ip_str} ({mac})")
                        except Exception as e:
                            logger.error(f"Error al ejecutar arping para {ip_str}: {str(e)}")
                    else:
                        # Método alternativo usando sockets
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.1)
                            result = sock.connect_ex((ip_str, 80))
                            sock.close()
                            if result == 0:
                                hosts.append({'ip': ip_str, 'mac': 'Unknown'})
                                logger.info(f"Host encontrado: {ip_str}")
                        except Exception as e:
                            if self.verbose:
                                logger.debug(f"Error al conectar con {ip_str}: {str(e)}")
                
                return hosts
        except Exception as e:
            logger.error(f"Error en escaneo ARP: {str(e)}")
            return []
    
    def port_scan_worker(self):
        '''
        Trabajador para el escaneo de puertos en paralelo
        '''
        while not self.stop_scan:
            try:
                # Obtener un elemento de la cola
                item = self.scan_queue.get(block=False)
                if item is None:
                    break
                
                host, port = item
                
                # Escanear el puerto
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = 'unknown'
                        
                        self.scan_results.put((host, port, service))
                        if self.verbose:
                            logger.info(f"Puerto abierto en {host}: {port}/{service}")
                    sock.close()
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"Error al escanear puerto {port} en {host}: {str(e)}")
                
                # Marcar la tarea como completada
                self.scan_queue.task_done()
            except queue.Empty:
                # No hay más elementos en la cola
                break
            except Exception as e:
                logger.error(f"Error en trabajador de escaneo: {str(e)}")
    
    def port_scan(self, target, ports=None, scan_type='tcp'):
        '''
        Realiza un escaneo de puertos en un host o rango de hosts
        '''
        if not is_valid_ip(target) and not is_valid_ip_range(target):
            # Intentar resolver el nombre de dominio
            ip = resolve_domain(target)
            if not ip:
                logger.error(f"No se pudo resolver el dominio: {target}")
                return {}
            target = ip
        
        # Determinar los puertos a escanear
        if not ports:
            if scan_type == 'tcp':
                # Puertos TCP comunes
                ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            elif scan_type == 'udp':
                # Puertos UDP comunes
                ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1434, 1900, 5353]
            else:
                logger.error(f"Tipo de escaneo no válido: {scan_type}")
                return {}
        elif isinstance(ports, str):
            # Convertir rango de puertos a lista
            if '-' in ports:
                start, end = ports.split('-')
                ports = list(range(int(start), int(end) + 1))
            elif ',' in ports:
                ports = [int(p) for p in ports.split(',')]
            else:
                ports = [int(ports)]
        
        # Verificar si el objetivo es un rango de IP
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        except:
            hosts = [target]
        
        total_hosts = len(hosts)
        total_ports = len(ports)
        total_scans = total_hosts * total_ports
        
        if total_scans > 10000 and not self.config.get('allow_large_scans', False):
            logger.warning(f"El escaneo es demasiado grande ({total_scans} combinaciones). Use allow_large_scans=True para permitir escaneos grandes.")
            return {}
        
        logger.info(f"Iniciando escaneo de puertos {scan_type.upper()} en {target} ({total_hosts} hosts, {total_ports} puertos)")
        
        # Inicializar resultados
        results = {}
        for host in hosts:
            results[host] = []
        
        # Reiniciar variables de control
        self.stop_scan = False
        self.scan_queue = queue.Queue()
        self.scan_results = queue.Queue()
        
        # Llenar la cola con las combinaciones de host y puerto
        for host in hosts:
            for port in ports:
                self.scan_queue.put((host, port))
        
        # Crear y iniciar los trabajadores
        self.worker_threads = []
        for _ in range(min(self.num_workers, total_scans)):
            thread = threading.Thread(target=self.port_scan_worker)
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
        
        # Esperar a que se complete el escaneo
        try:
            # Mostrar progreso
            start_time = time.time()
            while not self.stop_scan:
                # Procesar resultados disponibles
                while not self.scan_results.empty():
                    host, port, service = self.scan_results.get()
                    results[host].append({'port': port, 'service': service})
                
                # Verificar si se completó el escaneo
                if self.scan_queue.empty():
                    break
                
                # Mostrar progreso cada 2 segundos
                if self.verbose and time.time() - start_time > 2:
                    remaining = self.scan_queue.qsize()
                    progress = 100 - (remaining * 100 / total_scans)
                    logger.info(f"Progreso: {progress:.1f}% ({total_scans - remaining}/{total_scans})")
                    start_time = time.time()
                
                # Pequeña pausa para no consumir CPU
                time.sleep(0.1)
            
            # Procesar resultados finales
            while not self.scan_results.empty():
                host, port, service = self.scan_results.get()
                results[host].append({'port': port, 'service': service})
            
            # Eliminar hosts sin puertos abiertos
            results = {host: ports for host, ports in results.items() if ports}
            
            logger.info(f"Escaneo de puertos completado. Hosts con puertos abiertos: {len(results)}")
            return results
        except KeyboardInterrupt:
            logger.info("Escaneo interrumpido por el usuario")
            self.stop_scan = True
            return results
        except Exception as e:
            logger.error(f"Error en escaneo de puertos: {str(e)}")
            return results
        finally:
            # Detener los trabajadores
            self.stop_scan = True
            for thread in self.worker_threads:
                thread.join(0.5)
    
    def os_detection(self, target):
        '''
        Intenta detectar el sistema operativo de un host
        '''
        if not is_valid_ip(target):
            # Intentar resolver el nombre de dominio
            ip = resolve_domain(target)
            if not ip:
                logger.error(f"No se pudo resolver el dominio: {target}")
                return None
            target = ip
        
        logger.info(f"Iniciando detección de sistema operativo en {target}")
        
        # Intentar usar nmap para la detección de SO
        try:
            cmd = ['nmap', '-O', '--osscan-guess', target]
            output = run_command(cmd)
            if not output:
                logger.error("Error al ejecutar nmap")
                return None
            
            # Buscar la línea de detección de SO
            os_info = None
            for line in output.split('\n'):
                if 'OS:' in line or 'Running:' in line:
                    os_info = line.strip()
                    break
            
            return os_info
        except Exception as e:
            logger.error(f"Error en detección de SO: {str(e)}")
            return None
    
    def service_detection(self, target, ports):
        '''
        Detecta servicios en puertos abiertos
        '''
        if not is_valid_ip(target):
            # Intentar resolver el nombre de dominio
            ip = resolve_domain(target)
            if not ip:
                logger.error(f"No se pudo resolver el dominio: {target}")
                return {}
            target = ip
        
        # Convertir puertos a lista si es necesario
        if isinstance(ports, str):
            if '-' in ports:
                start, end = ports.split('-')
                ports = list(range(int(start), int(end) + 1))
            elif ',' in ports:
                ports = [int(p) for p in ports.split(',')]
            else:
                ports = [int(ports)]
        
        logger.info(f"Iniciando detección de servicios en {target} (puertos: {ports})")
        
        # Intentar usar nmap para la detección de servicios
        try:
            ports_str = ','.join(map(str, ports))
            cmd = ['nmap', '-sV', '-p', ports_str, target]
            output = run_command(cmd)
            if not output:
                logger.error("Error al ejecutar nmap")
                return {}
            
            # Parsear la salida
            services = {}
            port_line = False
            for line in output.split('\n'):
                if 'PORT' in line and 'STATE' in line and 'SERVICE' in line:
                    port_line = True
                    continue
                
                if port_line and line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0].split('/')
                        if len(port_info) >= 2:
                            port = int(port_info[0])
                            protocol = port_info[1]
                            state = parts[1]
                            service = parts[2]
                            version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                            
                            services[port] = {
                                'protocol': protocol,
                                'state': state,
                                'service': service,
                                'version': version
                            }
            
            return services
        except Exception as e:
            logger.error(f"Error en detección de servicios: {str(e)}")
            return {}
    
    def traceroute(self, target, max_hops=30, timeout=2):
        '''
        Realiza un traceroute a un host
        '''
        if not is_valid_ip(target):
            # Intentar resolver el nombre de dominio
            ip = resolve_domain(target)
            if not ip:
                logger.error(f"No se pudo resolver el dominio: {target}")
                return []
            target = ip
        
        logger.info(f"Iniciando traceroute a {target}")
        
        # Usar el comando traceroute/tracert del sistema
        try:
            if sys.platform.startswith('linux'):
                cmd = ['traceroute', '-n', '-w', str(timeout), '-m', str(max_hops), target]
            else:  # Windows
                cmd = ['tracert', '-d', '-w', str(timeout * 1000), '-h', str(max_hops), target]
            
            output = run_command(cmd)
            if not output:
                logger.error("Error al ejecutar traceroute")
                return []
            
            # Parsear la salida
            hops = []
            for line in output.split('\n'):
                if 'traceroute to' in line or 'Tracing route to' in line:
                    continue
                
                # Buscar líneas con números de salto
                hop_match = re.search(r'^\s*(\d+)\s+(.+)$', line)
                if hop_match:
                    hop_num = int(hop_match.group(1))
                    hop_info = hop_match.group(2).strip()
                    
                    # Extraer IPs
                    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hop_info)
                    
                    if ips:
                        hop = {
                            'hop': hop_num,
                            'ip': ips[0],
                            'rtt': []
                        }
                        
                        # Extraer tiempos de respuesta
                        rtts = re.findall(r'\b\d+(?:\.\d+)?\s*ms\b', hop_info)
                        for rtt in rtts:
                            hop['rtt'].append(float(rtt.replace('ms', '').strip()))
                        
                        hops.append(hop)
                    elif '*' in hop_info:
                        # Salto sin respuesta
                        hops.append({
                            'hop': hop_num,
                            'ip': '*',
                            'rtt': []
                        })
            
            return hops
        except Exception as e:
            logger.error(f"Error en traceroute: {str(e)}")
            return []
    
    def banner_grabbing(self, target, port):
        '''
        Intenta obtener el banner de un servicio
        '''
        if not is_valid_ip(target):
            # Intentar resolver el nombre de dominio
            ip = resolve_domain(target)
            if not ip:
                logger.error(f"No se pudo resolver el dominio: {target}")
                return None
            target = ip
        
        logger.info(f"Iniciando banner grabbing en {target}:{port}")
        
        # Intentar conectar y obtener el banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # Enviar una solicitud básica
            if port == 80 or port == 443:
                # HTTP/HTTPS
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 21:
                # FTP
                pass  # No es necesario enviar nada, el servidor FTP envía un banner automáticamente
            elif port == 22:
                # SSH
                pass  # No es necesario enviar nada, el servidor SSH envía un banner automáticamente
            elif port == 25 or port == 587:
                # SMTP
                sock.send(b"EHLO example.com\r\n")
            elif port == 110:
                # POP3
                pass  # No es necesario enviar nada, el servidor POP3 envía un banner automáticamente
            elif port == 143:
                # IMAP
                sock.send(b"A001 CAPABILITY\r\n")
            else:
                # Otros servicios
                sock.send(b"\r\n")
            
            # Recibir respuesta
            banner = sock.recv(1024)
            sock.close()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            logger.error(f"Error en banner grabbing: {str(e)}")
            return None
    
    def vulnerability_scan(self, target, ports=None):
        '''
        Realiza un escaneo básico de vulnerabilidades usando nmap
        '''
        if not is_valid_ip(target):
            # Intentar resolver el nombre de dominio
            ip = resolve_domain(target)
            if not ip:
                logger.error(f"No se pudo resolver el dominio: {target}")
                return []
            target = ip
        
        logger.info(f"Iniciando escaneo de vulnerabilidades en {target}")
        
        # Intentar usar nmap con scripts de vulnerabilidades
        try:
            cmd = ['nmap', '--script', 'vuln', target]
            if ports:
                if isinstance(ports, list):
                    ports_str = ','.join(map(str, ports))
                else:
                    ports_str = str(ports)
                cmd.extend(['-p', ports_str])
            
            output = run_command(cmd)
            if not output:
                logger.error("Error al ejecutar nmap")
                return []
            
            # Parsear la salida
            vulnerabilities = []
            vuln_section = False
            current_vuln = None
            
            for line in output.split('\n'):
                if '|' in line and '_VULNERABLE:' in line:
                    vuln_section = True
                    vuln_name = line.split('_VULNERABLE:')[0].split('|')[-1].strip()
                    current_vuln = {
                        'name': vuln_name,
                        'details': []
                    }
                    vulnerabilities.append(current_vuln)
                elif vuln_section and '|' in line and current_vuln:
                    detail = line.split('|')[-1].strip()
                    if detail:
                        current_vuln['details'].append(detail)
                elif not line.strip():
                    vuln_section = False
            
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error en escaneo de vulnerabilidades: {str(e)}")
            return []
    
    def network_sweep(self, target, scan_type='ping'):
        '''
        Realiza un barrido de red para encontrar hosts activos
        '''
        if not is_valid_ip_range(target):
            logger.error(f"Rango de IP no válido: {target}")
            return []
        
        logger.info(f"Iniciando barrido de red en {target} (tipo: {scan_type})")
        
        if scan_type == 'ping':
            return self.ping_sweep(target)
        elif scan_type == 'arp':
            # Obtener la interfaz adecuada
            interfaces = get_network_interfaces()
            if not interfaces:
                logger.error("No se encontraron interfaces de red")
                return []
            
            # Usar la primera interfaz por defecto
            interface = interfaces[0]
            return self.arp_scan(interface, target)
        elif scan_type == 'tcp':
            # Usar un puerto común para detectar hosts
            try:
                network = ipaddress.ip_network(target, strict=False)
                hosts = []
                
                for ip in network.hosts():
                    if self.stop_scan:
                        logger.info("Escaneo detenido por el usuario")
                        break
                    
                    ip_str = str(ip)
                    if self.verbose:
                        logger.info(f"Escaneando {ip_str}...")
                    
                    # Verificar si el host responde en algún puerto común
                    common_ports = [80, 443, 22, 445]
                    for port in common_ports:
                        if is_port_open(ip_str, port, timeout=0.5):
                            hosts.append(ip_str)
                            logger.info(f"Host activo: {ip_str} (puerto {port} abierto)")
                            break
                
                return hosts
            except Exception as e:
                logger.error(f"Error en barrido TCP: {str(e)}")
                return []
        else:
            logger.error(f"Tipo de barrido no válido: {scan_type}")
            return []
    
    def host_discovery(self, target, methods=None):
        '''
        Descubre hosts activos usando múltiples métodos
        '''
        if not methods:
            methods = ['ping', 'arp', 'tcp']
        
        logger.info(f"Iniciando descubrimiento de hosts en {target} (métodos: {methods})")
        
        all_hosts = set()
        
        for method in methods:
            if self.stop_scan:
                logger.info("Escaneo detenido por el usuario")
                break
            
            logger.info(f"Usando método de descubrimiento: {method}")
            
            if method == 'ping':
                hosts = self.ping_sweep(target)
            elif method == 'arp':
                # Obtener la interfaz adecuada
                interfaces = get_network_interfaces()
                if not interfaces:
                    logger.error("No se encontraron interfaces de red")
                    continue
                
                # Usar la primera interfaz por defecto
                interface = interfaces[0]
                arp_results = self.arp_scan(interface, target)
                hosts = [h['ip'] for h in arp_results]
            elif method == 'tcp':
                # Usar el método de barrido TCP
                hosts = self.network_sweep(target, scan_type='tcp')
            else:
                logger.warning(f"Método de descubrimiento desconocido: {method}")
                continue
            
            # Agregar hosts encontrados al conjunto
            all_hosts.update(hosts)
            logger.info(f"Hosts encontrados con método {method}: {len(hosts)}")
        
        logger.info(f"Total de hosts únicos encontrados: {len(all_hosts)}")
        return list(all_hosts)
    
    def scan(self, target, scan_type='full', ports=None):
        '''
        Realiza un escaneo completo de un host o red
        '''
        logger.info(f"Iniciando escaneo {scan_type} en {target}")
        
        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hosts': {}
        }
        
        try:
            # Determinar si el objetivo es un host o una red
            is_network = False
            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.num_addresses > 1:
                    is_network = True
            except:
                # No es una red, podría ser un host o dominio
                pass
            
            # Si es una red, primero descubrir hosts
            if is_network:
                logger.info(f"Descubriendo hosts en la red {target}")
                hosts = self.host_discovery(target)
                if not hosts:
                    logger.warning(f"No se encontraron hosts activos en {target}")
                    return results
                
                logger.info(f"Hosts activos encontrados: {len(hosts)}")
            else:
                # Es un solo host
                if not is_valid_ip(target):
                    # Intentar resolver el nombre de dominio
                    ip = resolve_domain(target)
                    if not ip:
                        logger.error(f"No se pudo resolver el dominio: {target}")
                        return results
                    target = ip
                
                hosts = [target]
            
            # Escanear cada host
            for host in hosts:
                if self.stop_scan:
                    logger.info("Escaneo detenido por el usuario")
                    break
                
                logger.info(f"Escaneando host: {host}")
                host_results = {
                    'ip': host,
                    'ports': [],
                    'os': None,
                    'services': {},
                    'vulnerabilities': []
                }
                
                # Escaneo de puertos
                if scan_type in ['full', 'ports', 'quick']:
                    if scan_type == 'quick':
                        # Escaneo rápido de puertos comunes
                        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
                        port_results = self.port_scan(host, common_ports)
                    else:
                        # Escaneo completo o específico
                        port_results = self.port_scan(host, ports)
                    
                    if host in port_results:
                        host_results['ports'] = port_results[host]
                
                # Detección de sistema operativo
                if scan_type in ['full', 'os']:
                    os_info = self.os_detection(host)
                    if os_info:
                        host_results['os'] = os_info
                
                # Detección de servicios
                if scan_type in ['full', 'services'] and host_results['ports']:
                    open_ports = [p['port'] for p in host_results['ports']]
                    services = self.service_detection(host, open_ports)
                    if services:
                        host_results['services'] = services
                
                # Escaneo de vulnerabilidades
                if scan_type in ['full', 'vuln'] and host_results['ports']:
                    open_ports = [p['port'] for p in host_results['ports']]
                    vulns = self.vulnerability_scan(host, open_ports)
                    if vulns:
                        host_results['vulnerabilities'] = vulns
                
                # Agregar resultados del host
                results['hosts'][host] = host_results
            
            return results
        except Exception as e:
            logger.error(f"Error en escaneo: {str(e)}")
            return results
    
    def stop(self):
        '''
        Detiene cualquier escaneo en curso
        '''
        logger.info("Deteniendo escaneo...")
        self.stop_scan = True
        
        # Esperar a que los hilos terminen
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(2.0)
        
        for thread in self.worker_threads:
            if thread.is_alive():
                thread.join(0.5)
        
        logger.info("Escaneo detenido")

# Función principal para pruebas
def main():
    print(f"{COLORS['HEADER']}Módulo de escaneo de redes para RedTrigger{COLORS['ENDC']}")
    
    scanner = NetworkScanner({
        'verbose': True,
        'timeout': 1,
        'num_workers': 50
    })
    
    # Ejemplo de uso
    target = input(f"{COLORS['BOLD']}Ingrese el objetivo (IP, rango o dominio): {COLORS['ENDC']}")
    scan_type = input(f"{COLORS['BOLD']}Tipo de escaneo (quick/full/ports/os/services/vuln): {COLORS['ENDC']}") or 'quick'
    
    results = scanner.scan(target, scan_type)
    
    # Mostrar resultados
    print(f"\n{COLORS['GREEN']}Resultados del escaneo:{COLORS['ENDC']}")
    print(f"Objetivo: {results['target']}")
    print(f"Tipo de escaneo: {results['scan_type']}")
    print(f"Timestamp: {results['timestamp']}")
    print(f"Hosts encontrados: {len(results['hosts'])}")
    
    for host, host_results in results['hosts'].items():
        print(f"\n{COLORS['BLUE']}Host: {host}{COLORS['ENDC']}")
        
        if host_results['os']:
            print(f"Sistema operativo: {host_results['os']}")
        
        if host_results['ports']:
            print(f"Puertos abiertos: {len(host_results['ports'])}")
            for port in host_results['ports']:
                print(f"  {port['port']}/{port['service']}")
        
        if host_results['services']:
            print("Servicios detectados:")
            for port, service in host_results['services'].items():
                print(f"  {port}/{service['protocol']} - {service['service']} {service['version']}")
        
        if host_results['vulnerabilities']:
            print(f"{COLORS['WARNING']}Vulnerabilidades detectadas: {len(host_results['vulnerabilities'])}{COLORS['ENDC']}")
            for vuln in host_results['vulnerabilities']:
                print(f"  {vuln['name']}")
                for detail in vuln['details']:
                    print(f"    - {detail}")

if __name__ == '__main__':
    main()