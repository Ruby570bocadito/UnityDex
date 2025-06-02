#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de utilidades para RedTrigger
'''

import os
import sys
import json
import socket
import struct
import ipaddress
import subprocess
import re
import random
import string
import hashlib
import logging
from datetime import datetime

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('redtrigger')

# Colores para la terminal
COLORS = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'GREEN': '\033[92m',
    'WARNING': '\033[93m',
    'FAIL': '\033[91m',
    'ENDC': '\033[0m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m'
}

# Cargar configuración
def load_config(config_file='config.json'):
    '''
    Carga la configuración desde un archivo JSON
    '''
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        else:
            logger.warning(f"Archivo de configuración {config_file} no encontrado. Usando valores predeterminados.")
            return {}
    except Exception as e:
        logger.error(f"Error al cargar la configuración: {str(e)}")
        return {}

# Guardar configuración
def save_config(config, config_file='config.json'):
    '''
    Guarda la configuración en un archivo JSON
    '''
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info(f"Configuración guardada en {config_file}")
        return True
    except Exception as e:
        logger.error(f"Error al guardar la configuración: {str(e)}")
        return False

# Verificar si una IP es válida
def is_valid_ip(ip):
    '''
    Verifica si una cadena es una dirección IP válida
    '''
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Verificar si un rango de IP es válido
def is_valid_ip_range(ip_range):
    '''
    Verifica si una cadena es un rango de IP válido (CIDR)
    '''
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False

# Verificar si un puerto es válido
def is_valid_port(port):
    '''
    Verifica si un puerto es válido (1-65535)
    '''
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False

# Verificar si un rango de puertos es válido
def is_valid_port_range(port_range):
    '''
    Verifica si un rango de puertos es válido (ej: 80-443)
    '''
    try:
        if '-' in port_range:
            start, end = port_range.split('-')
            start = int(start)
            end = int(end)
            return 1 <= start <= end <= 65535
        elif ',' in port_range:
            ports = port_range.split(',')
            return all(is_valid_port(p) for p in ports)
        else:
            return is_valid_port(port_range)
    except:
        return False

# Verificar si una URL es válida
def is_valid_url(url):
    '''
    Verifica si una URL es válida
    '''
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http://, https://, ftp://, ftps://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # dominio
        r'localhost|' # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # IP
        r'(?::\d+)?' # puerto opcional
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Obtener interfaces de red disponibles
def get_network_interfaces():
    '''
    Obtiene una lista de interfaces de red disponibles
    '''
    try:
        if sys.platform.startswith('linux'):
            interfaces = []
            for iface in os.listdir('/sys/class/net/'):
                interfaces.append(iface)
            return interfaces
        else:
            # Para otros sistemas operativos, usar socket
            import netifaces
            return netifaces.interfaces()
    except Exception as e:
        logger.error(f"Error al obtener interfaces de red: {str(e)}")
        return []

# Obtener la dirección IP de una interfaz
def get_interface_ip(interface):
    '''
    Obtiene la dirección IP de una interfaz de red
    '''
    try:
        if sys.platform.startswith('linux'):
            output = subprocess.check_output(['ip', 'addr', 'show', interface]).decode('utf-8')
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
            if match:
                return match.group(1)
        else:
            import netifaces
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                return addresses[netifaces.AF_INET][0]['addr']
    except Exception as e:
        logger.error(f"Error al obtener IP de la interfaz {interface}: {str(e)}")
    return None

# Obtener la dirección MAC de una interfaz
def get_interface_mac(interface):
    '''
    Obtiene la dirección MAC de una interfaz de red
    '''
    try:
        if sys.platform.startswith('linux'):
            output = subprocess.check_output(['ip', 'link', 'show', interface]).decode('utf-8')
            match = re.search(r'link/ether ([0-9a-f:]+)', output)
            if match:
                return match.group(1)
        else:
            import netifaces
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in addresses:
                return addresses[netifaces.AF_LINK][0]['addr']
    except Exception as e:
        logger.error(f"Error al obtener MAC de la interfaz {interface}: {str(e)}")
    return None

# Verificar si una interfaz está en modo monitor
def is_monitor_mode(interface):
    '''
    Verifica si una interfaz inalámbrica está en modo monitor
    '''
    try:
        if sys.platform.startswith('linux'):
            output = subprocess.check_output(['iwconfig', interface]).decode('utf-8')
            return 'Mode:Monitor' in output
    except Exception as e:
        logger.error(f"Error al verificar modo monitor de {interface}: {str(e)}")
    return False

# Convertir una dirección MAC a formato legible
def format_mac(mac):
    '''
    Convierte una dirección MAC a un formato legible
    '''
    if not mac:
        return None
    mac = mac.replace(':', '').replace('-', '').replace('.', '')
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

# Generar una contraseña aleatoria
def generate_password(length=12, include_special=True):
    '''
    Genera una contraseña aleatoria
    '''
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Calcular el hash de un archivo
def calculate_file_hash(file_path, algorithm='sha256'):
    '''
    Calcula el hash de un archivo
    '''
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Error al calcular hash del archivo {file_path}: {str(e)}")
        return None

# Convertir bytes a un formato legible
def human_readable_size(size, decimal_places=2):
    '''
    Convierte un tamaño en bytes a un formato legible (KB, MB, GB, etc.)
    '''
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0 or unit == 'PB':
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"

# Verificar si un comando está disponible
def is_command_available(command):
    '''
    Verifica si un comando está disponible en el sistema
    '''
    try:
        subprocess.check_output(['which', command], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

# Ejecutar un comando y obtener su salida
def run_command(command, shell=False, timeout=None):
    '''
    Ejecuta un comando y devuelve su salida
    '''
    try:
        if shell:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        else:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=timeout)
        return output.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        logger.error(f"Error al ejecutar comando: {e.output.decode('utf-8', errors='replace')}")
        return e.output.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        logger.error(f"Tiempo de espera agotado al ejecutar comando")
        return None
    except Exception as e:
        logger.error(f"Error al ejecutar comando: {str(e)}")
        return None

# Obtener información del sistema
def get_system_info():
    '''
    Obtiene información del sistema
    '''
    info = {
        'os': os.name,
        'platform': sys.platform,
        'python_version': sys.version,
        'hostname': socket.gethostname(),
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': os.getlogin() if hasattr(os, 'getlogin') else 'unknown'
    }
    
    # Información adicional para Linux
    if sys.platform.startswith('linux'):
        try:
            # Distribución
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            info['distribution'] = line.split('=')[1].strip().strip('"')
                            break
            
            # Kernel
            kernel = run_command(['uname', '-r'])
            if kernel:
                info['kernel'] = kernel.strip()
            
            # CPU
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.startswith('model name'):
                            info['cpu'] = line.split(':')[1].strip()
                            break
            
            # Memoria
            if os.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal'):
                            mem = int(line.split()[1]) * 1024  # KB a bytes
                            info['memory'] = human_readable_size(mem)
                            break
        except Exception as e:
            logger.error(f"Error al obtener información del sistema: {str(e)}")
    
    return info

# Guardar datos en un archivo JSON
def save_json(data, file_path):
    '''
    Guarda datos en un archivo JSON
    '''
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error al guardar archivo JSON {file_path}: {str(e)}")
        return False

# Cargar datos desde un archivo JSON
def load_json(file_path):
    '''
    Carga datos desde un archivo JSON
    '''
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        else:
            logger.warning(f"Archivo JSON {file_path} no encontrado")
            return None
    except Exception as e:
        logger.error(f"Error al cargar archivo JSON {file_path}: {str(e)}")
        return None

# Convertir una dirección IP a entero
def ip_to_int(ip):
    '''
    Convierte una dirección IP a un entero
    '''
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception as e:
        logger.error(f"Error al convertir IP a entero: {str(e)}")
        return None

# Convertir un entero a dirección IP
def int_to_ip(ip_int):
    '''
    Convierte un entero a una dirección IP
    '''
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except Exception as e:
        logger.error(f"Error al convertir entero a IP: {str(e)}")
        return None

# Obtener el gateway predeterminado
def get_default_gateway():
    '''
    Obtiene la dirección IP del gateway predeterminado
    '''
    try:
        if sys.platform.startswith('linux'):
            output = run_command(['ip', 'route', 'show', 'default'])
            if output:
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
                if match:
                    return match.group(1)
        else:
            import netifaces
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][0]
    except Exception as e:
        logger.error(f"Error al obtener gateway predeterminado: {str(e)}")
    return None

# Obtener la interfaz de red predeterminada
def get_default_interface():
    '''
    Obtiene el nombre de la interfaz de red predeterminada
    '''
    try:
        if sys.platform.startswith('linux'):
            output = run_command(['ip', 'route', 'show', 'default'])
            if output:
                match = re.search(r'default via \S+ dev (\S+)', output)
                if match:
                    return match.group(1)
        else:
            import netifaces
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][1]
    except Exception as e:
        logger.error(f"Error al obtener interfaz predeterminada: {str(e)}")
    return None

# Verificar conectividad a Internet
def check_internet_connection():
    '''
    Verifica si hay conexión a Internet
    '''
    try:
        # Intentar conectar a un servidor DNS de Google
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        pass
    return False

# Obtener la fecha y hora actual formateada
def get_timestamp(format='%Y-%m-%d %H:%M:%S'):
    '''
    Obtiene la fecha y hora actual formateada
    '''
    return datetime.now().strftime(format)

# Generar un nombre de archivo único basado en la fecha y hora
def generate_filename(prefix='', suffix='', extension='txt'):
    '''
    Genera un nombre de archivo único basado en la fecha y hora
    '''
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{prefix}{timestamp}{suffix}.{extension}"

# Verificar si un servicio está escuchando en un puerto
def is_port_open(host, port, timeout=2):
    '''
    Verifica si un servicio está escuchando en un puerto
    '''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except Exception as e:
        logger.error(f"Error al verificar puerto {port} en {host}: {str(e)}")
        return False

# Escanear puertos en un host
def scan_ports(host, ports=None, timeout=1):
    '''
    Escanea puertos en un host
    '''
    if not ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    open_ports = []
    for port in ports:
        if is_port_open(host, port, timeout):
            open_ports.append(port)
    
    return open_ports

# Resolver un nombre de dominio a IP
def resolve_domain(domain):
    '''
    Resuelve un nombre de dominio a una dirección IP
    '''
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        logger.error(f"Error al resolver dominio {domain}: {str(e)}")
        return None

# Verificar si un archivo existe y es legible
def is_file_readable(file_path):
    '''
    Verifica si un archivo existe y es legible
    '''
    return os.path.isfile(file_path) and os.access(file_path, os.R_OK)

# Verificar si un directorio existe y es escribible
def is_dir_writable(dir_path):
    '''
    Verifica si un directorio existe y es escribible
    '''
    return os.path.isdir(dir_path) and os.access(dir_path, os.W_OK)

# Crear un directorio si no existe
def create_dir_if_not_exists(dir_path):
    '''
    Crea un directorio si no existe
    '''
    try:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        return True
    except Exception as e:
        logger.error(f"Error al crear directorio {dir_path}: {str(e)}")
        return False

# Limpiar una cadena para usarla como nombre de archivo
def sanitize_filename(filename):
    '''
    Limpia una cadena para usarla como nombre de archivo
    '''
    # Reemplazar caracteres no válidos con guiones bajos
    return re.sub(r'[\\/*?:"<>|]', '_', filename)

# Obtener el tamaño de un archivo
def get_file_size(file_path):
    '''
    Obtiene el tamaño de un archivo en bytes
    '''
    try:
        return os.path.getsize(file_path)
    except Exception as e:
        logger.error(f"Error al obtener tamaño del archivo {file_path}: {str(e)}")
        return 0

# Verificar si un proceso está en ejecución por su PID
def is_process_running(pid):
    '''
    Verifica si un proceso está en ejecución por su PID
    '''
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
    except Exception as e:
        logger.error(f"Error al verificar proceso {pid}: {str(e)}")
        return False

# Obtener la lista de procesos en ejecución
def get_running_processes():
    '''
    Obtiene la lista de procesos en ejecución
    '''
    processes = []
    try:
        if sys.platform.startswith('linux'):
            output = run_command(['ps', 'aux'])
            if output:
                lines = output.strip().split('\n')
                for line in lines[1:]:  # Saltar la cabecera
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': int(parts[1]),
                            'cpu': float(parts[2]),
                            'mem': float(parts[3]),
                            'command': parts[10]
                        })
    except Exception as e:
        logger.error(f"Error al obtener procesos en ejecución: {str(e)}")
    
    return processes

# Verificar si un usuario existe en el sistema
def user_exists(username):
    '''
    Verifica si un usuario existe en el sistema
    '''
    try:
        if sys.platform.startswith('linux'):
            output = run_command(['id', username], shell=False)
            return output is not None and 'no such user' not in output.lower()
    except Exception as e:
        logger.error(f"Error al verificar usuario {username}: {str(e)}")
    return False

# Obtener información de un usuario
def get_user_info(username):
    '''
    Obtiene información de un usuario
    '''
    info = {}
    try:
        if sys.platform.startswith('linux'):
            # ID y grupos
            id_output = run_command(['id', username])
            if id_output:
                uid_match = re.search(r'uid=(\d+)', id_output)
                if uid_match:
                    info['uid'] = int(uid_match.group(1))
                
                gid_match = re.search(r'gid=(\d+)', id_output)
                if gid_match:
                    info['gid'] = int(gid_match.group(1))
                
                groups_match = re.search(r'groups=(.+)', id_output)
                if groups_match:
                    groups_str = groups_match.group(1)
                    groups = []
                    for group in re.finditer(r'(\d+)\(([^)]+)\)', groups_str):
                        groups.append({
                            'gid': int(group.group(1)),
                            'name': group.group(2)
                        })
                    info['groups'] = groups
            
            # Shell y directorio home
            passwd_output = run_command(['grep', f"^{username}:", '/etc/passwd'])
            if passwd_output:
                parts = passwd_output.strip().split(':')
                if len(parts) >= 7:
                    info['home'] = parts[5]
                    info['shell'] = parts[6]
    except Exception as e:
        logger.error(f"Error al obtener información del usuario {username}: {str(e)}")
    
    return info

# Verificar si un grupo existe en el sistema
def group_exists(groupname):
    '''
    Verifica si un grupo existe en el sistema
    '''
    try:
        if sys.platform.startswith('linux'):
            output = run_command(['grep', f"^{groupname}:", '/etc/group'])
            return output is not None and output.strip() != ''
    except Exception as e:
        logger.error(f"Error al verificar grupo {groupname}: {str(e)}")
    return False

# Obtener la versión de una herramienta
def get_tool_version(tool):
    '''
    Obtiene la versión de una herramienta
    '''
    try:
        if tool == 'nmap':
            output = run_command(['nmap', '--version'])
            if output:
                match = re.search(r'Nmap version ([\d\.]+)', output)
                if match:
                    return match.group(1)
        elif tool == 'tcpdump':
            output = run_command(['tcpdump', '--version'])
            if output:
                match = re.search(r'tcpdump version ([\d\.]+)', output)
                if match:
                    return match.group(1)
        elif tool == 'wireshark':
            output = run_command(['wireshark', '--version'])
            if output:
                match = re.search(r'Wireshark ([\d\.]+)', output)
                if match:
                    return match.group(1)
        elif tool == 'aircrack-ng':
            output = run_command(['aircrack-ng', '--version'])
            if output:
                match = re.search(r'Aircrack-ng ([\d\.]+)', output)
                if match:
                    return match.group(1)
        elif tool == 'hydra':
            output = run_command(['hydra', '-h'])
            if output:
                match = re.search(r'Hydra v([\d\.]+)', output)
                if match:
                    return match.group(1)
    except Exception as e:
        logger.error(f"Error al obtener versión de {tool}: {str(e)}")
    
    return None

# Función principal para pruebas
def main():
    print("Módulo de utilidades para RedTrigger")
    print(f"Interfaces de red disponibles: {get_network_interfaces()}")
    print(f"Gateway predeterminado: {get_default_gateway()}")
    print(f"Conexión a Internet: {'Sí' if check_internet_connection() else 'No'}")
    print(f"Información del sistema: {get_system_info()}")

if __name__ == '__main__':
    main()