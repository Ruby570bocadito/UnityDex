#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Módulo de escaneo de vulnerabilidades web para RedTrigger
'''

import os
import sys
import time
import json
import random
import socket
import logging
import threading
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importar módulo de utilidades
try:
    from utils import (
        is_valid_url, run_command, COLORS, create_dir_if_not_exists,
        generate_filename, save_json, load_json, check_internet_connection
    )
except ImportError:
    print("Error: No se pudo importar el módulo de utilidades")
    sys.exit(1)

# Intentar importar módulos necesarios
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Advertencia: Requests no está instalado. La funcionalidad de escaneo web estará limitada.")
    print("Instale requests con: pip install requests")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("Advertencia: BeautifulSoup no está instalado. La funcionalidad de análisis HTML estará limitada.")
    print("Instale beautifulsoup4 con: pip install beautifulsoup4")

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('redtrigger.web_scanner')

# Clase para el escaneo de vulnerabilidades web
class WebScanner:
    '''
    Clase para el escaneo de vulnerabilidades web
    '''
    def __init__(self, config=None):
        '''
        Inicializa el escáner web
        '''
        self.config = config or {}
        self.target = self.config.get('target', None)
        self.threads = self.config.get('threads', 10)
        self.timeout = self.config.get('timeout', 10)
        self.user_agent = self.config.get('user_agent', 'RedTrigger Web Scanner')
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.follow_redirects = self.config.get('follow_redirects', True)
        self.max_depth = self.config.get('max_depth', 2)
        self.cookies = self.config.get('cookies', {})
        self.headers = self.config.get('headers', {})
        self.proxy = self.config.get('proxy', None)
        self.auth = self.config.get('auth', None)
        self.output_dir = self.config.get('output_dir', 'results')
        self.verbose = self.config.get('verbose', False)
        
        # Inicializar variables de estado
        self.stop_scan = False
        self.scan_thread = None
        self.urls_to_scan = set()
        self.scanned_urls = set()
        self.findings = []
        self.forms = []
        self.links = set()
        self.resources = set()
        self.technologies = set()
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Configurar sesión de requests
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': self.user_agent
            })
            if self.headers:
                self.session.headers.update(self.headers)
            if self.cookies:
                self.session.cookies.update(self.cookies)
            if self.proxy:
                self.session.proxies.update({
                    'http': self.proxy,
                    'https': self.proxy
                })
            if self.auth:
                self.session.auth = (self.auth.get('username'), self.auth.get('password'))
    
    def _normalize_url(self, url, base_url=None):
        '''
        Normaliza una URL
        '''
        if not url:
            return None
        
        # Ignorar URLs de javascript, mailto, tel, etc.
        if url.startswith(('javascript:', 'mailto:', 'tel:', '#')):
            return None
        
        # Convertir URLs relativas a absolutas
        if base_url and not url.startswith(('http://', 'https://')):
            if url.startswith('/'):
                # URL relativa a la raíz del dominio
                parsed_base = urllib.parse.urlparse(base_url)
                base = f"{parsed_base.scheme}://{parsed_base.netloc}"
                url = base + url
            else:
                # URL relativa a la URL base
                url = urllib.parse.urljoin(base_url, url)
        
        # Eliminar fragmentos
        url = url.split('#')[0]
        
        # Asegurarse de que la URL termina con / si no tiene parámetros ni extensión
        parsed = urllib.parse.urlparse(url)
        if not parsed.params and not parsed.query and not parsed.fragment:
            path = parsed.path
            if path and not path.endswith('/') and '.' not in path.split('/')[-1]:
                path += '/'
                url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))
        
        return url
    
    def _is_same_domain(self, url, base_url):
        '''
        Verifica si una URL pertenece al mismo dominio que la URL base
        '''
        if not url or not base_url:
            return False
        
        parsed_url = urllib.parse.urlparse(url)
        parsed_base = urllib.parse.urlparse(base_url)
        
        return parsed_url.netloc == parsed_base.netloc
    
    def _make_request(self, url, method='GET', data=None, headers=None, allow_redirects=None):
        '''
        Realiza una petición HTTP
        '''
        if not REQUESTS_AVAILABLE:
            logger.error("Requests no está disponible. No se puede realizar la petición.")
            return None
        
        if not url:
            return None
        
        # Configurar parámetros
        if allow_redirects is None:
            allow_redirects = self.follow_redirects
        
        request_headers = {}
        if headers:
            request_headers.update(headers)
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url,
                    headers=request_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=allow_redirects
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    headers=request_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=allow_redirects
                )
            elif method.upper() == 'HEAD':
                response = self.session.head(
                    url,
                    headers=request_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=allow_redirects
                )
            else:
                logger.error(f"Método HTTP no soportado: {method}")
                return None
            
            return response
        except requests.exceptions.SSLError:
            logger.warning(f"Error SSL en {url}")
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f"Error de conexión en {url}")
            return None
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout en {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error en petición a {url}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado en petición a {url}: {str(e)}")
            return None
    
    def _extract_links(self, response, base_url):
        '''
        Extrae enlaces de una respuesta HTTP
        '''
        if not BS4_AVAILABLE or not response or not response.text:
            return set()
        
        links = set()
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extraer enlaces de etiquetas <a>
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                url = self._normalize_url(href, base_url)
                if url and self._is_same_domain(url, base_url):
                    links.add(url)
            
            # Extraer enlaces de etiquetas <link>
            for link_tag in soup.find_all('link', href=True):
                href = link_tag['href']
                url = self._normalize_url(href, base_url)
                if url and self._is_same_domain(url, base_url):
                    self.resources.add(url)
            
            # Extraer enlaces de etiquetas <script>
            for script_tag in soup.find_all('script', src=True):
                src = script_tag['src']
                url = self._normalize_url(src, base_url)
                if url and self._is_same_domain(url, base_url):
                    self.resources.add(url)
            
            # Extraer enlaces de etiquetas <img>
            for img_tag in soup.find_all('img', src=True):
                src = img_tag['src']
                url = self._normalize_url(src, base_url)
                if url and self._is_same_domain(url, base_url):
                    self.resources.add(url)
            
            # Detectar tecnologías
            self._detect_technologies(soup, response.headers)
            
            return links
        except Exception as e:
            logger.error(f"Error al extraer enlaces de {base_url}: {str(e)}")
            return set()
    
    def _extract_forms(self, response, base_url):
        '''
        Extrae formularios de una respuesta HTTP
        '''
        if not BS4_AVAILABLE or not response or not response.text:
            return []
        
        forms = []
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'url': base_url,
                    'action': self._normalize_url(form.get('action', ''), base_url) or base_url,
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                # Extraer campos del formulario
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_field.get('type', 'text').lower()
                    input_name = input_field.get('name', '')
                    input_value = input_field.get('value', '')
                    
                    if input_name:
                        form_data['inputs'].append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_value
                        })
                
                forms.append(form_data)
            
            return forms
        except Exception as e:
            logger.error(f"Error al extraer formularios de {base_url}: {str(e)}")
            return []
    
    def _detect_technologies(self, soup, headers):
        '''
        Detecta tecnologías utilizadas en una página web
        '''
        # Detectar por cabeceras HTTP
        if headers:
            if 'X-Powered-By' in headers:
                self.technologies.add(headers['X-Powered-By'])
            if 'Server' in headers:
                self.technologies.add(headers['Server'])
            if 'X-AspNet-Version' in headers:
                self.technologies.add(f"ASP.NET {headers['X-AspNet-Version']}")
            if 'X-Generator' in headers:
                self.technologies.add(headers['X-Generator'])
        
        # Detectar por meta tags
        if soup:
            # WordPress
            if soup.find('meta', {'name': 'generator', 'content': lambda x: x and 'WordPress' in x}):
                self.technologies.add('WordPress')
            
            # Joomla
            if soup.find('meta', {'name': 'generator', 'content': lambda x: x and 'Joomla' in x}):
                self.technologies.add('Joomla')
            
            # Drupal
            if soup.find('meta', {'name': 'Generator', 'content': lambda x: x and 'Drupal' in x}):
                self.technologies.add('Drupal')
            
            # Bootstrap
            if soup.find('link', {'href': lambda x: x and 'bootstrap' in x.lower()}):
                self.technologies.add('Bootstrap')
            
            # jQuery
            if soup.find('script', {'src': lambda x: x and 'jquery' in x.lower()}):
                self.technologies.add('jQuery')
            
            # React
            if soup.find(string=lambda text: text and 'react' in text.lower() and 'reactdom' in text.lower()):
                self.technologies.add('React')
            
            # Angular
            if soup.find(string=lambda text: text and 'angular' in text.lower()):
                self.technologies.add('Angular')
            
            # Vue.js
            if soup.find(string=lambda text: text and 'vue' in text.lower()):
                self.technologies.add('Vue.js')
    
    def _test_xss(self, url, params):
        '''
        Prueba vulnerabilidades XSS
        '''
        if not url or not params:
            return None
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '\'"><img src=x onerror=alert(1)>'
        ]
        
        for param_name in params:
            for payload in xss_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self._make_request(url, method='GET', data=test_params)
                if not response:
                    continue
                
                # Verificar si el payload está en la respuesta
                if payload in response.text:
                    return {
                        'type': 'xss',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f"Payload reflejado en la respuesta"
                    }
        
        return None
    
    def _test_sqli(self, url, params):
        '''
        Prueba vulnerabilidades de inyección SQL
        '''
        if not url or not params:
            return None
        
        sqli_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1' --",
            "1\" OR \"1\"=\"1\" --",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR '1'='1' /*",
            "\" OR \"1\"=\"1\" /*"
        ]
        
        sqli_errors = [
            "SQL syntax",
            "mysql_fetch",
            "mysql_num_rows",
            "mysql_query",
            "pg_query",
            "sqlite_query",
            "ORA-01756",
            "ORA-00933",
            "Microsoft SQL Native Client error",
            "ODBC SQL Server Driver",
            "SQLite3::",
            "System.Data.SQLite.SQLiteException"
        ]
        
        for param_name in params:
            for payload in sqli_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self._make_request(url, method='GET', data=test_params)
                if not response:
                    continue
                
                # Verificar si hay errores SQL en la respuesta
                for error in sqli_errors:
                    if error in response.text:
                        return {
                            'type': 'sqli',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Error SQL detectado: {error}"
                        }
        
        return None
    
    def _test_lfi(self, url, params):
        '''
        Prueba vulnerabilidades de inclusión de archivos locales
        '''
        if not url or not params:
            return None
        
        lfi_payloads = [
            "../../../../../../../etc/passwd",
            "../../../../../../../etc/passwd%00",
            "../../../../../../../windows/win.ini",
            "../../../../../../../windows/win.ini%00",
            "../../../../../../../boot.ini",
            "../../../../../../../boot.ini%00"
        ]
        
        lfi_patterns = [
            "root:x:",
            "[fonts]",
            "[boot loader]",
            "[operating systems]"
        ]
        
        for param_name in params:
            for payload in lfi_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self._make_request(url, method='GET', data=test_params)
                if not response:
                    continue
                
                # Verificar si hay patrones de archivos del sistema en la respuesta
                for pattern in lfi_patterns:
                    if pattern in response.text:
                        return {
                            'type': 'lfi',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Patrón de archivo del sistema detectado: {pattern}"
                        }
        
        return None
    
    def _test_open_redirect(self, url, params):
        '''
        Prueba vulnerabilidades de redirección abierta
        '''
        if not url or not params:
            return None
        
        redirect_payloads = [
            "https://example.com",
            "//example.com",
            "/\\example.com",
            "https:example.com"
        ]
        
        for param_name in params:
            for payload in redirect_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                response = self._make_request(url, method='GET', data=test_params, allow_redirects=False)
                if not response:
                    continue
                
                # Verificar si hay redirección a un dominio externo
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'example.com' in location:
                        return {
                            'type': 'open_redirect',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"Redirección a {location}"
                        }
        
        return None
    
    def _test_csrf(self, form):
        '''
        Prueba vulnerabilidades CSRF
        '''
        if not form:
            return None
        
        # Verificar si el formulario tiene tokens CSRF
        has_csrf_token = False
        for input_field in form['inputs']:
            name = input_field['name'].lower()
            if 'csrf' in name or 'token' in name or 'nonce' in name:
                has_csrf_token = True
                break
        
        if not has_csrf_token and form['method'] in ['POST', 'PUT', 'DELETE']:
            return {
                'type': 'csrf',
                'url': form['url'],
                'form_action': form['action'],
                'form_method': form['method'],
                'evidence': "Formulario sin protección CSRF"
            }
        
        return None
    
    def _scan_url(self, url, depth=0):
        '''
        Escanea una URL en busca de vulnerabilidades
        '''
        if self.stop_scan or url in self.scanned_urls or depth > self.max_depth:
            return
        
        logger.info(f"Escaneando URL: {url} (profundidad: {depth})")
        
        # Marcar URL como escaneada
        self.scanned_urls.add(url)
        
        # Realizar petición GET
        response = self._make_request(url, method='GET')
        if not response:
            return
        
        # Extraer enlaces
        links = self._extract_links(response, url)
        self.links.update(links)
        
        # Extraer formularios
        forms = self._extract_forms(response, url)
        self.forms.extend(forms)
        
        # Analizar parámetros de la URL
        parsed_url = urllib.parse.urlparse(url)
        params = {}
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    params[name] = value
        
        # Probar vulnerabilidades en parámetros
        if params:
            # XSS
            xss_finding = self._test_xss(url, params)
            if xss_finding:
                self.findings.append(xss_finding)
                logger.warning(f"Vulnerabilidad XSS encontrada en {url}, parámetro {xss_finding['parameter']}")
            
            # SQLi
            sqli_finding = self._test_sqli(url, params)
            if sqli_finding:
                self.findings.append(sqli_finding)
                logger.warning(f"Vulnerabilidad SQLi encontrada en {url}, parámetro {sqli_finding['parameter']}")
            
            # LFI
            lfi_finding = self._test_lfi(url, params)
            if lfi_finding:
                self.findings.append(lfi_finding)
                logger.warning(f"Vulnerabilidad LFI encontrada en {url}, parámetro {lfi_finding['parameter']}")
            
            # Open Redirect
            redirect_finding = self._test_open_redirect(url, params)
            if redirect_finding:
                self.findings.append(redirect_finding)
                logger.warning(f"Vulnerabilidad de redirección abierta encontrada en {url}, parámetro {redirect_finding['parameter']}")
        
        # Probar vulnerabilidades en formularios
        for form in forms:
            # CSRF
            csrf_finding = self._test_csrf(form)
            if csrf_finding:
                self.findings.append(csrf_finding)
                logger.warning(f"Vulnerabilidad CSRF encontrada en {form['url']}, formulario {form['action']}")
        
        # Agregar enlaces para escanear en la siguiente iteración
        if depth < self.max_depth:
            for link in links:
                if link not in self.scanned_urls and link not in self.urls_to_scan:
                    self.urls_to_scan.add(link)
    
    def _scan_worker(self):
        '''
        Trabajador para el escaneo en paralelo
        '''
        while not self.stop_scan and self.urls_to_scan:
            try:
                # Obtener una URL para escanear
                url = self.urls_to_scan.pop()
                
                # Calcular profundidad
                base_url = self.target.rstrip('/')
                url_path = url.replace(base_url, '').lstrip('/')
                depth = url_path.count('/')
                
                # Escanear URL
                self._scan_url(url, depth)
            except KeyError:
                # No hay más URLs para escanear
                break
            except Exception as e:
                logger.error(f"Error en trabajador de escaneo: {str(e)}")
    
    def start_scan(self, target=None, max_depth=None, threads=None):
        '''
        Inicia el escaneo de vulnerabilidades web
        '''
        if not REQUESTS_AVAILABLE:
            logger.error("Requests no está disponible. No se puede iniciar el escaneo.")
            return False
        
        # Actualizar configuración si se proporcionan parámetros
        if target:
            self.target = target
        if max_depth is not None:
            self.max_depth = max_depth
        if threads is not None:
            self.threads = threads
        
        # Verificar que se haya especificado un objetivo
        if not self.target:
            logger.error("No se ha especificado un objetivo para el escaneo")
            return False
        
        # Normalizar URL objetivo
        self.target = self._normalize_url(self.target)
        if not self.target:
            logger.error("URL objetivo no válida")
            return False
        
        # Verificar conectividad
        if not check_internet_connection():
            logger.error("No hay conexión a Internet")
            return False
        
        # Reiniciar variables
        self.stop_scan = False
        self.urls_to_scan = {self.target}
        self.scanned_urls = set()
        self.findings = []
        self.forms = []
        self.links = set()
        self.resources = set()
        self.technologies = set()
        self.scan_start_time = time.time()
        self.scan_end_time = None
        
        # Crear directorio de salida si no existe
        if self.output_dir and not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except Exception as e:
                logger.error(f"Error al crear directorio de salida: {str(e)}")
                return False
        
        logger.info(f"Iniciando escaneo web en {self.target} (profundidad máxima: {self.max_depth}, hilos: {self.threads})")
        
        # Iniciar trabajadores
        workers = []
        for _ in range(self.threads):
            worker = threading.Thread(target=self._scan_worker)
            worker.daemon = True
            worker.start()
            workers.append(worker)
        
        # Esperar a que terminen los trabajadores
        try:
            # Mostrar progreso
            while any(worker.is_alive() for worker in workers) and not self.stop_scan:
                scanned = len(self.scanned_urls)
                to_scan = len(self.urls_to_scan)
                total = scanned + to_scan
                
                if total > 0:
                    progress = scanned * 100 / total
                    logger.info(f"Progreso: {progress:.1f}% ({scanned}/{total})")
                
                time.sleep(2)
            
            # Finalizar escaneo
            self.scan_end_time = time.time()
            duration = self.scan_end_time - self.scan_start_time
            
            logger.info(f"Escaneo completado en {duration:.2f} segundos")
            logger.info(f"URLs escaneadas: {len(self.scanned_urls)}")
            logger.info(f"Vulnerabilidades encontradas: {len(self.findings)}")
            
            return True
        except KeyboardInterrupt:
            logger.info("Escaneo interrumpido por el usuario")
            self.stop_scan = True
            return False
        except Exception as e:
            logger.error(f"Error en escaneo: {str(e)}")
            return False
    
    def stop(self):
        '''
        Detiene el escaneo
        '''
        if not self.stop_scan:
            logger.info("Deteniendo escaneo...")
            self.stop_scan = True
            return True
        return False
    
    def get_results(self):
        '''
        Obtiene los resultados del escaneo
        '''
        duration = 0
        if self.scan_start_time:
            if self.scan_end_time:
                duration = self.scan_end_time - self.scan_start_time
            else:
                duration = time.time() - self.scan_start_time
        
        results = {
            'target': self.target,
            'start_time': datetime.fromtimestamp(self.scan_start_time).strftime('%Y-%m-%d %H:%M:%S') if self.scan_start_time else None,
            'end_time': datetime.fromtimestamp(self.scan_end_time).strftime('%Y-%m-%d %H:%M:%S') if self.scan_end_time else None,
            'duration': duration,
            'urls_scanned': len(self.scanned_urls),
            'vulnerabilities': self.findings,
            'forms': self.forms,
            'links': list(self.links),
            'resources': list(self.resources),
            'technologies': list(self.technologies)
        }
        
        return results
    
    def save_results(self, output_file=None):
        '''
        Guarda los resultados del escaneo en un archivo JSON
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
            output_file = os.path.join(self.output_dir, f"webscan_{timestamp}.json")
        
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
        Genera un informe del escaneo
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
            output_file = os.path.join(self.output_dir, f"webscan_report_{timestamp}.{format}")
        
        # Obtener resultados
        results = self.get_results()
        
        try:
            if format.lower() == 'txt':
                with open(output_file, 'w') as f:
                    f.write("=== INFORME DE ESCANEO WEB ===\n\n")
                    f.write(f"Objetivo: {results['target']}\n")
                    f.write(f"Inicio: {results['start_time']}\n")
                    f.write(f"Fin: {results['end_time']}\n")
                    f.write(f"Duración: {results['duration']:.2f} segundos\n")
                    f.write(f"URLs escaneadas: {results['urls_scanned']}\n\n")
                    
                    f.write("--- VULNERABILIDADES ENCONTRADAS ---\n")
                    if results['vulnerabilities']:
                        for i, vuln in enumerate(results['vulnerabilities'], 1):
                            f.write(f"[{i}] Tipo: {vuln['type']}\n")
                            f.write(f"    URL: {vuln['url']}\n")
                            if 'parameter' in vuln:
                                f.write(f"    Parámetro: {vuln['parameter']}\n")
                            if 'payload' in vuln:
                                f.write(f"    Payload: {vuln['payload']}\n")
                            f.write(f"    Evidencia: {vuln['evidence']}\n\n")
                    else:
                        f.write("No se encontraron vulnerabilidades\n\n")
                    
                    f.write("--- TECNOLOGÍAS DETECTADAS ---\n")
                    if results['technologies']:
                        for tech in sorted(results['technologies']):
                            f.write(f"- {tech}\n")
                    else:
                        f.write("No se detectaron tecnologías\n")
                    
                    f.write("\n--- FORMULARIOS ENCONTRADOS ---\n")
                    if results['forms']:
                        for i, form in enumerate(results['forms'], 1):
                            f.write(f"[{i}] URL: {form['url']}\n")
                            f.write(f"    Acción: {form['action']}\n")
                            f.write(f"    Método: {form['method']}\n")
                            f.write(f"    Campos: {len(form['inputs'])}\n")
                    else:
                        f.write("No se encontraron formularios\n")
                    
                    f.write("\n=== FIN DEL INFORME ===\n")
            elif format.lower() == 'html':
                with open(output_file, 'w') as f:
                    f.write("<!DOCTYPE html>\n")
                    f.write("<html>\n")
                    f.write("<head>\n")
                    f.write("    <title>Informe de Escaneo Web</title>\n")
                    f.write("    <style>\n")
                    f.write("        body { font-family: Arial, sans-serif; margin: 20px; }\n")
                    f.write("        h1 { color: #2c3e50; }\n")
                    f.write("        h2 { color: #3498db; margin-top: 20px; }\n")
                    f.write("        table { border-collapse: collapse; width: 100%; margin-top: 10px; }\n")
                    f.write("        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
                    f.write("        th { background-color: #f2f2f2; }\n")
                    f.write("        .vuln-high { background-color: #ffdddd; }\n")
                    f.write("        .vuln-medium { background-color: #ffffcc; }\n")
                    f.write("        .vuln-low { background-color: #ddffdd; }\n")
                    f.write("    </style>\n")
                    f.write("</head>\n")
                    f.write("<body>\n")
                    
                    f.write("    <h1>Informe de Escaneo Web</h1>\n")
                    f.write("    <p><strong>Objetivo:</strong> " + results['target'] + "</p>\n")
                    f.write("    <p><strong>Inicio:</strong> " + (results['start_time'] or 'N/A') + "</p>\n")
                    f.write("    <p><strong>Fin:</strong> " + (results['end_time'] or 'N/A') + "</p>\n")
                    f.write(f"    <p><strong>Duración:</strong> {results['duration']:.2f} segundos</p>\n")
                    f.write(f"    <p><strong>URLs escaneadas:</strong> {results['urls_scanned']}</p>\n")
                    
                    f.write("    <h2>Vulnerabilidades Encontradas</h2>\n")
                    if results['vulnerabilities']:
                        f.write("    <table>\n")
                        f.write("        <tr>\n")
                        f.write("            <th>#</th>\n")
                        f.write("            <th>Tipo</th>\n")
                        f.write("            <th>URL</th>\n")
                        f.write("            <th>Detalles</th>\n")
                        f.write("            <th>Evidencia</th>\n")
                        f.write("        </tr>\n")
                        
                        for i, vuln in enumerate(results['vulnerabilities'], 1):
                            vuln_type = vuln['type']
                            severity = "high" if vuln_type in ['sqli', 'rce', 'lfi'] else "medium" if vuln_type in ['xss', 'csrf'] else "low"
                            
                            f.write(f"        <tr class=\"vuln-{severity}\">\n")
                            f.write(f"            <td>{i}</td>\n")
                            f.write(f"            <td>{vuln_type}</td>\n")
                            f.write(f"            <td>{vuln['url']}</td>\n")
                            
                            details = ""
                            if 'parameter' in vuln:
                                details += f"Parámetro: {vuln['parameter']}<br>"
                            if 'payload' in vuln:
                                details += f"Payload: {vuln['payload']}"
                            
                            f.write(f"            <td>{details}</td>\n")
                            f.write(f"            <td>{vuln['evidence']}</td>\n")
                            f.write("        </tr>\n")
                        
                        f.write("    </table>\n")
                    else:
                        f.write("    <p>No se encontraron vulnerabilidades</p>\n")
                    
                    f.write("    <h2>Tecnologías Detectadas</h2>\n")
                    if results['technologies']:
                        f.write("    <ul>\n")
                        for tech in sorted(results['technologies']):
                            f.write(f"        <li>{tech}</li>\n")
                        f.write("    </ul>\n")
                    else:
                        f.write("    <p>No se detectaron tecnologías</p>\n")
                    
                    f.write("    <h2>Formularios Encontrados</h2>\n")
                    if results['forms']:
                        f.write("    <table>\n")
                        f.write("        <tr>\n")
                        f.write("            <th>#</th>\n")
                        f.write("            <th>URL</th>\n")
                        f.write("            <th>Acción</th>\n")
                        f.write("            <th>Método</th>\n")
                        f.write("            <th>Campos</th>\n")
                        f.write("        </tr>\n")
                        
                        for i, form in enumerate(results['forms'], 1):
                            f.write("        <tr>\n")
                            f.write(f"            <td>{i}</td>\n")
                            f.write(f"            <td>{form['url']}</td>\n")
                            f.write(f"            <td>{form['action']}</td>\n")
                            f.write(f"            <td>{form['method']}</td>\n")
                            f.write(f"            <td>{len(form['inputs'])}</td>\n")
                            f.write("        </tr>\n")
                        
                        f.write("    </table>\n")
                    else:
                        f.write("    <p>No se encontraron formularios</p>\n")
                    
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

# Función para escanear un sitio web
def scan_website(url, max_depth=2, threads=10, output_dir=None):
    '''
    Escanea un sitio web en busca de vulnerabilidades
    '''
    if not REQUESTS_AVAILABLE:
        logger.error("Requests no está disponible. No se puede realizar el escaneo.")
        return None
    
    # Verificar URL
    if not is_valid_url(url):
        logger.error(f"URL no válida: {url}")
        return None
    
    # Configurar escáner
    scanner = WebScanner({
        'target': url,
        'max_depth': max_depth,
        'threads': threads,
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

# Función para verificar una URL específica
def check_url(url, checks=None):
    '''
    Verifica una URL específica en busca de vulnerabilidades
    '''
    if not REQUESTS_AVAILABLE:
        logger.error("Requests no está disponible. No se puede realizar la verificación.")
        return None
    
    # Verificar URL
    if not is_valid_url(url):
        logger.error(f"URL no válida: {url}")
        return None
    
    if not checks:
        checks = ['xss', 'sqli', 'lfi', 'open_redirect']
    
    logger.info(f"Verificando URL: {url} (comprobaciones: {checks})")
    
    # Configurar escáner
    scanner = WebScanner({
        'target': url,
        'max_depth': 0,  # Solo verificar la URL proporcionada
        'threads': 1,
        'verbose': True
    })
    
    # Analizar parámetros de la URL
    parsed_url = urllib.parse.urlparse(url)
    params = {}
    if parsed_url.query:
        for param in parsed_url.query.split('&'):
            if '=' in param:
                name, value = param.split('=', 1)
                params[name] = value
    
    findings = []
    
    # Realizar comprobaciones
    if params:
        if 'xss' in checks:
            xss_finding = scanner._test_xss(url, params)
            if xss_finding:
                findings.append(xss_finding)
                logger.warning(f"Vulnerabilidad XSS encontrada en {url}, parámetro {xss_finding['parameter']}")
        
        if 'sqli' in checks:
            sqli_finding = scanner._test_sqli(url, params)
            if sqli_finding:
                findings.append(sqli_finding)
                logger.warning(f"Vulnerabilidad SQLi encontrada en {url}, parámetro {sqli_finding['parameter']}")
        
        if 'lfi' in checks:
            lfi_finding = scanner._test_lfi(url, params)
            if lfi_finding:
                findings.append(lfi_finding)
                logger.warning(f"Vulnerabilidad LFI encontrada en {url}, parámetro {lfi_finding['parameter']}")
        
        if 'open_redirect' in checks:
            redirect_finding = scanner._test_open_redirect(url, params)
            if redirect_finding:
                findings.append(redirect_finding)
                logger.warning(f"Vulnerabilidad de redirección abierta encontrada en {url}, parámetro {redirect_finding['parameter']}")
    else:
        logger.info(f"La URL no tiene parámetros para verificar")
    
    return findings

# Función principal para pruebas
def main():
    print(f"{COLORS['HEADER']}Módulo de escaneo de vulnerabilidades web para RedTrigger{COLORS['ENDC']}")
    
    if not REQUESTS_AVAILABLE:
        print(f"{COLORS['FAIL']}Error: Requests no está instalado. Instale requests con: pip install requests{COLORS['ENDC']}")
        return
    
    # Solicitar URL objetivo
    url = input(f"{COLORS['BOLD']}Ingrese la URL objetivo: {COLORS['ENDC']}")
    if not is_valid_url(url):
        print(f"{COLORS['FAIL']}URL no válida{COLORS['ENDC']}")
        return
    
    # Configurar opciones de escaneo
    max_depth = input(f"{COLORS['BOLD']}Profundidad máxima (1-5, por defecto 2): {COLORS['ENDC']}") or "2"
    threads = input(f"{COLORS['BOLD']}Número de hilos (1-20, por defecto 10): {COLORS['ENDC']}") or "10"
    
    try:
        max_depth = int(max_depth)
        threads = int(threads)
        
        if max_depth < 1 or max_depth > 5:
            print(f"{COLORS['WARNING']}Profundidad no válida, usando valor por defecto (2){COLORS['ENDC']}")
            max_depth = 2
        
        if threads < 1 or threads > 20:
            print(f"{COLORS['WARNING']}Número de hilos no válido, usando valor por defecto (10){COLORS['ENDC']}")
            threads = 10
    except:
        print(f"{COLORS['WARNING']}Valores no válidos, usando valores por defecto{COLORS['ENDC']}")
        max_depth = 2
        threads = 10
    
    # Crear directorio de resultados
    output_dir = 'results'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Iniciar escaneo
    print(f"\n{COLORS['GREEN']}Iniciando escaneo de {url} (profundidad: {max_depth}, hilos: {threads}){COLORS['ENDC']}")
    print("Esto puede tardar varios minutos dependiendo del sitio...")
    print("Presione Ctrl+C para cancelar el escaneo")
    
    try:
        results = scan_website(url, max_depth, threads, output_dir)
        
        if results:
            # Mostrar resultados
            print(f"\n{COLORS['BLUE']}Escaneo completado{COLORS['ENDC']}")
            print(f"URLs escaneadas: {results['urls_scanned']}")
            print(f"Vulnerabilidades encontradas: {len(results['vulnerabilities'])}")
            print(f"Tecnologías detectadas: {len(results['technologies'])}")
            
            if results['vulnerabilities']:
                print(f"\n{COLORS['WARNING']}Vulnerabilidades encontradas:{COLORS['ENDC']}")
                for i, vuln in enumerate(results['vulnerabilities'], 1):
                    print(f"  {i}. Tipo: {vuln['type']}")
                    print(f"     URL: {vuln['url']}")
                    if 'parameter' in vuln:
                        print(f"     Parámetro: {vuln['parameter']}")
                    print(f"     Evidencia: {vuln['evidence']}")
            
            if results['technologies']:
                print(f"\n{COLORS['BLUE']}Tecnologías detectadas:{COLORS['ENDC']}")
                for tech in sorted(results['technologies']):
                    print(f"  - {tech}")
            
            # Mostrar ruta de los informes
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            json_file = os.path.join(output_dir, f"webscan_{timestamp}.json")
            html_file = os.path.join(output_dir, f"webscan_report_{timestamp}.html")
            
            print(f"\n{COLORS['GREEN']}Informes generados:{COLORS['ENDC']}")
            print(f"  - JSON: {json_file}")
            print(f"  - HTML: {html_file}")
    except KeyboardInterrupt:
        print(f"\n{COLORS['WARNING']}Escaneo cancelado por el usuario{COLORS['ENDC']}")
    except Exception as e:
        print(f"\n{COLORS['FAIL']}Error durante el escaneo: {str(e)}{COLORS['ENDC']}")

if __name__ == '__main__':
    main()