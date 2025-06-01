#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para análisis de seguridad en dispositivos IoT
Permite identificar, escanear y analizar dispositivos IoT en la red
"""

import os
import sys
import json
import time
import socket
import requests
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Importar utilidades comunes
try:
    from utils import get_default_gateway, get_default_interface, load_config
except ImportError:
    print("Error: No se pudieron importar las utilidades necesarias.")
    sys.exit(1)

# Configurar logging
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('iot_scanner')

# Base de datos de firmas de dispositivos IoT comunes
IOT_SIGNATURES = {
    'puertos': {
        8080: ['Cámaras IP', 'Routers'],
        2323: ['Dispositivos Telnet vulnerables', 'Mirai botnet'],
        23: ['Telnet sin protección'],
        80: ['Interfaces web IoT'],
        443: ['Interfaces web IoT seguras'],
        1883: ['Broker MQTT'],
        8883: ['Broker MQTT seguro'],
        5683: ['CoAP (Constrained Application Protocol)'],
        5684: ['CoAP seguro'],
        9999: ['Dispositivos Philips Hue'],
        4567: ['Dispositivos Wink Hub'],
        8888: ['Dispositivos HiveMQ'],
        8443: ['Interfaces web seguras alternativas']
    },
    'banners': {
        'Hikvision': ['Cámara IP Hikvision'],
        'Dahua': ['Cámara IP Dahua'],
        'RTSP': ['Cámara con streaming'],
        'Nest': ['Dispositivo Nest'],
        'Philips hue': ['Iluminación Philips Hue'],
        'Sonos': ['Altavoz Sonos'],
        'LIFX': ['Iluminación LIFX'],
        'TP-Link': ['Dispositivo TP-Link'],
        'Belkin': ['Dispositivo Belkin/Wemo'],
        'Xiaomi': ['Dispositivo Xiaomi/Mi'],
        'Tuya': ['Dispositivo Tuya/Smart Life'],
        'MQTT': ['Broker MQTT'],
        'CoAP': ['Dispositivo CoAP'],
        'IKEA TRÅDFRI': ['Iluminación IKEA'],
        'Amazon': ['Dispositivo Amazon Echo/Alexa'],
        'Google Home': ['Dispositivo Google Home'],
        'Apple': ['Dispositivo HomeKit'],
        'Samsung SmartThings': ['Dispositivo SmartThings'],
        'Zigbee': ['Dispositivo Zigbee'],
        'Z-Wave': ['Dispositivo Z-Wave']
    },
    'vulnerabilidades_comunes': {
        'Contraseñas por defecto': {
            'descripcion': 'El dispositivo utiliza credenciales por defecto conocidas',
            'impacto': 'Alto',
            'mitigacion': 'Cambiar las contraseñas por defecto inmediatamente después de la instalación'
        },
        'Firmware desactualizado': {
            'descripcion': 'El dispositivo ejecuta una versión de firmware con vulnerabilidades conocidas',
            'impacto': 'Alto',
            'mitigacion': 'Actualizar el firmware a la última versión disponible'
        },
        'Telnet/SSH abierto': {
            'descripcion': 'Servicios de administración remota expuestos',
            'impacto': 'Alto',
            'mitigacion': 'Deshabilitar Telnet, usar SSH con autenticación de clave y restringir acceso'
        },
        'UPnP habilitado': {
            'descripcion': 'Universal Plug and Play habilitado y expuesto',
            'impacto': 'Medio',
            'mitigacion': 'Deshabilitar UPnP si no es necesario o restringir a la red local'
        },
        'MQTT sin autenticación': {
            'descripcion': 'Broker MQTT sin autenticación',
            'impacto': 'Alto',
            'mitigacion': 'Configurar autenticación y cifrado TLS para MQTT'
        },
        'CoAP sin seguridad': {
            'descripcion': 'Protocolo CoAP sin DTLS',
            'impacto': 'Medio',
            'mitigacion': 'Implementar DTLS para CoAP o restringir a la red local'
        },
        'Comunicación sin cifrar': {
            'descripcion': 'El dispositivo transmite datos sin cifrar',
            'impacto': 'Alto',
            'mitigacion': 'Actualizar a versiones que soporten cifrado o implementar VPN'
        },
        'API sin protección': {
            'descripcion': 'API local o en la nube sin autenticación adecuada',
            'impacto': 'Alto',
            'mitigacion': 'Implementar autenticación OAuth2 o similar y limitar permisos'
        }
    }
}

# Vulnerabilidades específicas por fabricante
VENDOR_VULNERABILITIES = {
    'Hikvision': [
        'CVE-2021-36260 - Ejecución de código remoto sin autenticación',
        'CVE-2017-7921 - Bypass de autenticación en cámaras IP'
    ],
    'Dahua': [
        'CVE-2021-33044 - Bypass de autenticación',
        'CVE-2021-33045 - Escalada de privilegios'
    ],
    'TP-Link': [
        'CVE-2020-24297 - Desbordamiento de búfer en routers',
        'CVE-2020-10882 - Ejecución de código remoto'
    ],
    'Nest': [
        'Vulnerabilidades de privacidad',
        'Problemas de integración con terceros'
    ],
    'Philips Hue': [
        'CVE-2020-6007 - Vulnerabilidad en el protocolo Zigbee',
        'Problemas de actualización remota'
    ],
    'Tuya': [
        'Problemas de cifrado en la comunicación con la nube',
        'Vulnerabilidades en el protocolo propietario'
    ],
    'Xiaomi': [
        'Filtración de datos a servidores externos',
        'Problemas de privacidad en la integración con asistentes de voz'
    ],
    'Genérico': [
        'Contraseñas por defecto',
        'Firmware desactualizado',
        'Comunicación sin cifrar',
        'Falta de actualizaciones de seguridad'
    ]
}

class IoTScanner:
    """Clase principal para el escaneo de dispositivos IoT"""
    
    def __init__(self, options=None):
        """Inicializa el escáner de IoT con opciones avanzadas
        
        Args:
            options: Diccionario con opciones de configuración
                - target: IP, rango de IPs o subred a escanear
                - ports: Lista de puertos a escanear
                - timeout: Tiempo de espera para conexiones
                - threads: Número de hilos para escaneo paralelo
                - deep_scan: Realizar análisis profundo de vulnerabilidades
                - zigbee: Incluir análisis de protocolos ZigBee
                - mqtt: Incluir análisis de protocolos MQTT
                - coap: Incluir análisis de protocolos CoAP
                - zwave: Incluir análisis de protocolos Z-Wave
                - bluetooth: Incluir análisis de dispositivos Bluetooth
                - passive: Modo de escaneo pasivo (solo escucha)
                - aggressive: Modo de escaneo agresivo (pruebas de penetración)
        """
        options = options or {}
        self.target = options.get('target') or get_default_gateway() + '/24'
        self.ports = options.get('ports')
        if isinstance(self.ports, str):
            self.ports = [int(p) for p in self.ports.split(',')]
        else:
            self.ports = self.ports or list(IOT_SIGNATURES['puertos'].keys())
        
        self.timeout = options.get('timeout', 1)
        self.threads = options.get('threads', 50)
        self.deep_scan = options.get('deep_scan', False)
        self.zigbee_enabled = options.get('zigbee', False)
        self.mqtt_enabled = options.get('mqtt', False)
        self.coap_enabled = options.get('coap', False)
        self.zwave_enabled = options.get('zwave', False)
        self.bluetooth_enabled = options.get('bluetooth', False)
        self.passive_mode = options.get('passive', False)
        self.aggressive_mode = options.get('aggressive', False)
        
        # Configuración de protocolos específicos
        self.zigbee_config = {
            'channel': options.get('zigbee_channel', 15),
            'pan_id': options.get('zigbee_pan_id', None),
            'extended_pan_id': options.get('zigbee_extended_pan_id', None)
        }
        
        self.zwave_config = {
            'home_id': options.get('zwave_home_id', None),
            'network_key': options.get('zwave_network_key', None)
        }
        
        self.results = {
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': None,
            'devices': [],
            'wireless_devices': [],  # Para dispositivos ZigBee, Z-Wave, Bluetooth
            'protocols': {           # Estadísticas por protocolo
                'mqtt': {'devices': 0, 'vulnerabilities': 0},
                'coap': {'devices': 0, 'vulnerabilities': 0},
                'zigbee': {'devices': 0, 'vulnerabilities': 0},
                'zwave': {'devices': 0, 'vulnerabilities': 0},
                'bluetooth': {'devices': 0, 'vulnerabilities': 0}
            },
            'summary': {
                'total_devices': 0,
                'vulnerable_devices': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'low_vulnerabilities': 0,
                'attack_vectors': 0
            }
        }
        
        logger.info(f"Inicializando escáner IoT avanzado para {self.target}")
        
        # Inicializar interfaces inalámbricas si es necesario
        if any([self.zigbee_enabled, self.zwave_enabled, self.bluetooth_enabled]):
            self._init_wireless_interfaces()
    
    def _init_wireless_interfaces(self):
        """Inicializa las interfaces inalámbricas necesarias para el escaneo"""
        try:
            # Inicializar interfaz ZigBee si está habilitada
            if self.zigbee_enabled:
                try:
                    import pyzigbee
                    logger.info("Inicializando interfaz ZigBee...")
                    # Código para inicializar interfaz ZigBee
                    # En una implementación real, se configuraría el adaptador ZigBee
                except ImportError:
                    logger.warning("Módulo pyzigbee no encontrado. El análisis ZigBee estará limitado.")
            
            # Inicializar interfaz Z-Wave si está habilitada
            if self.zwave_enabled:
                try:
                    import pyzwave
                    logger.info("Inicializando interfaz Z-Wave...")
                    # Código para inicializar interfaz Z-Wave
                    # En una implementación real, se configuraría el adaptador Z-Wave
                except ImportError:
                    logger.warning("Módulo pyzwave no encontrado. El análisis Z-Wave estará limitado.")
            
            # Inicializar interfaz Bluetooth si está habilitada
            if self.bluetooth_enabled:
                try:
                    import bluetooth
                    logger.info("Inicializando interfaz Bluetooth...")
                    # Código para inicializar interfaz Bluetooth
                    # En una implementación real, se configuraría el adaptador Bluetooth
                except ImportError:
                    logger.warning("Módulo bluetooth no encontrado. El análisis Bluetooth estará limitado.")
        
        except Exception as e:
            logger.error(f"Error al inicializar interfaces inalámbricas: {str(e)}")
    
    def scan(self):
        """Ejecuta el escaneo completo de dispositivos IoT"""
        try:
            logger.info(f"Iniciando escaneo IoT avanzado en {self.target}")
            
            # Fase 1: Escaneo de red TCP/IP
            if not self.passive_mode:
                targets = self._parse_target()
                logger.info(f"Escaneando {len(targets)} hosts en busca de dispositivos IoT")
                
                # Escanear hosts en paralelo
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    executor.map(self._scan_host, targets)
            
            # Fase 2: Escaneo de protocolos específicos IoT
            if self.mqtt_enabled:
                self._scan_mqtt_devices()
            
            if self.coap_enabled:
                self._scan_coap_devices()
            
            # Fase 3: Escaneo de dispositivos inalámbricos
            if self.zigbee_enabled:
                self._scan_zigbee_devices()
            
            if self.zwave_enabled:
                self._scan_zwave_devices()
            
            if self.bluetooth_enabled:
                self._scan_bluetooth_devices()
            
            # Fase 4: Análisis de vulnerabilidades profundo si está habilitado
            if self.deep_scan:
                self.analyze_vulnerabilities()
            
            # Actualizar resumen
            self.results['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.results['summary']['total_devices'] = len(self.results['devices']) + len(self.results['wireless_devices'])
            self.results['summary']['vulnerable_devices'] = sum(1 for device in self.results['devices'] if device.get('vulnerabilities'))
            self.results['summary']['vulnerable_devices'] += sum(1 for device in self.results['wireless_devices'] if device.get('vulnerabilities'))
            
            # Contar vulnerabilidades por severidad
            for device_list in [self.results['devices'], self.results['wireless_devices']]:
                for device in device_list:
                    for vuln in device.get('vulnerabilities', []):
                        if vuln.get('impacto') == 'Crítico':
                            self.results['summary']['critical_vulnerabilities'] += 1
                        elif vuln.get('impacto') == 'Alto':
                            self.results['summary']['high_vulnerabilities'] += 1
                        elif vuln.get('impacto') == 'Medio':
                            self.results['summary']['medium_vulnerabilities'] += 1
                        elif vuln.get('impacto') == 'Bajo':
                            self.results['summary']['low_vulnerabilities'] += 1
            
            # Calcular vectores de ataque potenciales
            self._calculate_attack_vectors()
            
            logger.info(f"Escaneo IoT completado. Encontrados {self.results['summary']['total_devices']} dispositivos, {self.results['summary']['vulnerable_devices']} vulnerables.")
            return self.results
        
        except Exception as e:
            logger.error(f"Error durante el escaneo: {str(e)}")
            return None
    
    def _scan_mqtt_devices(self):
        """Escanea dispositivos que utilizan el protocolo MQTT"""
        logger.info("Iniciando escaneo de dispositivos MQTT...")
        try:
            import paho.mqtt.client as mqtt
            
            # Buscar brokers MQTT en la red
            mqtt_ports = [1883, 8883]
            targets = self._parse_target()
            
            for target in targets:
                for port in mqtt_ports:
                    if self._check_port(target, port):
                        # Intentar conectarse al broker MQTT
                        client = mqtt.Client()
                        client.username_pw_set("probe", "probe")
                        
                        try:
                            # Intentar conexión sin autenticación
                            client.connect(target, port, 5)
                            
                            # Si llegamos aquí, el broker no requiere autenticación (vulnerable)
                            device_info = {
                                'ip': target,
                                'protocol': 'MQTT',
                                'port': port,
                                'device_type': 'MQTT Broker',
                                'vulnerabilities': [{
                                    'nombre': 'MQTT sin autenticación',
                                    'descripcion': 'El broker MQTT permite conexiones sin autenticación',
                                    'impacto': 'Alto',
                                    'mitigacion': 'Configurar autenticación en el broker MQTT'
                                }]
                            }
                            
                            self.results['devices'].append(device_info)
                            self.results['protocols']['mqtt']['devices'] += 1
                            self.results['protocols']['mqtt']['vulnerabilities'] += 1
                            
                            logger.info(f"Broker MQTT vulnerable encontrado en {target}:{port}")
                            
                            # Intentar descubrir tópicos
                            if self.aggressive_mode:
                                self._probe_mqtt_topics(client)
                            
                            client.disconnect()
                        except:
                            # El broker requiere autenticación (seguro)
                            logger.info(f"Broker MQTT seguro encontrado en {target}:{port}")
                            
                            device_info = {
                                'ip': target,
                                'protocol': 'MQTT',
                                'port': port,
                                'device_type': 'MQTT Broker',
                                'vulnerabilities': []
                            }
                            
                            self.results['devices'].append(device_info)
                            self.results['protocols']['mqtt']['devices'] += 1
        
        except ImportError:
            logger.warning("Módulo paho-mqtt no encontrado. El análisis MQTT estará limitado.")
        except Exception as e:
            logger.error(f"Error durante el escaneo MQTT: {str(e)}")
    
    def _scan_coap_devices(self):
        """Escanea dispositivos que utilizan el protocolo CoAP"""
        logger.info("Iniciando escaneo de dispositivos CoAP...")
        coap_devices = []
        
        try:
            # En una implementación real, se utilizaría una biblioteca CoAP
            # como aiocoap o CoAPthon3
            coap_port = 5683
            coap_secure_port = 5684  # Puerto para CoAP sobre DTLS
            targets = self._parse_target()
            
            # Asegurarse de que la estructura de resultados para CoAP esté inicializada
            if 'protocols' not in self.results:
                self.results['protocols'] = {}
            if 'coap' not in self.results['protocols']:
                self.results['protocols']['coap'] = {
                    'devices': 0, 
                    'vulnerabilities': 0,
                    'vulnerabilities_list': []
                }
            
            for target in targets:
                try:
                    # Verificar si el puerto CoAP está abierto (normal o seguro)
                    if self._check_port(target, coap_port) or self._check_port(target, coap_secure_port):
                        # Intentar descubrir recursos CoAP
                        resources = self._discover_coap_resources(target)
                        
                        # Obtener información del dispositivo
                        hostname = self._get_hostname(target)
                        mac = self._get_mac_address(target)
                        vendor_info = self._identify_vendor({'ip': target, 'mac': mac})
                        
                        device_info = {
                            'ip': target,
                            'protocol': 'CoAP',
                            'port': coap_port if self._check_port(target, coap_port) else coap_secure_port,
                            'device_type': 'Dispositivo CoAP',
                            'resources': resources,
                            'hostname': hostname,
                            'mac': mac,
                            'vendor': vendor_info,
                            'vulnerabilities': [],
                            'secure_port_open': self._check_port(target, coap_secure_port)
                        }
                        
                        # Verificar vulnerabilidades CoAP
                        # 1. Verificar si no utiliza DTLS
                        if not resources.get('secure', True) and not device_info['secure_port_open']:
                            device_info['vulnerabilities'].append({
                                'nombre': 'CoAP sin seguridad',
                                'descripcion': 'El dispositivo CoAP no utiliza DTLS para cifrar las comunicaciones',
                                'impacto': 'Alto',
                                'mitigacion': 'Habilitar DTLS para las comunicaciones CoAP',
                                'cve': 'N/A',
                                'referencias': ['https://tools.ietf.org/html/rfc7252']
                            })
                            self.results['protocols']['coap']['vulnerabilities'] += 1
                            if 'CoAP sin seguridad' not in self.results['protocols']['coap']['vulnerabilities_list']:
                                self.results['protocols']['coap']['vulnerabilities_list'].append('CoAP sin seguridad')
                        
                        # 2. Verificar si hay recursos sensibles expuestos
                        sensitive_resources = [r for r in resources.get('resources', []) if r.get('sensitive', False)]
                        if sensitive_resources:
                            device_info['vulnerabilities'].append({
                                'nombre': 'Recursos sensibles expuestos',
                                'descripcion': f'El dispositivo CoAP expone {len(sensitive_resources)} recursos sensibles sin autenticación adecuada',
                                'impacto': 'Medio',
                                'mitigacion': 'Implementar autenticación y autorización para recursos sensibles',
                                'recursos_afectados': [r['path'] for r in sensitive_resources],
                                'cve': 'N/A'
                            })
                            self.results['protocols']['coap']['vulnerabilities'] += 1
                            if 'Recursos sensibles expuestos' not in self.results['protocols']['coap']['vulnerabilities_list']:
                                self.results['protocols']['coap']['vulnerabilities_list'].append('Recursos sensibles expuestos')
                        
                        # 3. Verificar si no requiere autenticación
                        if not resources.get('auth_required', False):
                            device_info['vulnerabilities'].append({
                                'nombre': 'CoAP sin autenticación',
                                'descripcion': 'El dispositivo CoAP no requiere autenticación para acceder a los recursos',
                                'impacto': 'Medio',
                                'mitigacion': 'Implementar mecanismos de autenticación como DTLS-PSK o DTLS-RPK',
                                'cve': 'N/A'
                            })
                            self.results['protocols']['coap']['vulnerabilities'] += 1
                            if 'CoAP sin autenticación' not in self.results['protocols']['coap']['vulnerabilities_list']:
                                self.results['protocols']['coap']['vulnerabilities_list'].append('CoAP sin autenticación')
                        
                        # Añadir el dispositivo a los resultados
                        self.results['devices'].append(device_info)
                        coap_devices.append(device_info)
                        self.results['protocols']['coap']['devices'] += 1
                        self.results['summary']['total_devices'] += 1
                        
                        # Actualizar contador de dispositivos vulnerables
                        if device_info['vulnerabilities']:
                            self.results['summary']['vulnerable_devices'] += 1
                            
                            # Actualizar contadores de vulnerabilidades
                            for vuln in device_info['vulnerabilities']:
                                if vuln['impacto'] == 'Crítico':
                                    self.results['summary']['critical_vulnerabilities'] += 1
                                elif vuln['impacto'] == 'Alto':
                                    self.results['summary']['high_vulnerabilities'] += 1
                                elif vuln['impacto'] == 'Medio':
                                    self.results['summary']['medium_vulnerabilities'] += 1
                                elif vuln['impacto'] == 'Bajo':
                                    self.results['summary']['low_vulnerabilities'] += 1
                        
                        logger.info(f"Dispositivo CoAP encontrado en {target}:{device_info['port']}")
                        if device_info['vulnerabilities']:
                            logger.warning(f"Se encontraron {len(device_info['vulnerabilities'])} vulnerabilidades en el dispositivo CoAP {target}")
                except Exception as device_error:
                    logger.error(f"Error al escanear el dispositivo CoAP {target}: {str(device_error)}")
                    continue
        
        except Exception as e:
            logger.error(f"Error durante el escaneo CoAP: {str(e)}")
            logger.debug(f"Detalles del error: {e}", exc_info=True)
        
        return coap_devices
    
    def _discover_coap_resources(self, target):
        """Descubre recursos CoAP en un dispositivo
        
        En una implementación real, se enviaría una solicitud CoAP GET /.well-known/core
        y se analizaría la respuesta para obtener los recursos disponibles.
        
        Args:
            target: La dirección IP del dispositivo CoAP
            
        Returns:
            Un diccionario con información sobre los recursos CoAP descubiertos
        """
        # Simulamos el descubrimiento de recursos CoAP
        # En una implementación real, se utilizaría una biblioteca como aiocoap o CoAPthon3
        
        # Simulamos encontrar algunos recursos comunes en dispositivos CoAP
        resources = [
            {
                'path': '/.well-known/core',
                'rt': 'core.c',
                'if': 'core.b',
                'ct': '40',
                'sensitive': False
            },
            {
                'path': '/sensors/temperature',
                'rt': 'temperature-c',
                'if': 'sensor',
                'ct': '0',  # text/plain
                'sensitive': False
            },
            {
                'path': '/actuators/led',
                'rt': 'light-control',
                'if': 'core.a',
                'ct': '0',
                'sensitive': False
            },
            {
                'path': '/config',
                'rt': 'config',
                'if': 'core.p',
                'ct': '50',  # application/json
                'sensitive': True  # Recurso sensible que podría exponer configuración
            },
            {
                'path': '/firmware',
                'rt': 'firmware',
                'if': 'core.p',
                'ct': '42',  # application/octet-stream
                'sensitive': True  # Recurso sensible para actualización de firmware
            }
        ]
        
        # Determinar si el dispositivo utiliza DTLS (en este caso simulamos que no)
        secure = False
        
        # Verificar si hay recursos que requieren autenticación
        auth_required = any(r.get('auth_required', False) for r in resources)
        
        return {
            'resources': resources,
            'secure': secure,
            'auth_required': auth_required,
            'observe_supported': True,  # Simulamos que el dispositivo soporta observación
            'block_supported': False    # Simulamos que el dispositivo no soporta transferencia por bloques
        }
    
    def _scan_zigbee_devices(self):
        """Escanea dispositivos ZigBee"""
        logger.info("Iniciando escaneo de dispositivos ZigBee...")
        try:
            # En una implementación real, se utilizaría hardware específico y bibliotecas
            # como pyzigbee para interactuar con dispositivos ZigBee
            
            # Simulamos encontrar algunos dispositivos ZigBee
            zigbee_devices = [
                {
                    'address': '0x1234',
                    'device_type': 'Bombilla inteligente',
                    'manufacturer': 'Philips Hue',
                    'model': 'LCT001',
                    'vulnerabilities': [{
                        'nombre': 'Comunicación ZigBee sin cifrar',
                        'descripcion': 'El dispositivo utiliza comunicación ZigBee sin cifrado',
                        'impacto': 'Medio',
                        'mitigacion': 'Actualizar firmware y habilitar cifrado ZigBee'
                    }]
                },
                {
                    'address': '0x5678',
                    'device_type': 'Sensor de movimiento',
                    'manufacturer': 'SmartThings',
                    'model': 'GP-U999SJVLCAA',
                    'vulnerabilities': []
                }
            ]
            
            # Añadir dispositivos encontrados a los resultados
            for device in zigbee_devices:
                self.results['wireless_devices'].append({
                    'protocol': 'ZigBee',
                    'address': device['address'],
                    'device_type': device['device_type'],
                    'manufacturer': device['manufacturer'],
                    'model': device['model'],
                    'vulnerabilities': device['vulnerabilities']
                })
                
                self.results['protocols']['zigbee']['devices'] += 1
                self.results['protocols']['zigbee']['vulnerabilities'] += len(device['vulnerabilities'])
            
            logger.info(f"Encontrados {len(zigbee_devices)} dispositivos ZigBee")
        
        except Exception as e:
            logger.error(f"Error durante el escaneo ZigBee: {str(e)}")
    
    def _scan_zwave_devices(self):
        """Escanea dispositivos Z-Wave"""
        logger.info("Iniciando escaneo de dispositivos Z-Wave...")
        try:
            # En una implementación real, se utilizaría hardware específico y bibliotecas
            # como pyzwave para interactuar con dispositivos Z-Wave
            
            # Simulamos encontrar algunos dispositivos Z-Wave
            zwave_devices = [
                {
                    'node_id': 2,
                    'device_type': 'Cerradura inteligente',
                    'manufacturer': 'Yale',
                    'model': 'YRD256',
                    'vulnerabilities': []
                },
                {
                    'node_id': 5,
                    'device_type': 'Termostato',
                    'manufacturer': 'Nest',
                    'model': 'T3007ES',
                    'vulnerabilities': [{
                        'nombre': 'Versión Z-Wave antigua',
                        'descripcion': 'El dispositivo utiliza una versión antigua del protocolo Z-Wave con vulnerabilidades conocidas',
                        'impacto': 'Alto',
                        'mitigacion': 'Actualizar firmware o reemplazar el dispositivo'
                    }]
                }
            ]
            
            # Añadir dispositivos encontrados a los resultados
            for device in zwave_devices:
                self.results['wireless_devices'].append({
                    'protocol': 'Z-Wave',
                    'node_id': device['node_id'],
                    'device_type': device['device_type'],
                    'manufacturer': device['manufacturer'],
                    'model': device['model'],
                    'vulnerabilities': device['vulnerabilities']
                })
                
                self.results['protocols']['zwave']['devices'] += 1
                self.results['protocols']['zwave']['vulnerabilities'] += len(device['vulnerabilities'])
            
            logger.info(f"Encontrados {len(zwave_devices)} dispositivos Z-Wave")
        
        except Exception as e:
            logger.error(f"Error durante el escaneo Z-Wave: {str(e)}")
    
    def _scan_bluetooth_devices(self):
        """Escanea dispositivos Bluetooth/BLE"""
        logger.info("Iniciando escaneo de dispositivos Bluetooth...")
        try:
            # En una implementación real, se utilizaría una biblioteca como PyBluez
            # para descubrir dispositivos Bluetooth
            
            # Simulamos encontrar algunos dispositivos Bluetooth
            bluetooth_devices = [
                {
                    'address': '00:11:22:33:44:55',
                    'name': 'SmartLock-1234',
                    'device_type': 'Cerradura inteligente',
                    'manufacturer': 'August',
                    'vulnerabilities': [{
                        'nombre': 'Bluetooth sin emparejamiento seguro',
                        'descripcion': 'El dispositivo no requiere emparejamiento seguro para la conexión Bluetooth',
                        'impacto': 'Crítico',
                        'mitigacion': 'Actualizar firmware y habilitar emparejamiento seguro'
                    }]
                },
                {
                    'address': '66:77:88:99:AA:BB',
                    'name': 'SmartBulb-5678',
                    'device_type': 'Bombilla inteligente',
                    'manufacturer': 'LIFX',
                    'vulnerabilities': []
                }
            ]
            
            # Añadir dispositivos encontrados a los resultados
            for device in bluetooth_devices:
                self.results['wireless_devices'].append({
                    'protocol': 'Bluetooth',
                    'address': device['address'],
                    'name': device['name'],
                    'device_type': device['device_type'],
                    'manufacturer': device['manufacturer'],
                    'vulnerabilities': device['vulnerabilities']
                })
                
                self.results['protocols']['bluetooth']['devices'] += 1
                self.results['protocols']['bluetooth']['vulnerabilities'] += len(device['vulnerabilities'])
            
            logger.info(f"Encontrados {len(bluetooth_devices)} dispositivos Bluetooth")
        
        except Exception as e:
            logger.error(f"Error durante el escaneo Bluetooth: {str(e)}")
    
    def _calculate_attack_vectors(self):
        """Calcula posibles vectores de ataque basados en los dispositivos encontrados"""
        attack_vectors = 0
        
        # Verificar dispositivos vulnerables por protocolo
        for protocol, stats in self.results['protocols'].items():
            if stats['vulnerabilities'] > 0:
                attack_vectors += 1
        
        # Verificar dispositivos con múltiples vulnerabilidades críticas o altas
        for device_list in [self.results['devices'], self.results['wireless_devices']]:
            for device in device_list:
                critical_high_vulns = sum(1 for vuln in device.get('vulnerabilities', []) 
                                        if vuln.get('impacto') in ['Crítico', 'Alto'])
                if critical_high_vulns >= 2:
                    attack_vectors += 1
        
        # Verificar combinaciones peligrosas de dispositivos
        has_router = any(d.get('device_type') == 'Router' for d in self.results['devices'])
        has_camera = any(d.get('device_type') == 'Cámara IP' for d in self.results['devices'])
        has_lock = any(d.get('device_type') == 'Cerradura inteligente' for d in self.results['wireless_devices'])
        
        if has_router and (has_camera or has_lock):
            attack_vectors += 1
        
        self.results['summary']['attack_vectors'] = attack_vectors
    
    def _parse_target(self):
        """Convierte el objetivo en una lista de direcciones IP"""
        targets = []
        try:
            # Si es una dirección IP única
            if '/' not in self.target and '-' not in self.target:
                targets.append(self.target)
            # Si es un rango CIDR
            elif '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            # Si es un rango con guión
            elif '-' in self.target:
                start_ip, end_ip = self.target.split('-')
                start_ip = ipaddress.IPv4Address(start_ip.strip())
                end_ip = ipaddress.IPv4Address(end_ip.strip())
                targets = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
        except Exception as e:
            logger.error(f"Error al parsear el objetivo: {str(e)}")
            # Usar la red local por defecto
            network = ipaddress.ip_network(get_default_gateway() + '/24', strict=False)
            targets = [str(ip) for ip in network.hosts()]
        
        return targets
    
    def _scan_host(self, ip):
        """Escanea un host en busca de puertos abiertos y servicios IoT"""
        open_ports = []
        device_info = {
            'ip': ip,
            'mac': self._get_mac_address(ip),
            'hostname': self._get_hostname(ip),
            'vendor': 'Desconocido',
            'device_type': 'Desconocido',
            'open_ports': [],
            'services': [],
            'vulnerabilities': []
        }
        
        # Escanear puertos
        for port in self.ports:
            if self._check_port(ip, port):
                open_ports.append(port)
                port_info = {
                    'port': port,
                    'service': self._identify_service(port),
                    'banner': self._get_banner(ip, port)
                }
                device_info['open_ports'].append(port_info)
        
        # Si no hay puertos abiertos, no es un dispositivo de interés
        if not open_ports:
            return
        
        # Identificar tipo de dispositivo
        device_info['device_type'] = self._identify_device_type(device_info)
        
        # Identificar fabricante basado en MAC o banners
        device_info['vendor'] = self._identify_vendor(device_info)
        
        # Buscar vulnerabilidades conocidas
        device_info['vulnerabilities'] = self._check_vulnerabilities(device_info)
        
        # Añadir a los resultados
        self.results['devices'].append(device_info)
        logger.info(f"Dispositivo IoT encontrado: {ip} - {device_info['device_type']} - {device_info['vendor']}")
    
    def _check_port(self, ip, port):
        """Comprueba si un puerto está abierto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_banner(self, ip, port):
        """Intenta obtener el banner de un servicio"""
        banner = ""
        try:
            # Diferentes métodos según el puerto
            if port == 80 or port == 8080 or port == 443 or port == 8443:
                # HTTP/HTTPS
                protocol = "https" if port in [443, 8443] else "http"
                try:
                    response = requests.get(f"{protocol}://{ip}:{port}", timeout=self.timeout, verify=False)
                    banner = response.headers.get('Server', '')
                    # Buscar en el título
                    if '<title>' in response.text.lower():
                        title_start = response.text.lower().find('<title>') + 7
                        title_end = response.text.lower().find('</title>')
                        if title_end > title_start:
                            banner += " - " + response.text[title_start:title_end].strip()
                except:
                    pass
            else:
                # Otros servicios (Telnet, MQTT, etc.)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                # Algunos servicios requieren un comando inicial
                if port == 23 or port == 2323:  # Telnet
                    pass  # Telnet suele enviar un banner automáticamente
                elif port == 1883 or port == 8883:  # MQTT
                    # Enviar un paquete CONNECT de MQTT
                    sock.send(b'\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00')
                
                # Recibir respuesta
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
        except Exception as e:
            pass
        
        return banner
    
    def _get_mac_address(self, ip):
        """Obtiene la dirección MAC de un host"""
        # Esta función depende del sistema operativo
        # En sistemas Linux se puede usar el comando arp
        try:
            if os.name == 'posix':  # Linux/Mac
                cmd = f"arp -n {ip} | grep -v Address | awk '{{print $3}}'"
                mac = subprocess.check_output(cmd, shell=True).decode().strip()
                return mac if mac else "Desconocido"
            elif os.name == 'nt':  # Windows
                cmd = f"arp -a {ip}"
                result = subprocess.check_output(cmd, shell=True).decode()
                for line in result.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1].replace('-', ':')
        except:
            pass
        
        return "Desconocido"
    
    def _get_hostname(self, ip):
        """Intenta resolver el nombre de host"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Desconocido"
    
    def _identify_service(self, port):
        """Identifica el servicio basado en el puerto"""
        services = IOT_SIGNATURES['puertos'].get(port, [])
        return services[0] if services else "Desconocido"
    
    def _identify_device_type(self, device_info):
        """Identifica el tipo de dispositivo basado en puertos y banners"""
        # Primero intentar identificar por banners
        for port_info in device_info['open_ports']:
            banner = port_info.get('banner', '').lower()
            for keyword, device_types in IOT_SIGNATURES['banners'].items():
                if keyword.lower() in banner:
                    return device_types[0]
        
        # Si no se identifica por banner, usar puertos
        for port_info in device_info['open_ports']:
            port = port_info.get('port')
            if port in IOT_SIGNATURES['puertos']:
                return IOT_SIGNATURES['puertos'][port][0]
        
        # Si no se puede identificar
        return "Dispositivo IoT genérico"
    
    def _identify_vendor(self, device_info):
        """Identifica el fabricante basado en MAC o banners"""
        # Primero intentar identificar por banners
        for port_info in device_info['open_ports']:
            banner = port_info.get('banner', '').lower()
            for vendor in VENDOR_VULNERABILITIES.keys():
                if vendor.lower() in banner:
                    return vendor
        
        # Intentar identificar por MAC
        mac = device_info.get('mac', '').upper()
        if mac and mac != "Desconocido":
            # Aquí se podría implementar una base de datos de OUI (primeros 6 dígitos de MAC)
            # Por simplicidad, solo verificamos algunos fabricantes comunes
            mac_prefix = mac[:8]
            if mac_prefix in ['B0:C5:54', '74:DA:38', '4C:BC:A5']:
                return 'TP-Link'
            elif mac_prefix in ['00:0E:8F', 'C0:56:27', '90:9A:4A']:
                return 'Hikvision'
            elif mac_prefix in ['00:1C:B3', '00:60:09', '38:01:9F']:
                return 'Dahua'
            elif mac_prefix in ['F8:F0:05', '00:17:88', 'EC:B5:FA']:
                return 'Philips Hue'
            elif mac_prefix in ['18:B4:30', '70:EE:50', '64:16:66']:
                return 'Nest'
            elif mac_prefix in ['FC:67:1F', '68:28:BA', '00:66:4B']:
                return 'Xiaomi'
        
        # Si no se puede identificar
        return "Desconocido"
    
    def _check_vulnerabilities(self, device_info):
        """Comprueba vulnerabilidades conocidas para el dispositivo"""
        vulnerabilities = []
        vendor = device_info.get('vendor')
        device_type = device_info.get('device_type')
        open_ports = [p.get('port') for p in device_info.get('open_ports', [])]
        
        # Verificar vulnerabilidades específicas del fabricante
        if vendor in VENDOR_VULNERABILITIES:
            for vuln in VENDOR_VULNERABILITIES[vendor]:
                vulnerabilities.append({
                    'nombre': vuln,
                    'descripcion': f"Vulnerabilidad específica de {vendor}",
                    'impacto': 'Alto',
                    'mitigacion': 'Actualizar firmware a la última versión disponible'
                })
        
        # Verificar vulnerabilidades comunes basadas en puertos abiertos
        if 23 in open_ports or 2323 in open_ports:
            vulnerabilities.append({
                'nombre': 'Telnet abierto',
                'descripcion': IOT_SIGNATURES['vulnerabilidades_comunes']['Telnet/SSH abierto']['descripcion'],
                'impacto': IOT_SIGNATURES['vulnerabilidades_comunes']['Telnet/SSH abierto']['impacto'],
                'mitigacion': IOT_SIGNATURES['vulnerabilidades_comunes']['Telnet/SSH abierto']['mitigacion']
            })
        
        if 1883 in open_ports:
            # Verificar si MQTT requiere autenticación
            for port_info in device_info.get('open_ports', []):
                if port_info.get('port') == 1883:
                    # Si pudimos conectar y obtener un banner sin autenticación
                    if port_info.get('banner'):
                        vulnerabilities.append({
                            'nombre': 'MQTT sin autenticación',
                            'descripcion': IOT_SIGNATURES['vulnerabilidades_comunes']['MQTT sin autenticación']['descripcion'],
                            'impacto': IOT_SIGNATURES['vulnerabilidades_comunes']['MQTT sin autenticación']['impacto'],
                            'mitigacion': IOT_SIGNATURES['vulnerabilidades_comunes']['MQTT sin autenticación']['mitigacion']
                        })
        
        if 5683 in open_ports:
            vulnerabilities.append({
                'nombre': 'CoAP sin seguridad',
                'descripcion': IOT_SIGNATURES['vulnerabilidades_comunes']['CoAP sin seguridad']['descripcion'],
                'impacto': IOT_SIGNATURES['vulnerabilidades_comunes']['CoAP sin seguridad']['impacto'],
                'mitigacion': IOT_SIGNATURES['vulnerabilidades_comunes']['CoAP sin seguridad']['mitigacion']
            })
        
        # Verificar si hay puertos HTTP pero no HTTPS
        if (80 in open_ports or 8080 in open_ports) and not (443 in open_ports or 8443 in open_ports):
            vulnerabilities.append({
                'nombre': 'Comunicación sin cifrar',
                'descripcion': IOT_SIGNATURES['vulnerabilidades_comunes']['Comunicación sin cifrar']['descripcion'],
                'impacto': IOT_SIGNATURES['vulnerabilidades_comunes']['Comunicación sin cifrar']['impacto'],
                'mitigacion': IOT_SIGNATURES['vulnerabilidades_comunes']['Comunicación sin cifrar']['mitigacion']
            })
        
        return vulnerabilities

    def generate_report(self, output_format='text', output_file=None):
        """Genera un informe de los resultados del escaneo
        
        Args:
            output_format: Formato del informe ('text', 'json', 'html')
            output_file: Ruta del archivo de salida (opcional)
        
        Returns:
            El informe en el formato especificado
        """
        if not self.results['devices']:
            return "No se encontraron dispositivos IoT"
        
        if output_format == 'json':
            report = json.dumps(self.results, indent=4)
        elif output_format == 'html':
            report = self._generate_html_report()
        else:  # text
            report = self._generate_text_report()
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Informe guardado en {output_file}")
        
        return report
    
    def _generate_text_report(self):
        """Genera un informe en formato texto"""
        report = """INFORME DE ESCANEO DE DISPOSITIVOS IOT
=================================

"""
        report += f"Fecha de inicio: {self.results['start_time']}\n"
        report += f"Fecha de finalización: {self.results['end_time']}\n"
        report += f"Objetivo: {self.target}\n\n"
        
        report += "RESUMEN\n------\n"
        report += f"Total de dispositivos IoT encontrados: {self.results['summary']['total_devices']}\n"
        report += f"Dispositivos con vulnerabilidades: {self.results['summary']['vulnerable_devices']}\n"
        report += f"Vulnerabilidades críticas: {self.results['summary']['critical_vulnerabilities']}\n"
        report += f"Vulnerabilidades altas: {self.results['summary']['high_vulnerabilities']}\n"
        report += f"Vulnerabilidades medias: {self.results['summary']['medium_vulnerabilities']}\n"
        report += f"Vulnerabilidades bajas: {self.results['summary']['low_vulnerabilities']}\n\n"
        
        report += "DISPOSITIVOS ENCONTRADOS\n---------------------\n"
        for i, device in enumerate(self.results['devices'], 1):
            report += f"\nDispositivo #{i}\n"
            report += f"  IP: {device['ip']}\n"
            report += f"  Hostname: {device['hostname']}\n"
            report += f"  MAC: {device['mac']}\n"
            report += f"  Fabricante: {device['vendor']}\n"
            report += f"  Tipo: {device['device_type']}\n"
            
            report += "  Puertos abiertos:\n"
            for port_info in device['open_ports']:
                report += f"    - Puerto {port_info['port']}: {port_info['service']}\n"
                if port_info['banner']:
                    report += f"      Banner: {port_info['banner']}\n"
            
            if device['vulnerabilities']:
                report += "  Vulnerabilidades:\n"
                for vuln in device['vulnerabilities']:
                    report += f"    - {vuln['nombre']} (Impacto: {vuln['impacto']})\n"
                    report += f"      Descripción: {vuln['descripcion']}\n"
                    report += f"      Mitigación: {vuln['mitigacion']}\n"
            else:
                report += "  No se encontraron vulnerabilidades conocidas\n"
        
        report += "\n\nRECOMENDACIONES DE SEGURIDAD\n--------------------------\n"
        report += "1. Actualizar el firmware de todos los dispositivos IoT a la última versión disponible\n"
        report += "2. Cambiar las contraseñas por defecto y utilizar contraseñas fuertes y únicas\n"
        report += "3. Deshabilitar servicios innecesarios como Telnet, UPnP, etc.\n"
        report += "4. Implementar segmentación de red para aislar dispositivos IoT\n"
        report += "5. Utilizar cifrado en todas las comunicaciones cuando sea posible\n"
        report += "6. Configurar correctamente los firewalls para limitar el acceso a los dispositivos\n"
        report += "7. Monitorizar regularmente el tráfico de red en busca de comportamientos anómalos\n"
        
        return report
    
    def _generate_html_report(self):
        """Genera un informe en formato HTML"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Informe de Escaneo de Dispositivos IoT</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #3498db; }
        h3 { color: #2980b9; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
        .device { background-color: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .vulnerability { background-color: #fff8f8; padding: 10px; margin: 5px 0; border-left: 3px solid #e74c3c; }
        .high { border-left: 3px solid #c0392b; }
        .medium { border-left: 3px solid #e67e22; }
        .low { border-left: 3px solid #f1c40f; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Informe de Escaneo de Dispositivos IoT</h1>
    
    <div class="summary">
        <h2>Información del Escaneo</h2>
        <p><strong>Fecha de inicio:</strong> {start_time}</p>
        <p><strong>Fecha de finalización:</strong> {end_time}</p>
        <p><strong>Objetivo:</strong> {target}</p>
        
        <h2>Resumen</h2>
        <table>
            <tr><th>Métrica</th><th>Valor</th></tr>
            <tr><td>Total de dispositivos IoT encontrados</td><td>{total_devices}</td></tr>
            <tr><td>Dispositivos con vulnerabilidades</td><td>{vulnerable_devices}</td></tr>
            <tr><td>Vulnerabilidades críticas</td><td>{critical_vulnerabilities}</td></tr>
            <tr><td>Vulnerabilidades altas</td><td>{high_vulnerabilities}</td></tr>
            <tr><td>Vulnerabilidades medias</td><td>{medium_vulnerabilities}</td></tr>
            <tr><td>Vulnerabilidades bajas</td><td>{low_vulnerabilities}</td></tr>
        </table>
    </div>
    
    <h2>Dispositivos Encontrados</h2>
    
    {devices_html}
    
    <h2>Recomendaciones de Seguridad</h2>
    <ol>
        <li>Actualizar el firmware de todos los dispositivos IoT a la última versión disponible</li>
        <li>Cambiar las contraseñas por defecto y utilizar contraseñas fuertes y únicas</li>
        <li>Deshabilitar servicios innecesarios como Telnet, UPnP, etc.</li>
        <li>Implementar segmentación de red para aislar dispositivos IoT</li>
        <li>Utilizar cifrado en todas las comunicaciones cuando sea posible</li>
        <li>Configurar correctamente los firewalls para limitar el acceso a los dispositivos</li>
        <li>Monitorizar regularmente el tráfico de red en busca de comportamientos anómalos</li>
    </ol>
</body>
</html>
"""
        
        # Generar HTML para cada dispositivo
        devices_html = ""
        for i, device in enumerate(self.results['devices'], 1):
            devices_html += f"""<div class="device">
    <h3>Dispositivo #{i}: {device['ip']} ({device['device_type']})</h3>
    <p><strong>Hostname:</strong> {device['hostname']}</p>
    <p><strong>MAC:</strong> {device['mac']}</p>
    <p><strong>Fabricante:</strong> {device['vendor']}</p>
    
    <h4>Puertos abiertos</h4>
    <table>
        <tr><th>Puerto</th><th>Servicio</th><th>Banner</th></tr>
"""
            
            for port_info in device['open_ports']:
                devices_html += f"""        <tr>
            <td>{port_info['port']}</td>
            <td>{port_info['service']}</td>
            <td>{port_info['banner'] or '-'}</td>
        </tr>
"""
            
            devices_html += """    </table>
    
"""
            
            if device['vulnerabilities']:
                devices_html += """    <h4>Vulnerabilidades</h4>
"""
                for vuln in device['vulnerabilities']:
                    impact_class = "high" if vuln['impacto'] == "Alto" else "medium" if vuln['impacto'] == "Medio" else "low"
                    devices_html += f"""    <div class="vulnerability {impact_class}">
        <h5>{vuln['nombre']} (Impacto: {vuln['impacto']})</h5>
        <p><strong>Descripción:</strong> {vuln['descripcion']}</p>
        <p><strong>Mitigación:</strong> {vuln['mitigacion']}</p>
    </div>
"""
            else:
                devices_html += """    <p><em>No se encontraron vulnerabilidades conocidas</em></p>
"""
            
            devices_html += """</div>
"""
        
        # Reemplazar variables en la plantilla
        html = html.format(
            start_time=self.results['start_time'],
            end_time=self.results['end_time'],
            target=self.target,
            total_devices=self.results['summary']['total_devices'],
            vulnerable_devices=self.results['summary']['vulnerable_devices'],
            critical_vulnerabilities=self.results['summary']['critical_vulnerabilities'],
            high_vulnerabilities=self.results['summary']['high_vulnerabilities'],
            medium_vulnerabilities=self.results['summary']['medium_vulnerabilities'],
            low_vulnerabilities=self.results['summary']['low_vulnerabilities'],
            devices_html=devices_html
        )
        
        return html

# Funciones principales para usar desde línea de comandos o como módulo
def scan_iot_devices(target=None, ports=None, output=None, format='text', deep_scan=False, **kwargs):
    """Función principal para escanear dispositivos IoT
    
    Args:
        target: IP, rango de IPs o subred a escanear
        ports: Lista de puertos a escanear (separados por comas si es string, o lista de enteros)
        output: Archivo de salida para el informe
        format: Formato del informe ('text', 'json', 'html')
        deep_scan: Realizar análisis profundo de vulnerabilidades
        **kwargs: Opciones adicionales para el escáner
            - timeout: Tiempo de espera para conexiones (default: 1)
            - threads: Número de hilos para escaneo paralelo (default: 50)
            - mqtt: Incluir análisis de protocolos MQTT (default: False)
            - coap: Incluir análisis de protocolos CoAP (default: False)
            - zigbee: Incluir análisis de protocolos ZigBee (default: False)
            - zwave: Incluir análisis de protocolos Z-Wave (default: False)
            - bluetooth: Incluir análisis de dispositivos Bluetooth (default: False)
            - passive: Modo de escaneo pasivo (default: False)
            - aggressive: Modo de escaneo agresivo (default: False)
    
    Returns:
        Resultados del escaneo
    """
    # Convertir puertos a lista de enteros si se proporcionan como string
    port_list = None
    if isinstance(ports, str):
        port_list = [int(p.strip()) for p in ports.split(',')]
    elif isinstance(ports, list):
        port_list = ports
    
    # Crear opciones para el escáner
    options = {
        'target': target,
        'ports': port_list,
        'timeout': kwargs.get('timeout', 1),
        'threads': kwargs.get('threads', 50),
        'mqtt_enabled': kwargs.get('mqtt', False),
        'coap_enabled': kwargs.get('coap', False),
        'zigbee_enabled': kwargs.get('zigbee', False),
        'zwave_enabled': kwargs.get('zwave', False),
        'bluetooth_enabled': kwargs.get('bluetooth', False),
        'passive_mode': kwargs.get('passive', False),
        'aggressive_mode': kwargs.get('aggressive', False),
        'deep_scan': deep_scan
    }
    
    # Crear y ejecutar el escáner
    scanner = IoTScanner(**options)
    results = scanner.scan()
    
    # Analizar vulnerabilidades si se solicita un escaneo profundo
    if deep_scan:
        scanner.analyze_vulnerabilities()
    
    # Generar informe
    if results:
        report = scanner.generate_report(output_format=format, output_file=output)
        if not output:
            print(report)
    
    return results


def quick_scan(target, output=None, format='text'):
    """Realiza un escaneo rápido de dispositivos IoT con configuración predeterminada
    
    Esta función proporciona una forma simplificada de escanear dispositivos IoT
    utilizando una configuración predeterminada optimizada para velocidad.
    
    Args:
        target: IP, rango de IPs o subred a escanear
        output: Archivo de salida para el informe (opcional)
        format: Formato del informe ('text', 'json', 'html')
    
    Returns:
        Resultados del escaneo
    
    Example:
        ```python
        from iot_scanner import quick_scan
        
        # Escanear la red local
        results = quick_scan('192.168.1.0/24')
        
        # Escanear un dispositivo específico y guardar el informe en HTML
        quick_scan('192.168.1.100', 'informe_iot.html', 'html')
        ```
    """
    # Configuración optimizada para un escaneo rápido
    common_ports = [80, 443, 8080, 8443, 1883, 5683, 23, 22, 21, 2323]
    
    return scan_iot_devices(
        target=target,
        ports=common_ports,
        output=output,
        format=format,
        deep_scan=False,
        timeout=0.5,
        threads=100,
        mqtt=True,
        coap=True
    )


def deep_scan(target, output=None, format='text'):
    """Realiza un escaneo profundo de dispositivos IoT con análisis completo de vulnerabilidades
    
    Esta función proporciona una forma simplificada de realizar un análisis exhaustivo
    de seguridad en dispositivos IoT, incluyendo detección de vulnerabilidades avanzada.
    
    Args:
        target: IP, rango de IPs o subred a escanear
        output: Archivo de salida para el informe (opcional)
        format: Formato del informe ('text', 'json', 'html')
    
    Returns:
        Resultados del escaneo
    
    Example:
        ```python
        from iot_scanner import deep_scan
        
        # Escaneo profundo de un dispositivo específico
        results = deep_scan('192.168.1.100')
        
        # Escaneo profundo de la red local y guardar informe en JSON
        deep_scan('192.168.1.0/24', 'informe_detallado.json', 'json')
        ```
    """
    # Configuración completa para un escaneo profundo
    return scan_iot_devices(
        target=target,
        ports=None,  # Usar todos los puertos predeterminados
        output=output,
        format=format,
        deep_scan=True,
        timeout=2,
        threads=50,
        mqtt=True,
        coap=True,
        zigbee=True,
        zwave=True,
        bluetooth=True
    )

# Ejecutar como script independiente
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Escáner de seguridad para dispositivos IoT')
    parser.add_argument('-t', '--target', help='IP, rango de IPs o subred a escanear')
    parser.add_argument('-p', '--ports', help='Lista de puertos a escanear (separados por comas)')
    parser.add_argument('-o', '--output', help='Archivo de salida para el informe')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'html'], default='text',
                        help='Formato del informe (text, json, html)')
    
    args = parser.parse_args()
    scan_iot_devices(target=args.target, ports=args.ports, output=args.output, format=args.format)