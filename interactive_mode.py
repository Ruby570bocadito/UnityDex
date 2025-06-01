# Función para modo interactivo
# Importaciones necesarias
import readline
import os
import sys
import time
import json
import threading
import itertools
from datetime import datetime

# Importar funciones y constantes de UnityDex
from unitydex import COLORS, VERSION
from unitydex import network_scan, ssl_analysis, advanced_port_scan
from unitydex import network_vulnerability_scan, malware_analysis, generate_report
from utils import get_default_gateway, get_default_interface, load_config

# Añadir color azul al diccionario COLORS si no existe
if 'BLUE' not in COLORS:
    COLORS['BLUE'] = '\033[1;34m'

# Función para mostrar banner con el tema actual
def print_banner():
    banner = f"""
{THEMES[CURRENT_THEME]['HIGHLIGHT']}██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗{THEMES[CURRENT_THEME]['TITLE']}██████╗ ███████╗██╗  ██╗{COLORS['ENDC']}
{THEMES[CURRENT_THEME]['HIGHLIGHT']}██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝{THEMES[CURRENT_THEME]['TITLE']}██╔══██╗██╔════╝╚██╗██╔╝{COLORS['ENDC']}
{THEMES[CURRENT_THEME]['HIGHLIGHT']}██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝ {THEMES[CURRENT_THEME]['TITLE']}██║  ██║█████╗   ╚███╔╝ {COLORS['ENDC']}
{THEMES[CURRENT_THEME]['HIGHLIGHT']}██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝  {THEMES[CURRENT_THEME]['TITLE']}██║  ██║██╔══╝   ██╔██╗ {COLORS['ENDC']}
{THEMES[CURRENT_THEME]['HIGHLIGHT']}╚██████╔╝██║ ╚████║██║   ██║      ██║   {THEMES[CURRENT_THEME]['TITLE']}██████╔╝███████╗██╔╝ ██╗{COLORS['ENDC']}
{THEMES[CURRENT_THEME]['HIGHLIGHT']} ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝   {THEMES[CURRENT_THEME]['TITLE']}╚═════╝ ╚══════╝╚═╝  ╚═╝{COLORS['ENDC']}

{COLORS['BOLD']}{THEMES[CURRENT_THEME]['FOREGROUND']}Herramienta avanzada para análisis de seguridad en redes{COLORS['ENDC']}
{THEMES[CURRENT_THEME]['INFO']}Versión: {VERSION} | Autor: UnityDex Team{COLORS['ENDC']}
{THEMES[CURRENT_THEME]['WARNING']}\"La seguridad no es un producto, es un proceso\"{COLORS['ENDC']}
"""
    print(banner)
    
    # Mostrar fecha y hora actual
    current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    print(f"{THEMES[CURRENT_THEME]['SUCCESS']}[+] Fecha y hora: {current_time}{COLORS['ENDC']}")
    
    # Mostrar información del sistema
    try:
        import platform
        system_info = platform.system() + " " + platform.release()
        print(f"{THEMES[CURRENT_THEME]['SUCCESS']}[+] Sistema: {system_info}{COLORS['ENDC']}")
    except:
        pass

# Temas disponibles
THEMES = {
    'default': {
        'MENU_BORDER': COLORS['CYAN'],
        'MENU_TITLE': COLORS['WHITE'],
        'MENU_OPTION_NUM': COLORS['GREEN'],
        'MENU_OPTION_TEXT': COLORS['ENDC'],
        'MENU_HIGHLIGHT': COLORS['YELLOW'],
        'MENU_WARNING': COLORS['RED'],
        'PROMPT': COLORS['BLUE'],
        'SUCCESS_MSG': COLORS['SUCCESS'],
        'ERROR_MSG': COLORS['ERROR'],
        'INFO_MSG': COLORS['INFO'],
        'WARNING_MSG': COLORS['WARNING'],
        'BACKGROUND': '',
        'FOREGROUND': COLORS['WHITE']
    },
    'dark': {
        'MENU_BORDER': COLORS['BLUE'],
        'MENU_TITLE': COLORS['CYAN'],
        'MENU_OPTION_NUM': COLORS['GREEN'],
        'MENU_OPTION_TEXT': COLORS['WHITE'],
        'MENU_HIGHLIGHT': COLORS['YELLOW'],
        'MENU_WARNING': COLORS['RED'],
        'PROMPT': COLORS['CYAN'],
        'SUCCESS_MSG': COLORS['GREEN'],
        'ERROR_MSG': COLORS['RED'],
        'INFO_MSG': COLORS['BLUE'],
        'WARNING_MSG': COLORS['YELLOW'],
        'BACKGROUND': '',
        'FOREGROUND': COLORS['WHITE']
    },
    'hacker': {
        'MENU_BORDER': COLORS['GREEN'],
        'MENU_TITLE': COLORS['GREEN'],
        'MENU_OPTION_NUM': COLORS['GREEN'],
        'MENU_OPTION_TEXT': COLORS['GREEN'],
        'MENU_HIGHLIGHT': COLORS['GREEN'],
        'MENU_WARNING': COLORS['RED'],
        'PROMPT': COLORS['GREEN'],
        'SUCCESS_MSG': COLORS['GREEN'],
        'ERROR_MSG': COLORS['RED'],
        'INFO_MSG': COLORS['GREEN'],
        'WARNING_MSG': COLORS['YELLOW'],
        'BACKGROUND': '',
        'FOREGROUND': COLORS['GREEN']
    },
    'colorful': {
        'MENU_BORDER': COLORS['MAGENTA'] if 'MAGENTA' in COLORS else COLORS['PURPLE'],
        'MENU_TITLE': COLORS['CYAN'],
        'MENU_OPTION_NUM': COLORS['YELLOW'],
        'MENU_OPTION_TEXT': COLORS['WHITE'],
        'MENU_HIGHLIGHT': COLORS['GREEN'],
        'MENU_WARNING': COLORS['RED'],
        'PROMPT': COLORS['BLUE'],
        'SUCCESS_MSG': COLORS['GREEN'],
        'ERROR_MSG': COLORS['RED'],
        'INFO_MSG': COLORS['CYAN'],
        'WARNING_MSG': COLORS['YELLOW'],
        'BACKGROUND': '',
        'FOREGROUND': COLORS['WHITE']
    }
}

# Tema actual (por defecto)
CURRENT_THEME = 'default'

# Clase para mostrar una animación de carga
class LoadingAnimation:
    def __init__(self, desc="Cargando", end="Completado", timeout=0.1):
        self.desc = desc
        self.end = end
        self.timeout = timeout
        self.spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        self.busy = False
        self.spinner_thread = None

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(f"\r{COLORS['BOLD']}{THEMES[CURRENT_THEME]['HIGHLIGHT']}{next(self.spinner)} {self.desc}{COLORS['ENDC']}")
            sys.stdout.flush()
            time.sleep(self.timeout)

    def __enter__(self):
        self.busy = True
        self.spinner_thread = threading.Thread(target=self.spinner_task)
        self.spinner_thread.start()
        return self

    def __exit__(self, exception, value, tb):
        self.busy = False
        time.sleep(self.timeout)
        if exception is None:
            sys.stdout.write(f"\r{THEMES[CURRENT_THEME]['SUCCESS']}✓ {self.end}{COLORS['ENDC']}\n")
        else:
            sys.stdout.write(f"\r{THEMES[CURRENT_THEME]['ERROR']}✗ Error: {value}{COLORS['ENDC']}\n")
        sys.stdout.flush()
        return False  # Propagar excepciones

# Función para mostrar ayuda
def print_help(commands):
    """Muestra la lista de comandos disponibles"""
    theme = THEMES[CURRENT_THEME]
    print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}                AYUDA DE UNITYDEX                      {theme['MENU_BORDER']}║{COLORS['ENDC']}")
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╠═══════════════════════════════════════════════════════════╣{COLORS['ENDC']}")
    
    # Agrupar comandos por categorías
    basic_commands = {k: v for k, v in commands.items() if k in ['help', 'clear', 'history', 'interfaces', 'exit']}
    scan_commands = {k: v for k, v in commands.items() if k in ['scan', 'port', 'vuln', 'capture']}
    web_commands = {k: v for k, v in commands.items() if k in ['web', 'dict', 'mitm', 'ssl', 'ddos']}
    other_commands = {k: v for k, v in commands.items() if k in ['wireless', 'malware', 'report', 'config']}
    
    # Imprimir comandos básicos
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {COLORS['BOLD']}COMANDOS BÁSICOS:{COLORS['ENDC']}                                    {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    for cmd, desc in basic_commands.items():
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}  {theme['SUCCESS_MSG']}{cmd:<10}{COLORS['ENDC']} - {desc:<35} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    
    # Imprimir comandos de escaneo
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {COLORS['BOLD']}ESCANEO Y ANÁLISIS DE RED:{COLORS['ENDC']}                          {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    for cmd, desc in scan_commands.items():
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}  {theme['SUCCESS_MSG']}{cmd:<10}{COLORS['ENDC']} - {desc:<35} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    
    # Imprimir comandos web y ataques
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {COLORS['BOLD']}ANÁLISIS WEB Y ATAQUES:{COLORS['ENDC']}                            {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    for cmd, desc in web_commands.items():
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}  {theme['SUCCESS_MSG']}{cmd:<10}{COLORS['ENDC']} - {desc:<35} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    
    # Imprimir otros comandos
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {COLORS['BOLD']}OTRAS HERRAMIENTAS:{COLORS['ENDC']}                                {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    for cmd, desc in other_commands.items():
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}  {theme['SUCCESS_MSG']}{cmd:<10}{COLORS['ENDC']} - {desc:<35} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    
    # Imprimir comandos que no están en ninguna categoría
    remaining_commands = {k: v for k, v in commands.items() 
                         if k not in basic_commands and k not in scan_commands 
                         and k not in web_commands and k not in other_commands}
    if remaining_commands:
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {COLORS['BOLD']}OTROS COMANDOS:{COLORS['ENDC']}                                    {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        for cmd, desc in remaining_commands.items():
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}  {theme['SUCCESS_MSG']}{cmd:<10}{COLORS['ENDC']} - {desc:<35} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
    
    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
    print(f"\n{theme['INFO_MSG']}Para más información sobre un comando, escribe 'comando help'{COLORS['ENDC']}")


# Función para mostrar el menú de configuración
def config_menu(config):
    """Muestra el menú de configuración"""
    global CURRENT_THEME
    while True:
        theme = THEMES[CURRENT_THEME]
        print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}               MENÚ DE CONFIGURACIÓN                  {theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╠═══════════════════════════════════════════════════════════╣{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}1.{COLORS['ENDC']} Interfaz de red predeterminada                    {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}    {theme['INFO_MSG']}Actual: {config.get('default_interface', 'auto')}{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}2.{COLORS['ENDC']} API key de VirusTotal                             {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}    {theme['INFO_MSG']}Actual: {config.get('virustotal_api_key', 'no configurada')}{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}3.{COLORS['ENDC']} Ruta de wordlist                                  {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}    {theme['INFO_MSG']}Actual: {config.get('wordlist_path', '/usr/share/wordlists')}{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}4.{COLORS['ENDC']} Tema de la interfaz                               {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}    {theme['INFO_MSG']}Actual: {CURRENT_THEME}{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}                                                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_WARNING']}5.{COLORS['ENDC']} Guardar y salir                                   {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
        
        option = input(f"\n{COLORS['BOLD']}{theme['PROMPT']}Opción> {COLORS['ENDC']}")
        
        if option == '1':
            interfaces = get_available_interfaces()
            if interfaces:
                print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
                print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}            INTERFACES DE RED DISPONIBLES             {theme['MENU_BORDER']}║{COLORS['ENDC']}")
                print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╠═══════════════════════════════════════════════════════════╣{COLORS['ENDC']}")
                for i, iface in enumerate(interfaces, 1):
                    print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}{i}.{COLORS['ENDC']} {iface:<43} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
                print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}0.{COLORS['ENDC']} Auto (detectar automáticamente){' ' * 25} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
                print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
                
                iface_option = input(f"\n{COLORS['BOLD']}{theme['PROMPT']}Seleccione una interfaz> {COLORS['ENDC']}")
                if iface_option == '0':
                    config['default_interface'] = 'auto'
                    print(f"{theme['SUCCESS_MSG']}[+] Interfaz configurada a 'auto'{COLORS['ENDC']}")
                elif iface_option.isdigit() and 1 <= int(iface_option) <= len(interfaces):
                    config['default_interface'] = interfaces[int(iface_option) - 1]
                    print(f"{theme['SUCCESS_MSG']}[+] Interfaz configurada a '{interfaces[int(iface_option) - 1]}'{COLORS['ENDC']}")
                else:
                    print(f"{theme['ERROR_MSG']}[!] Opción no válida{COLORS['ENDC']}")
            else:
                print(f"{theme['ERROR_MSG']}[!] No se encontraron interfaces de red{COLORS['ENDC']}")
        elif option == '2':
            print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}               CONFIGURAR API VIRUSTOTAL              {theme['MENU_BORDER']}║{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
            api_key = input(f"\n{COLORS['BOLD']}{theme['PROMPT']}API Key de VirusTotal> {COLORS['ENDC']}")
            config['virustotal_api_key'] = api_key
            print(f"{theme['SUCCESS_MSG']}[+] API key de VirusTotal configurada{COLORS['ENDC']}")
        elif option == '3':
            print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}               CONFIGURAR RUTA WORDLIST              {theme['MENU_BORDER']}║{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
            wordlist_path = input(f"\n{COLORS['BOLD']}{theme['PROMPT']}Ruta de diccionarios> {COLORS['ENDC']}")
            config['wordlist_path'] = wordlist_path
            print(f"{theme['SUCCESS_MSG']}[+] Ruta de wordlist configurada{COLORS['ENDC']}")
        elif option == '4':
            # Mostrar temas disponibles
            print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}                  TEMAS DISPONIBLES                   {theme['MENU_BORDER']}║{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╠═══════════════════════════════════════════════════════════╣{COLORS['ENDC']}")
            for i, theme_name in enumerate(THEMES.keys(), 1):
                print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}{i}.{COLORS['ENDC']} {theme_name:<43} {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
            print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
            
            theme_option = input(f"\n{COLORS['BOLD']}{theme['PROMPT']}Seleccione un tema> {COLORS['ENDC']}")
            theme_names = list(THEMES.keys())
            if theme_option.isdigit() and 1 <= int(theme_option) <= len(theme_names):
                CURRENT_THEME = theme_names[int(theme_option) - 1]
                config['theme'] = CURRENT_THEME
                print(f"{theme['SUCCESS_MSG']}[+] Tema configurado a '{CURRENT_THEME}'{COLORS['ENDC']}")
            else:
                print(f"{theme['ERROR_MSG']}[!] Opción no válida{COLORS['ENDC']}")
        elif option == '5':
            with open('config.json', 'w') as f:
                json.dump(config, f, indent=4)
            print(f"{theme['SUCCESS_MSG']}[+] Configuración guardada{COLORS['ENDC']}")
            return
        else:
            print(f"{theme['ERROR_MSG']}[!] Opción no válida{COLORS['ENDC']}")


# Función para obtener interfaces de red disponibles
def get_available_interfaces():
    """Obtiene la lista de interfaces de red disponibles"""
    try:
        from utils import get_network_interfaces
        return get_network_interfaces()
    except ImportError:
        return []

# Función para mostrar la pantalla de bienvenida con animación
def show_welcome_screen():
    """Muestra una pantalla de bienvenida animada"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Logo de UnityDex con animación
    logo = [
        f"{THEMES[CURRENT_THEME]['HIGHLIGHT']}██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗{THEMES[CURRENT_THEME]['TITLE']}██████╗ ███████╗██╗  ██╗{COLORS['ENDC']}",
        f"{THEMES[CURRENT_THEME]['HIGHLIGHT']}██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝{THEMES[CURRENT_THEME]['TITLE']}██╔══██╗██╔════╝╚██╗██╔╝{COLORS['ENDC']}",
        f"{THEMES[CURRENT_THEME]['HIGHLIGHT']}██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝ {THEMES[CURRENT_THEME]['TITLE']}██║  ██║█████╗   ╚███╔╝ {COLORS['ENDC']}",
        f"{THEMES[CURRENT_THEME]['HIGHLIGHT']}██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝  {THEMES[CURRENT_THEME]['TITLE']}██║  ██║██╔══╝   ██╔██╗ {COLORS['ENDC']}",
        f"{THEMES[CURRENT_THEME]['HIGHLIGHT']}╚██████╔╝██║ ╚████║██║   ██║      ██║   {THEMES[CURRENT_THEME]['TITLE']}██████╔╝███████╗██╔╝ ██╗{COLORS['ENDC']}",
        f"{THEMES[CURRENT_THEME]['HIGHLIGHT']} ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝   {THEMES[CURRENT_THEME]['TITLE']}╚═════╝ ╚══════╝╚═╝  ╚═╝{COLORS['ENDC']}"
    ]
    
    # Mostrar logo línea por línea con animación
    for line in logo:
        print(line)
        time.sleep(0.1)
    
    print("\n")
    print(f"{COLORS['BOLD']}{THEMES[CURRENT_THEME]['FOREGROUND']}Herramienta avanzada para análisis de seguridad en redes{COLORS['ENDC']}")
    print(f"{THEMES[CURRENT_THEME]['INFO']}Versión: {VERSION} | Autor: UnityDex Team{COLORS['ENDC']}")
    print(f"{THEMES[CURRENT_THEME]['WARNING']}\"La seguridad no es un producto, es un proceso\"{COLORS['ENDC']}")
    print("\n")
    
    # Mostrar carga de componentes con animación
    components = [
        "Módulos de red",
        "Analizador de vulnerabilidades",
        "Escáner de puertos",
        "Herramientas de análisis web",
        "Motor de informes",
        "Interfaz de usuario"
    ]
    
    print(f"{THEMES[CURRENT_THEME]['INFO']}Inicializando componentes...{COLORS['ENDC']}")
    for component in components:
        with LoadingAnimation(f"Cargando {component}", f"{component} cargado"):
            # Simular carga
            time.sleep(0.5)
    
    print(f"\n{THEMES[CURRENT_THEME]['SUCCESS']}[+] Sistema listo{COLORS['ENDC']}")
    time.sleep(1)

def interactive_mode():
    """Inicia el modo interactivo de UnityDex"""
    # Mostrar pantalla de bienvenida
    show_welcome_screen()
    
    # Verificar permisos de root en sistemas Linux
    
    # Verificar permisos de root en sistemas Linux
    try:
        if sys.platform.startswith('linux') and os.geteuid() != 0:
            print(f"{COLORS['FAIL']}[!] UnityDex debe ser ejecutado como root{COLORS['ENDC']}")
            sys.exit(0)
    except AttributeError:
        pass  # No estamos en Linux o no podemos verificar permisos
    
    config = load_config()
    history = []
    
    # Configurar autocompletado
    commands = {
        'scan': 'Escaneo de red',
        'capture': 'Captura de paquetes',
        'web': 'Análisis de vulnerabilidades web',
        'dict': 'Ataque de diccionario',
        'wireless': 'Escaneo de redes inalámbricas',
        'mitm': 'Ataque Man-in-the-Middle',
        'ssl': 'Análisis SSL/TLS',
        'port': 'Escaneo avanzado de puertos',
        'vuln': 'Análisis de vulnerabilidades de red',
        'malware': 'Análisis de archivos maliciosos',
        'ddos': 'Ataque DDoS (solo con fines educativos)',
        'report': 'Generar informe',
        'config': 'Configuración',
        'clear': 'Limpiar pantalla',
        'history': 'Mostrar historial de comandos',
        'interfaces': 'Listar interfaces de red disponibles',
        'help': 'Mostrar esta ayuda',
        'exit': 'Salir del programa'
    }
    
    # Función de autocompletado
    def completer(text, state):
        options = [cmd for cmd in commands.keys() if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        else:
            return None
    
    # Configurar readline si está disponible
    try:
        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
    except (ImportError, AttributeError):
        print(f"{COLORS['WARNING']}[!] Autocompletado no disponible{COLORS['ENDC']}")
    
    # Función para mostrar el menú principal
    def show_main_menu():
        theme = THEMES[CURRENT_THEME]
        print(f"\n{COLORS['BOLD']}{theme['MENU_BORDER']}╔═══════════════════════════════════════════════════════════╗{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{theme['MENU_TITLE']}               MENÚ PRINCIPAL DE UNITYDEX               {theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╠═══════════════════════════════════════════════════════════╣{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}1.{COLORS['ENDC']}  Escaneo de red                                     {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}2.{COLORS['ENDC']}  Análisis de vulnerabilidades de red               {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}3.{COLORS['ENDC']}  Escaneo avanzado de puertos                       {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}4.{COLORS['ENDC']}  Captura de paquetes                               {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}5.{COLORS['ENDC']}  Análisis de vulnerabilidades web                  {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}6.{COLORS['ENDC']}  Ataque de diccionario                             {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}7.{COLORS['ENDC']}  Escaneo de redes inalámbricas                     {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}8.{COLORS['ENDC']}  Ataque Man-in-the-Middle                          {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}9.{COLORS['ENDC']}  Análisis SSL/TLS                                  {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_WARNING']}10.{COLORS['ENDC']} Ataque DDoS (solo con fines educativos)           {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}11.{COLORS['ENDC']} Análisis de archivos maliciosos                   {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_OPTION_NUM']}12.{COLORS['ENDC']} Generar informe                                   {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_HIGHLIGHT']}13.{COLORS['ENDC']} Configuración                                     {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_HIGHLIGHT']}14.{COLORS['ENDC']} Listar interfaces de red disponibles              {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_HIGHLIGHT']}15.{COLORS['ENDC']} Mostrar historial de comandos                     {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_HIGHLIGHT']}16.{COLORS['ENDC']} Limpiar pantalla                                  {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_HIGHLIGHT']}17.{COLORS['ENDC']} Ayuda                                             {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']} {theme['MENU_WARNING']}0.{COLORS['ENDC']}  Salir                                             {COLORS['BOLD']}{theme['MENU_BORDER']}║{COLORS['ENDC']}")
        print(f"{COLORS['BOLD']}{theme['MENU_BORDER']}╚═══════════════════════════════════════════════════════════╝{COLORS['ENDC']}")
        print(f"\n{theme['INFO_MSG']}También puedes escribir directamente el nombre del comando (ej: 'scan', 'ddos'){COLORS['ENDC']}")
    
    theme = THEMES[CURRENT_THEME]
    print(f"\n{theme['FOREGROUND']}Modo interactivo de UnityDex. Escribe 'help' para ver los comandos disponibles.{COLORS['ENDC']}")
    show_main_menu()
    
    while True:
        try:
            cmd = input(f"\n{COLORS['BOLD']}{theme['PROMPT']}UnityDex> {COLORS['ENDC']}").strip()
            
            if not cmd:
                continue
            
            # Añadir al historial
            history.append(cmd)
            
            # Procesar opciones numéricas del menú principal
            if cmd.isdigit():
                option = int(cmd)
                if option == 0:  # Salir
                    print(f"\n{COLORS['INFO']}Saliendo de UnityDex. ¡Hasta pronto!{COLORS['ENDC']}")
                    break
                elif option == 1:  # Escaneo de red
                    cmd = 'scan'
                elif option == 2:  # Análisis de vulnerabilidades de red
                    cmd = 'vuln'
                elif option == 3:  # Escaneo avanzado de puertos
                    cmd = 'port'
                elif option == 4:  # Captura de paquetes
                    cmd = 'capture'
                elif option == 5:  # Análisis de vulnerabilidades web
                    cmd = 'web'
                elif option == 6:  # Ataque de diccionario
                    cmd = 'dict'
                elif option == 7:  # Escaneo de redes inalámbricas
                    cmd = 'wireless'
                elif option == 8:  # Ataque Man-in-the-Middle
                    cmd = 'mitm'
                elif option == 9:  # Análisis SSL/TLS
                    cmd = 'ssl'
                elif option == 10:  # Ataque DDoS
                    cmd = 'ddos'
                elif option == 11:  # Análisis de archivos maliciosos
                    cmd = 'malware'
                elif option == 12:  # Generar informe
                    cmd = 'report'
                elif option == 13:  # Configuración
                    cmd = 'config'
                elif option == 14:  # Listar interfaces de red disponibles
                    cmd = 'interfaces'
                elif option == 15:  # Mostrar historial de comandos
                    cmd = 'history'
                elif option == 16:  # Limpiar pantalla
                    cmd = 'clear'
                elif option == 17:  # Ayuda
                    cmd = 'help'
                else:
                    print(f"\n{THEMES[CURRENT_THEME]['ERROR']}[!] Opción no válida{COLORS['ENDC']}")
                    continue
             
            # Procesar comandos
            if cmd == 'exit':
                print(f"\n{THEMES[CURRENT_THEME]['FOREGROUND']}¡Hasta pronto!{COLORS['ENDC']}")
                break
            elif cmd == 'help':
                print_help(commands)
            elif cmd == 'clear':
                # Limpiar pantalla (compatible con Windows y Unix)
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            elif cmd == 'history':
                print(f"\n{THEMES[CURRENT_THEME]['FOREGROUND']}Historial de comandos:{COLORS['ENDC']}")
                for i, hist_cmd in enumerate(history[:-1], 1):  # Excluir el comando 'history' actual
                    print(f"  {i}. {hist_cmd}")
            elif cmd == 'interfaces':
                interfaces = get_available_interfaces()
                if interfaces:
                    print(f"\n{THEMES[CURRENT_THEME]['FOREGROUND']}Interfaces de red disponibles:{COLORS['ENDC']}")
                    for i, iface in enumerate(interfaces, 1):
                        print(f"  {i}. {iface}")
                    
                    # Mostrar interfaz predeterminada
                    default_iface = get_default_interface()
                    if default_iface:
                        print(f"\n{THEMES[CURRENT_THEME]['SUCCESS']}[+] Interfaz predeterminada: {default_iface}{COLORS['ENDC']}")
                else:
                    print(f"{THEMES[CURRENT_THEME]['ERROR']}[!] No se encontraron interfaces de red{COLORS['ENDC']}")
            elif cmd == 'scan':
                target = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Objetivo (IP/rango): {COLORS['ENDC']}")
                if target:
                    method = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Método (quick/full/vuln) [quick]: {COLORS['ENDC']}") or 'quick'
                    network_scan(target, method)
            elif cmd == 'capture':
                interface = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Interfaz ({get_default_interface() or 'eth0'}): {COLORS['ENDC']}") or get_default_interface() or 'eth0'
                duration = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Duración en segundos [60]: {COLORS['ENDC']}") or '60'
                filter_expr = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Filtro (opcional): {COLORS['ENDC']}")
                output = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Archivo de salida [capture_{int(time.time())}.pcap]: {COLORS['ENDC']}") or f'capture_{int(time.time())}.pcap'
                
                try:
                    from packet_capture import capture_packets
                    capture_packets(interface, int(duration), output, filter_expr)
                except ImportError:
                    print(f"{THEMES[CURRENT_THEME]['ERROR']}[!] No se pudo importar el módulo de captura de paquetes{COLORS['ENDC']}")
            elif cmd == 'web':
                url = input(f"{THEMES[CURRENT_THEME]['PROMPT']}URL objetivo: {COLORS['ENDC']}")
                if url:
                    try:
                        from web_scanner import scan_web
                        scan_web(url)
                    except ImportError:
                        print(f"{THEMES[CURRENT_THEME]['ERROR']}[!] No se pudo importar el módulo de escaneo web{COLORS['ENDC']}")
            elif cmd == 'dict':
                target = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Objetivo (IP/dominio): {COLORS['ENDC']}")
                service = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Servicio (ssh/ftp/smb): {COLORS['ENDC']}")
                username = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Usuario: {COLORS['ENDC']}")
                wordlist = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Ruta al diccionario: {COLORS['ENDC']}")
                
                if target and service and username and wordlist:
                    try:
                        from dict_attack import dictionary_attack
                        dictionary_attack(target, service, username, wordlist)
                    except ImportError:
                        print(f"{THEMES[CURRENT_THEME]['ERROR']}[!] No se pudo importar el módulo de ataques de diccionario{COLORS['ENDC']}")
            elif cmd == 'wireless':
                interface = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Interfaz inalámbrica: {COLORS['ENDC']}")
                scan_time = input(f"{THEMES[CURRENT_THEME]['PROMPT']}Tiempo de escaneo en segundos [30]: {COLORS['ENDC']}") or '30'
                
                if interface:
                    try:
                        from wireless_scanner import scan_wireless
                        scan_wireless(interface, int(scan_time))
                    except ImportError:
                        print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de escaneo inalámbrico{COLORS['ENDC']}")
            elif cmd == 'mitm':
                interface = input(f"{COLORS['BLUE']}Interfaz ({get_default_interface() or 'eth0'}): {COLORS['ENDC']}") or get_default_interface() or 'eth0'
                target = input(f"{COLORS['BLUE']}IP objetivo: {COLORS['ENDC']}")
                gateway = input(f"{COLORS['BLUE']}IP del gateway [{get_default_gateway()}]: {COLORS['ENDC']}") or get_default_gateway()
                attack_type = input(f"{COLORS['BLUE']}Tipo de ataque (arpspoof/ettercap/bettercap) [arpspoof]: {COLORS['ENDC']}") or 'arpspoof'
                ssl_strip = input(f"{COLORS['BLUE']}Habilitar SSL Strip (s/n) [n]: {COLORS['ENDC']}").lower() == 's'
                dns_spoof = input(f"{COLORS['BLUE']}Habilitar DNS Spoofing (s/n) [n]: {COLORS['ENDC']}").lower() == 's'
                packet_capture = input(f"{COLORS['BLUE']}Habilitar captura de paquetes (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                duration = input(f"{COLORS['BLUE']}Duración en segundos (opcional): {COLORS['ENDC']}")
                
                if target and gateway:
                    try:
                        from mitm_attack import perform_mitm_attack
                        perform_mitm_attack(
                            interface=interface,
                            gateway_ip=gateway,
                            target_ip=target,
                            attack_type=attack_type,
                            ssl_strip=ssl_strip,
                            dns_spoof=dns_spoof,
                            packet_capture=packet_capture,
                            duration=int(duration) if duration else None
                        )
                    except ImportError:
                        print(f"{COLORS['FAIL']}[!] No se pudo importar el módulo de ataques MITM{COLORS['ENDC']}")
            elif cmd == 'ssl':
                interface = input(f"{COLORS['BLUE']}Interfaz ({get_default_interface() or 'eth0'}): {COLORS['ENDC']}") or get_default_interface() or 'eth0'
                target = input(f"{COLORS['BLUE']}IP objetivo: {COLORS['ENDC']}")
                gateway = input(f"{COLORS['BLUE']}IP del gateway [{get_default_gateway()}]: {COLORS['ENDC']}") or get_default_gateway()
                attack_type = input(f"{COLORS['BLUE']}Herramienta para MITM (ettercap/bettercap/arpspoof) [ettercap]: {COLORS['ENDC']}") or 'ettercap'
                duration = input(f"{COLORS['BLUE']}Duración en segundos (opcional): {COLORS['ENDC']}")
                
                if target:
                    ssl_analysis(
                        interface=interface,
                        target=target,
                        gateway=gateway,
                        attack_type=attack_type,
                        duration=int(duration) if duration else None
                    )
            elif cmd == 'port':
                target = input(f"{COLORS['BLUE']}Objetivo (IP/dominio): {COLORS['ENDC']}")
                ports = input(f"{COLORS['BLUE']}Puertos (ej: 22,80,443 o 1-1000) [todos]: {COLORS['ENDC']}")
                scan_type = input(f"{COLORS['BLUE']}Tipo de escaneo (tcp/udp/both) [tcp]: {COLORS['ENDC']}") or 'tcp'
                timing = input(f"{COLORS['BLUE']}Velocidad (0-5) [3]: {COLORS['ENDC']}") or '3'
                service = input(f"{COLORS['BLUE']}Detección de servicios (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                os_detect = input(f"{COLORS['BLUE']}Detección de SO (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                
                if target:
                    advanced_port_scan(
                        target=target,
                        ports=ports,
                        scan_type=scan_type,
                        timing=int(timing),
                        service=service,
                        os=os_detect
                    )
            elif cmd == 'vuln':
                target = input(f"{COLORS['BLUE']}Objetivo (IP/dominio): {COLORS['ENDC']}")
                scan_type = input(f"{COLORS['BLUE']}Tipo de escaneo (quick/full) [full]: {COLORS['ENDC']}") or 'full'
                
                if target:
                    network_vulnerability_scan(target, scan_type)
            elif cmd == 'malware':
                file_path = input(f"{COLORS['BLUE']}Ruta al archivo: {COLORS['ENDC']}")
                sandbox = input(f"{COLORS['BLUE']}Ejecutar en sandbox (s/n) [n]: {COLORS['ENDC']}").lower() == 's'
                virustotal = input(f"{COLORS['BLUE']}Verificar en VirusTotal (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                output = input(f"{COLORS['BLUE']}Archivo de salida (opcional): {COLORS['ENDC']}")
                
                if file_path:
                    options = {
                        'sandbox': sandbox,
                        'virustotal': virustotal,
                        'output': output
                    }
                    malware_analysis(file_path, options)
            elif cmd == 'report':
                output = input(f"{COLORS['BLUE']}Archivo de salida (JSON o HTML): {COLORS['ENDC']}")
                include_system = input(f"{COLORS['BLUE']}Incluir información del sistema (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                include_network = input(f"{COLORS['BLUE']}Incluir información de red (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                include_scans = input(f"{COLORS['BLUE']}Incluir resultados de escaneos (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                include_vulns = input(f"{COLORS['BLUE']}Incluir análisis de vulnerabilidades (s/n) [s]: {COLORS['ENDC']}").lower() != 'n'
                
                if output:
                    generate_report(output, include_system, include_network, include_scans, include_vulns)
            elif cmd == 'ddos':
                print(f"{COLORS['BOLD']}{COLORS['RED']}ADVERTENCIA: Esta herramienta debe usarse SOLO con fines educativos y en entornos controlados.{COLORS['ENDC']}")
                print(f"{COLORS['RED']}El uso indebido de esta herramienta puede ser ilegal y está sujeto a sanciones legales.{COLORS['ENDC']}\n")
                
                target = input(f"{COLORS['BLUE']}Objetivo (IP o dominio): {COLORS['ENDC']}")
                if not target:
                    print(f"{COLORS['FAIL']}[!] Debe especificar un objetivo{COLORS['ENDC']}")
                    continue
                
                try:
                    port = int(input(f"{COLORS['BLUE']}Puerto objetivo: {COLORS['ENDC']}"))
                    if port < 1 or port > 65535:
                        print(f"{COLORS['FAIL']}[!] El puerto debe estar entre 1 y 65535{COLORS['ENDC']}")
                        continue
                except ValueError:
                    print(f"{COLORS['FAIL']}[!] El puerto debe ser un número{COLORS['ENDC']}")
                    continue
                
                print(f"{COLORS['BLUE']}Métodos disponibles:{COLORS['ENDC']}")
                print(f"  1. SYN Flood - Envía paquetes SYN para agotar las conexiones del servidor")
                print(f"  2. UDP Flood - Envía paquetes UDP para saturar el ancho de banda")
                print(f"  3. HTTP Flood - Envía solicitudes HTTP para agotar recursos web")
                print(f"  4. ICMP Flood - Envía paquetes ICMP (ping) para saturar la red")
                
                method_option = input(f"{COLORS['BLUE']}Seleccione un método [1]: {COLORS['ENDC']}") or '1'
                method_map = {'1': 'syn', '2': 'udp', '3': 'http', '4': 'icmp'}
                
                if method_option not in method_map:
                    print(f"{COLORS['FAIL']}[!] Opción no válida{COLORS['ENDC']}")
                    continue
                
                method = method_map[method_option]
                
                try:
                    duration = int(input(f"{COLORS['BLUE']}Duración en segundos [60]: {COLORS['ENDC']}") or '60')
                    if duration < 1:
                        print(f"{COLORS['FAIL']}[!] La duración debe ser mayor que 0{COLORS['ENDC']}")
                        continue
                except ValueError:
                    print(f"{COLORS['FAIL']}[!] La duración debe ser un número{COLORS['ENDC']}")
                    continue
                
                try:
                    threads = int(input(f"{COLORS['BLUE']}Número de hilos [10]: {COLORS['ENDC']}") or '10')
                    if threads < 1:
                        print(f"{COLORS['FAIL']}[!] El número de hilos debe ser mayor que 0{COLORS['ENDC']}")
                        continue
                except ValueError:
                    print(f"{COLORS['FAIL']}[!] El número de hilos debe ser un número{COLORS['ENDC']}")
                    continue
                
                # Importar la función de ataque DDoS desde unitydex
                from unitydex import ddos_attack
                ddos_attack(target, port, method, duration, threads)
            elif cmd == 'config':
                config_menu(config)
            else:
                print(f"{COLORS['FAIL']}[!] Comando desconocido: {cmd}{COLORS['ENDC']}")
                print(f"{COLORS['INFO']}[*] Escribe 'help' para ver los comandos disponibles{COLORS['ENDC']}")
        except KeyboardInterrupt:
            print(f"\n{COLORS['WARNING']}[!] Operación cancelada{COLORS['ENDC']}")
        except Exception as e:
            print(f"{COLORS['FAIL']}[!] Error: {str(e)}{COLORS['ENDC']}")
            import traceback
            traceback.print_exc()
    
    return