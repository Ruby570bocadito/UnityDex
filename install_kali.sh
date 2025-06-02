#!/bin/bash

# Script de instalación para UnityDex en Kali Linux
# Este script instala todas las dependencias necesarias para ejecutar UnityDex

# Colores para mensajes
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}      Instalador de UnityDex para Kali Linux      ${NC}"
echo -e "${BLUE}==================================================${NC}"

# Verificar si se está ejecutando como root
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}[!] Este script debe ejecutarse como root${NC}"
   echo -e "${YELLOW}[*] Ejecute: sudo ./install_kali.sh${NC}"
   exit 1
fi

# Verificar si es Kali Linux
if [ ! -f /etc/os-release ] || ! grep -q 'kali' /etc/os-release; then
    echo -e "${YELLOW}[!] Este script está diseñado para Kali Linux${NC}"
    echo -e "${YELLOW}[*] Puede continuar, pero algunas dependencias podrían no instalarse correctamente${NC}"
    read -p "¿Desea continuar? (s/n): " choice
    if [ "$choice" != "s" ]; then
        echo -e "${RED}[!] Instalación cancelada${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}[+] Actualizando repositorios...${NC}"
sudo apt update

echo -e "${GREEN}[+] Instalando dependencias del sistema...${NC}"
sudo apt install -y python3 python3-pip python3-dev nmap tcpdump wireshark tshark aircrack-ng libpcap-dev libfuzzy-dev yara python3-yara

echo -e "${GREEN}[+] Instalando dependencias de Python...${NC}"
pip3 install -r requirements.txt

# Verificar si hay errores en la instalación de dependencias Python
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Algunas dependencias de Python no se pudieron instalar automáticamente${NC}"
    echo -e "${YELLOW}[*] Intentando instalar dependencias críticas manualmente...${NC}"
    
    # Instalar dependencias críticas manualmente
    pip3 install requests scapy paramiko colorama python-nmap pyOpenSSL cryptography
    
    # Intentar instalar dependencias problemáticas
    echo -e "${YELLOW}[*] Intentando instalar pypcap...${NC}"
    pip3 install pypcap
    
    echo -e "${YELLOW}[*] Intentando instalar ssdeep...${NC}"
    pip3 install ssdeep
fi

# Dar permisos de ejecución al script principal
echo -e "${GREEN}[+] Configurando permisos...${NC}"
chmod +x unitydex.py

echo -e "${GREEN}[+] Instalación completada${NC}"
echo -e "${BLUE}==================================================${NC}"
echo -e "${GREEN}Para ejecutar UnityDex:${NC}"
echo -e "${YELLOW}sudo ./unitydex.py -i${NC} (modo interactivo)"
echo -e "${YELLOW}sudo ./unitydex.py --help${NC} (ver opciones disponibles)"
echo -e "${BLUE}==================================================${NC}"