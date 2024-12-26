import os
import subprocess
import sys
import time

# Función para ejecutar comandos con privilegios de root y manejar errores de red
def run_command(command, retries=3, fix_missing=False):
    """
    Ejecuta un comando con intentos automáticos en caso de fallos, con opción de resolver problemas de red.
    :param command: Comando a ejecutar
    :param retries: Número de intentos en caso de fallos
    :param fix_missing: Si se establece en True, intenta corregir problemas de descarga
    """
    attempt = 0
    while attempt < retries:
        try:
            subprocess.run(command, check=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error al ejecutar '{command}', reintentando ({attempt + 1}/{retries})...")
            if fix_missing and "Temporary failure resolving" in str(e):
                print("[+] Intentando solucionar problemas de conexión...")
                fix_network_issue()
            attempt += 1
            time.sleep(5)  # Espera 5 segundos antes de reintentar
    print(f"[-] Error crítico al ejecutar '{command}', no se pudo completar después de {retries} intentos.")
    return False

# Función para solucionar problemas de red (cambio de repositorio o reiniciar el servicio de red)
def fix_network_issue():
    """
    Intenta solucionar problemas de conexión a Internet cambiando el servidor de repositorios
    o reiniciando el servicio de red.
    """
    # Cambiar servidor de repositorio en sources.list
    print("[+] Cambiando el servidor de repositorios a uno más cercano...")
    with open("/etc/apt/sources.list", "r") as file:
        sources = file.readlines()
    with open("/etc/apt/sources.list", "w") as file:
        for line in sources:
            # Cambia el servidor de repositorio si es necesario (aquí se cambia por uno de Debian)
            if "http.kali.org" in line:
                line = line.replace("http.kali.org", "ftp.debian.org")
            file.write(line)

    # Actualiza los repositorios
    print("[+] Actualizando fuentes de repositorios...")
    run_command("sudo apt update")

    # Reinicia el servicio de red
    print("[+] Reiniciando el servicio de red...")
    run_command("sudo systemctl restart NetworkManager")

# Función para verificar y asegurar que las dependencias estén disponibles
def check_package(package, command="apt install"):
    """
    Verifica si un paquete está disponible y lo instala si no está presente.
    """
    print(f"[+] Comprobando si {package} está instalado...")
    try:
        subprocess.run(f"dpkg -l | grep {package}", check=True, shell=True)
        print(f"[+] {package} ya está instalado.")
    except subprocess.CalledProcessError:
        print(f"[-] {package} no está instalado, instalando...")
        run_command(f"sudo {command} -y {package}")

# Función para instalar dependencias del sistema
def install_system_dependencies():
    print("[+] Instalando dependencias del sistema...")
    system_packages = [
        "iw", "aircrack-ng", "nmap", "tcpdump", "hostapd", "wireshark", "hping3", "git", "net-tools"
    ]
    
    # Actualizar las fuentes de repositorio
    if not run_command("sudo apt update", retries=5, fix_missing=True):
        print("[-] No se pudo actualizar las fuentes del repositorio.")
        sys.exit(1)

    for package in system_packages:
        check_package(package)

# Función para instalar dependencias de Python
def install_python_dependencies():
    print("[+] Instalando dependencias de Python...")
    python_packages = [
        "scapy", "tabulate", "pyyaml", "requests", "subprocess", "wifi"
    ]
    
    for package in python_packages:
        print(f"[+] Instalando {package}...")
        if not run_command(f"pip3 install {package}", retries=3):
            print(f"[-] Error al instalar {package} en Python.")
            sys.exit(1)

# Función principal para instalar todo
def install_all():
    install_system_dependencies()
    install_python_dependencies()
    print("[+] Instalación completada. Puedes ejecutar el script con `python3 sniff2.py`.")

# Ejecutar la instalación
if __name__ == "__main__":
    print("[+] Iniciando el instalador...")
    install_all()
