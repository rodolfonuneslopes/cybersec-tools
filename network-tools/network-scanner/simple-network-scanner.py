import ipaddress
import os
from sys import exit
import requests
import validators
import netifaces
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether

current_interface = None


def show_interfaces():
    interfaces = netifaces.interfaces()

    if not interfaces:
        print("You don't seem to have any working interface.")
        back_or_quit()

    for interface in interfaces:
        print(interface)


def get_interface(interface):
    interfaces = netifaces.interfaces()

    if not interfaces:
        print("You don't seem to have any working interface.")
        back_or_quit()

    for i in interfaces:
        if i == interface:
            return interface

    print(f"I couldn't find the interface {interface}")
    choose_interface()


def choose_interface():
    clear_console()
    print("\nYou have the following interfaces:\n")
    show_interfaces()
    chosen_interface = input(
        "\nPlease enter the name of the interface you whish to work with:  ")

    interfaces = netifaces.interfaces()
    if chosen_interface not in interfaces:
        print(
            f"Interface {chosen_interface} doesn't appear to exist.")
        back_or_quit()

    global current_interface
    current_interface = get_interface(chosen_interface)
    input(
        f"I'll be working with interface {current_interface}. Press any key to show the main menu.")
    clear_console()
    show_menu()


def show_menu():
    print("1. Ethernet scan\n2. Test IPv4 Address\n3. Test IPv4 Address and Port Number\n4. Test URL\n")
    choice = input("Please enter a number: ")
    str(choice)

    match choice:

        case "1":
            scan_ethernet()

        case "2":
            address = input("Enter a valid IPv4 address: ")
            validate_address(address, 0)

        case "3":
            address = input("Enter a valid IPv4 address: ")

            try:
                port = int(input("Enter a valid port number: "))

                if port < 1 or port > 65535:
                    input(str(port) + " is not a valid port number.")
                    back_or_quit()

                clear_console()
                validate_address(address, port)

            except ValueError:
                print(str(port) + " is not a valid port number.\n")
                back_or_quit()

        case "4":
            url = input("Enter a valid URL: ")

            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url

            test_url(url)

        case _:
            input("That's not a valid option.")
            back_or_quit()


def back_or_quit():
    user_input = input(
        "Press 'q' to quit or any other key to go back to the main menu: ")

    if user_input == "q":
        print("\n Goodbye!\n")
        time.sleep(1)
        clear_console()
        exit()

    clear_console()
    init()


def clear_console():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def validate_address(address, port):
    try:
        ipaddress.ip_address(address)
        if port == 0:
            test_address(address)
        else:
            test_address_and_port(address, port)
    except ValueError:
        clear_console()
        print("The address " + address + " is not valid.")
        back_or_quit()


def netmask_to_cidr(netmask):
    binary_string = ''.join(format(int(octet), '08b')
                            for octet in netmask.split('.'))
    cidr = binary_string.count('1')
    return f'/{cidr}'


def scan_ethernet():
    clear_console()

    try:
        broadcast_address = netifaces.ifaddresses(
            current_interface)[netifaces.AF_INET][0]["broadcast"]
        netmask = netifaces.ifaddresses(current_interface)[
            netifaces.AF_INET][0]["netmask"]
        full_address = broadcast_address + netmask_to_cidr(netmask)

    except KeyError as e:
        if str(e) == "'broadcast'":
            print(
                f"\nInterface {current_interface} doesn't seem to have a broadcast address.")
            back_or_quit()
        elif str(e) == "'netmask'":
            print(
                f"\nInterface {current_interface} doesn't seem to have a netmask.")
            back_or_quit()
        else:
            print(
                f"\nThere seems to be an error with interface {current_interface}.\n")
            back_or_quit()

    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=full_address)
    print("Searching for hosts...\n")
    ans, unans = srp(arp_packet, timeout=3, retry=3,
                     verbose=0, iface=current_interface)

    if not ans:
        print("\nI couldn't find any hosts\n")
        back_or_quit()

    ans.summary(lambda s, r: r.sprintf("MAC %Ether.src% <-> IPv4 %ARP.psrc%"))
    print("\n")
    back_or_quit()


def test_address(address):
    clear_console()
    print(f"Waiting for responses from {address}...")
    ans, unans = sr(IP(dst=address) / ICMP(), timeout=3,
                    verbose=0, iface=current_interface)

    if ans:
        print("The host with the IP address " + address + " is online." + "\n")
        back_or_quit()
    else:
        print("The host with the IP address " + address + " is offline.")
        back_or_quit()


def test_address_and_port(address, port):
    clear_console()
    print(f"Waiting for responses from {address} at port {port}...")
    host_echo = sr1(IP(dst=address) / ICMP(), timeout=3,
                    verbose=0, iface=current_interface)

    if not host_echo:
        print(f"The host at {address} seems to be unreachable.")
        back_or_quit()

    try:
        ip_packet = IP(dst=address) / TCP(dport=port, flags="S")
        response = sr1(ip_packet, verbose=0, timeout=2,
                       iface=current_interface)

        if response is None:
            raise TypeError("The host at " + address + " is not responding.")

        if not response.haslayer(TCP):
            print(f"Port {port} is not listening for TCP connections.")
            back_or_quit()

        if response[TCP].flags == "SA":
            print("The host at " + address +
                  " is listening for TCP connections on port " + str(port))
            send(IP(dst=address) / TCP(dport=port, flags="R"),
                 verbose=0, iface=current_interface)
            back_or_quit()
        elif response[TCP].flags == "R":
            print(
                f"The host at {address} refused to establish a TCP connection on port {port}")
            back_or_quit()
        else:
            print("The host at " + address +
                  " is not listening for TCP connections on port " + str(port))
            back_or_quit()

    except TypeError:
        print("The host at " + address +
              " is not listening for TCP connections on port " + str(port))
        back_or_quit()


def test_url(url):
    try:
        response = requests.get(url)

        response.raise_for_status()

        if response.history:
            print("Everything is OK, but there have been redirects (Status Code is 300).")
            back_or_quit()
        else:
            print("Everything is OK (Status code is 200).")
            back_or_quit()
    except requests.exceptions.RequestException as exception:
        print("\nIt seems we have an error:\n" + "\n" + str(exception) + "\n")
        back_or_quit()


def init():
    choose_interface()


init()
