#!/usr/bin/env python3         
import socket
import time
from scapy.all import *
import argparse

def parse_ports(value):
    value = value.replace(" ", "")
    
    parts = value.split(",")
    
    return [int(p) for p in parts]



def syn(args):

    porte_chiuse = 0           # contenitore esterno
    porte_filtrate = 0         # contenitore porte filtrate

    if args.ports:
        
        lista = args.ports
    else:
        lista = range(1, 65536)

    for x in lista:

        pkt = IP(dst=args.target)/TCP(dport=x, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)

        if resp is None :
            porte_filtrate += 1           # accumulo in silenzio
            continue

        if resp.haslayer(TCP) and resp[TCP].flags == 0x12:
            print(f"[+] Porta aperta: {x}")  # stampo SOLO aperte
        else:
            porte_chiuse += 1               # accumulo in silenzio

    print("\n--- RISULTATO ---")
    print(f"Porte chiuse: {porte_chiuse}")
    print(f"porte filtrate {porte_filtrate}")


def normal(args):
    porte_chiuse = 0           # contenitore esterno
    porte_filtrate = 0         # contenitore prote filtrate 

    if args.ports:
        lista = args.ports
    else:
        lista = range(1, 65536)

    
    for x in lista:
        
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((args.target, x))
        except TimeoutError:
            # timeout = probabilmente porta filtrata
            porte_filtrate += 1
        except OSError:
            # errore immediato = porta chiusa
            porte_chiuse += 1
        else:
            # SOLO le porte aperte vengono stampate
            print(f"[+] Porta aperta: {x}")

        finally:
            s.close()

    # riepilogo finale
    print("\n----- RISULTATO -----")
    print(f"Porte chiuse:   {porte_chiuse}")
    print(f"Porte filtrate: {porte_filtrate}")
    print(f"Porte aperte:   stampate sopra")



parser = argparse.ArgumentParser(
    prog ="scanner", 
    description=("Comandi disponibili:\n"
        "  syn       SYN scan (stealth)\n"
        "  normal    TCP connect scan (accurato)\n\n"
        "Cosa può fare ogni comando:\n"
        "syn:\n"
        "  -p        porte a scelta\n"
        "  -p-       tutte le 65535 porte\n\n"
        "normal:\n"
        "  -p        porte a scelta\n"
        "  -p-       tutte le 65535 porte\n"
        "per altre funzioni working in progress\n"
        "Es:\n"
        "scanner syn -p- -t ip\n"
        "scanner normal -p 80,23 -t ip\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
)
sub = parser.add_subparsers(dest="command")
syn_cmd = sub.add_parser("syn")
porte_cmd = sub.add_parser("normal")

#----------syn-------------

syn_cmd.add_argument("-t","--target",required=True)
syn_cmd.add_argument("-p","--ports",nargs="+", type=parse_ports)
syn_cmd.add_argument("-p-","--allports", action="store_true")
syn_cmd.set_defaults(func=syn)

#------------normal----------
porte_cmd.add_argument("-t","--target",required=True)
porte_cmd.add_argument("-p","--ports",nargs="+",type=parse_ports)
porte_cmd.add_argument("-p-","--allports",action="store_true")
porte_cmd.set_defaults(func=normal)

#---------fine--------
args = parser.parse_args()
args.func(args)