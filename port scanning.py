#!/usr/bin/env python3         
import socket
import time
from scapy.all import *
import argparse

#funzione usata per gestire spaiz e virgole
def parse_ports(value):
    value = value.replace(" ", "")
    
    parts = value.split(",")
    
    return [int(p) for p in parts]



# prima funzione per il syn
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
    print(f"Porte aperte:   stampate sopra")

#seconda funzione per il parametro normale
def normal(args):
    
    porte_chiuse = 0           # contenitore esterno
    porte_filtrate = 0         # contenitore porte filtrate
    
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
            print(f"Porta aperta: {x}")

        finally:
            s.close()

    # riepilogo finale
    print("\n--- RISULTATO ---")
    print(f"Porte chiuse: {porte_chiuse}")
    print(f"porte filtrate {porte_filtrate}")
    print(f"Porte aperte:   stampate sopra")

#funzione per udp
def udp (args):
    porte_chiuse = 0           # contenitore porte chiuse


    if args.ports:
        lista = args.ports
    else:
        lista = range(1, 65535)

    for x in lista:
        match x:
            case 53:
    
                dkcg = IP(dst=args.target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
                resp = sr1(dkcg, timeout=1, verbose=0)

                if resp is None:
                    print("la porta 53 è open/filtred")

                elif resp.haslayer(UDP):
                    print("la porta 53 è aperta")

                elif resp.haslayer(ICMP):
                    if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                        print("la porta 53 è chiusa") 
    
                else:
                    print("è successo qualcosa che non era previsto, perfavore riprovare la scansione")


            case 69:
        
                payload = b'\x00\x01' + b'filestranissimoerrefrtgrgwfgr.txt\x00'  + b'octet\x00'

                dkcg = IP(dst=args.target)/UDP(sport=50002, dport=69)/Raw(payload)
                resp = sr1(dkcg, timeout=1, verbose=0)

                if resp is None:
                    print("la porta 69 è open/filtred")

                elif resp.haslayer(UDP):
                    print("Porta 69 aperta")

                elif resp.haslayer(ICMP):
                    if resp[ICMP].type ==3 and resp[ICMP].code == 3:
                        print("la port 69 è chiusa ")
                
                else:
                    print("è successo qualcosa che non era previsto, perfavore riprovare la scansione")
        

            case 123:

                dichiarazione ='!BBBB3I4Q'
                primo_byte = 0x23
                valori_corretti = (
                primo_byte,  # B
                0,           # B
                0,           # B
                0,           # B
                0, 0, 0,     # 3I
                0, 0, 0, 0   # 4Q
                )

                payload = struct.pack(dichiarazione, *valori_corretti)

                dkcg = IP(dst=args.target)/UDP(sport=50002, dport=123)/Raw(payload)
                resp = sr1(dkcg, timeout=1, verbose=0)

                if resp is None:
                    print("la porta 123 è filtrata")

                elif resp.haslayer(UDP):
                    print("Porta 123 aperta ")

                elif resp.haslayer(ICMP):
                    if resp[ICMP].type ==3 and resp[ICMP].code == 3:
                        print("porta 123 chiusa")

                else:
                    print("è successo qualcosa che non era previsto, perfavore riprovare la scansione")

        
            case 500:
                # IKEv1 Header (28 bytes)
                init_spi = b"\x00"*8
                resp_spi = b"\x00"*8
                next_payload = 0x22     # SA payload
                version = 0x10          # IKEv1 major=1 minor=0
                exchange_type = 0x01    # Main Mode
                flags = 0x00            # none
                msg_id = b"\x00\x00\x00\x00"
                length = struct.pack("!I", 40)

                header = init_spi + resp_spi + bytes([next_payload, version, exchange_type, flags]) + msg_id + length

            
                sa_payload = b"\x00"*12

                pkt = header + sa_payload

                dkcg = IP(dst=args.target)/UDP(dport=500)/Raw(pkt)
                resp = sr1(dkcg,timeout=1, verbose=0)

                if resp is None:
                    print("porta 500 è open/filtred")

                elif resp.haslayer(UDP):
                    print("brosky 500 è aperta")

                elif resp.haslayer(ICMP):
                    if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                        print("la port 500 è chiusa brosky")

                else:
                    print("è successo qualcosa che non era previsto, perfavore riprovare la scansione")



            case 1900:
                payload = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST:239.255.255.250:1900\r\n"
                    "MAN:\"ssdp:discover\"\r\n"
                    "MX:1\r\n"
                    "ST:ssdp:all\r\n"
                    "\r\n"
                    ).encode()
            
                dcg = IP(dst=args.target)/UDP(sport=50001, dport=1900)/Raw(payload)
                resp = sr1(dcg, timeout=4, verbose=0)

                if resp is None:
                    print("la porta 1900 è filtrata")

                elif resp.haslayer(UDP):
                    print("la porta 1900 èaperta")

                elif resp.haslayer(ICMP):
                    if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                        print("la port 1900 è chiusa ")

                else:
                    print("è successo qualcosa che non era previsto, perfavore riprovare la scansione")


            case _:
                duc = IP(dst=args.target)/UDP(sport=50007, dport=x)
                ans, unans = sr(duc, timeout=2, verbose=0)
                
                for snd, rcv in ans:
                    port = snd[UDP].dport
                    
                    try:
                        if rcv.haslayer(UDP):
                            print(f"Porta {port} aperta")
                        elif rcv.haslayer(ICMP):
                            if rcv[ICMP].type == 3 and rcv[ICMP].code == 3:
                                porte_chiuse += 1
                        else:
                            print("ce stato un problema, perfavore irrpova la scansione")

                    except Exception as e:
                        print(f"Errore nella gestione della risposta per la porta {port}: {e}")
                        
                        # porte senza risposta
                        
                        for pkt in unans:
                            try:
                                port = pkt[UDP].dport
                                print(f"Porta {port} OPEN|FILTERED")
                                    
                            except Exception as e:
                                print(f"Errore nell'elaborazione pacchetto non risposto: {e}")

    # riepilogo finale
    print("\n----- RISULTATO -----")
    print(f"Porte chiuse:   {porte_chiuse}")
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
        "udp:\n"
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
udp_cmd = sub.add_parser("udp")

#----------syn-------------

syn_cmd.add_argument("-t","--target",required=True)
syn_cmd.add_argument("-p","--ports", type=parse_ports)
syn_cmd.add_argument("-p-","--allports", action="store_true")
syn_cmd.set_defaults(func=syn)

#------------normal----------
porte_cmd.add_argument("-t","--target",required=True)
porte_cmd.add_argument("-p","--ports",type=parse_ports)
porte_cmd.add_argument("-p-","--allports",action="store_true")
porte_cmd.set_defaults(func=normal)

#-------------UDP--------------
udp_cmd.add_argument("-t","--target", required=True)
udp_cmd.add_argument("-p","--ports",type=parse_ports)
udp_cmd.add_argument("-p-","--allports",action="store_true")
udp_cmd.set_defaults(func=udp)

#---------fine--------
args = parser.parse_args()
args.func(args)