#!/usr/bin/env python3
"""
Analisador de PCAP - Script de análise de tráfego capturado

Este script lê arquivos .pcap gerados por tcpdump/Wireshark e
extrai informações úteis sobre o tráfego de rede.
"""

import sys
import argparse
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, ICMP
from collections import defaultdict
from datetime import datetime


def analyze_pcap(pcap_file, verbose=False):
    """Analisar arquivo PCAP e extrair informações"""
    
    print(f"\n{'='*70}")
    print(f"ANÁLISE DE TRÁFEGO PCAP")
    print(f"{'='*70}\n")
    
    print(f"📂 Arquivo: {pcap_file}")
    print(f"⏰ Análise iniciada em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"❌ Erro ao ler arquivo: {e}")
        return
    
    # Contadores
    total_packets = len(packets)
    ip_packets = 0
    tcp_packets = 0
    udp_packets = 0
    dns_packets = 0
    arp_packets = 0
    icmp_packets = 0
    
    # Dicionários para análise
    src_ips = defaultdict(int)
    dst_ips = defaultdict(int)
    protocols = defaultdict(int)
    src_ports = defaultdict(int)
    dst_ports = defaultdict(int)
    conversations = defaultdict(int)
    
    print(f"📊 Total de pacotes: {total_packets}\n")
    
    # Processar pacotes
    for pkt in packets:
        # IP
        if pkt.haslayer(IP):
            ip_packets += 1
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            
            src_ips[src_ip] += 1
            dst_ips[dst_ip] += 1
            
            # Conversações (src -> dst)
            conversation = f"{src_ip} → {dst_ip}"
            conversations[conversation] += 1
            
            # TCP
            if pkt.haslayer(TCP):
                tcp_packets += 1
                protocols['TCP'] += 1
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                src_ports[src_port] += 1
                dst_ports[dst_port] += 1
                
                # Checar flags TCP
                if pkt[TCP].flags.S:  # SYN
                    protocols['TCP-SYN'] += 1
                if pkt[TCP].flags.A:  # ACK
                    protocols['TCP-ACK'] += 1
                if pkt[TCP].flags.F:  # FIN
                    protocols['TCP-FIN'] += 1
                if pkt[TCP].flags.R:  # RST
                    protocols['TCP-RST'] += 1
            
            # UDP
            elif pkt.haslayer(UDP):
                udp_packets += 1
                protocols['UDP'] += 1
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                src_ports[src_port] += 1
                dst_ports[dst_port] += 1
                
                # DNS (porta 53)
                if pkt.haslayer(DNS):
                    dns_packets += 1
                    protocols['DNS'] += 1
                    if verbose:
                        print(f"   🔍 DNS Query/Response detectado")
            
            # ICMP
            elif pkt.haslayer(ICMP):
                icmp_packets += 1
                protocols['ICMP'] += 1
        
        # ARP
        elif pkt.haslayer(ARP):
            arp_packets += 1
            protocols['ARP'] += 1
    
    # Exibir estatísticas gerais
    print("┌─ ESTATÍSTICAS GERAIS ─────────────────────────────┐")
    print(f"│ Total de Pacotes:        {total_packets:>30} │")
    print(f"│ Pacotes IP:              {ip_packets:>30} │")
    print(f"│ Pacotes TCP:             {tcp_packets:>30} │")
    print(f"│ Pacotes UDP:             {udp_packets:>30} │")
    print(f"│ Pacotes ICMP:            {icmp_packets:>30} │")
    print(f"│ Pacotes DNS:             {dns_packets:>30} │")
    print(f"│ Pacotes ARP:             {arp_packets:>30} │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # IPs de origem
    print("┌─ TOP IPs DE ORIGEM ───────────────────────────────┐")
    for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
        percentage = (count / total_packets) * 100
        print(f"│ {ip:>15} : {count:>6} pacotes ({percentage:>5.1f}%) │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # IPs de destino
    print("┌─ TOP IPs DE DESTINO ──────────────────────────────┐")
    for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
        percentage = (count / total_packets) * 100
        print(f"│ {ip:>15} : {count:>6} pacotes ({percentage:>5.1f}%) │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # Portas de origem
    print("┌─ TOP PORTAS DE ORIGEM ────────────────────────────┐")
    for port, count in sorted(src_ports.items(), key=lambda x: x[1], reverse=True)[:5]:
        percentage = (count / total_packets) * 100
        print(f"│ Porta {port:>6}: {count:>6} pacotes ({percentage:>5.1f}%) │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # Portas de destino
    print("┌─ TOP PORTAS DE DESTINO ───────────────────────────┐")
    for port, count in sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:5]:
        service = "HTTP" if port == 80 else "HTTPS" if port == 443 else "DNS" if port == 53 else "SSH" if port == 22 else "?"
        percentage = (count / total_packets) * 100
        print(f"│ Porta {port:>6} ({service:>5}): {count:>4} pacotes ({percentage:>5.1f}%) │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # Conversações
    print("┌─ TOP CONVERSAÇÕES (IP Source → IP Dest) ──────────┐")
    for conv, count in sorted(conversations.items(), key=lambda x: x[1], reverse=True)[:5]:
        percentage = (count / total_packets) * 100
        print(f"│ {conv:>35}: {count:>4} ({percentage:>5.1f}%) │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # Protocolos
    print("┌─ DISTRIBUIÇÃO DE PROTOCOLOS ──────────────────────┐")
    for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_packets) * 100
        print(f"│ {proto:>15}: {count:>6} pacotes ({percentage:>5.1f}%) │")
    print("└────────────────────────────────────────────────────┘\n")
    
    # Análise de segurança
    print("┌─ ANÁLISE DE SEGURANÇA ────────────────────────────┐")
    
    tcp_syn = protocols.get('TCP-SYN', 0)
    tcp_rst = protocols.get('TCP-RST', 0)
    
    if tcp_syn > 10:
        print(f"│ ⚠️  Muitos pacotes SYN detectados ({tcp_syn})         │")
        print(f"│    → Possível SYN flood attack?                 │")
    
    if tcp_rst > 5:
        print(f"│ ⚠️  Múltiplas conexões resetadas ({tcp_rst})         │")
        print(f"│    → Conexões não completadas                   │")
    
    if dns_packets > 0:
        print(f"│ ℹ️  Tráfego DNS detectado ({dns_packets} pacotes)      │")
        print(f"│    → Verificar se usando DoH para privacidade   │")
    
    if arp_packets > 10:
        print(f"│ ℹ️  Tráfego ARP elevado ({arp_packets} pacotes)       │")
        print(f"│    → Possível ARP scan ou spoofing?            │")
    
    print("└────────────────────────────────────────────────────┘\n")
    
    print(f"✅ Análise concluída!\n")
    
    # Gerar relatório detalhado se verbose
    if verbose:
        print("\n" + "="*70)
        print("ANÁLISE DETALHADA DE PACOTES")
        print("="*70 + "\n")
        
        for idx, pkt in enumerate(packets[:20], 1):  # Mostrar primeiros 20
            print(f"\n📦 Pacote #{idx}:")
            if pkt.haslayer(IP):
                print(f"   IP Src: {pkt[IP].src} → IP Dst: {pkt[IP].dst}")
                if pkt.haslayer(TCP):
                    print(f"   TCP Src Port: {pkt[TCP].sport} → TCP Dst Port: {pkt[TCP].dport}")
                    flags = []
                    if pkt[TCP].flags.S: flags.append("SYN")
                    if pkt[TCP].flags.A: flags.append("ACK")
                    if pkt[TCP].flags.F: flags.append("FIN")
                    if pkt[TCP].flags.R: flags.append("RST")
                    print(f"   Flags: {', '.join(flags) if flags else 'None'}")
                elif pkt.haslayer(UDP):
                    print(f"   UDP Src Port: {pkt[UDP].sport} → UDP Dst Port: {pkt[UDP].dport}")


def main():
    parser = argparse.ArgumentParser(
        description="Analisador de arquivos PCAP com Scapy"
    )
    parser.add_argument('pcap_file', help='Caminho para arquivo .pcap')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Modo verbose (mostrar pacotes detalhados)')
    
    args = parser.parse_args()
    
    analyze_pcap(args.pcap_file, verbose=args.verbose)


if __name__ == '__main__':
    main()
