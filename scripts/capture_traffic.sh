#!/bin/bash
# Script para capturar tráfego de rede com tcpdump

# Cores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Função para exibir menu
show_menu() {
    echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     CAPTURA DE TRÁFEGO - WIRESHARK TRAFFIC LAB      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}\n"
    echo -e "Escolha um tipo de captura:\n"
    echo -e "  ${GREEN}1)${NC} Ping (ICMP)"
    echo -e "  ${GREEN}2)${NC} DNS Queries"
    echo -e "  ${GREEN}3)${NC} HTTP Traffic (porta 80)"
    echo -e "  ${GREEN}4)${NC} HTTPS Traffic (porta 443)"
    echo -e "  ${GREEN}5)${NC} DHCP Exchange"
    echo -e "  ${GREEN}6)${NC} TCP Handshake"
    echo -e "  ${GREEN}7)${NC} ARP Traffic"
    echo -e "  ${GREEN}8)${NC} Captura Customizada"
    echo -e "  ${GREEN}0)${NC} Sair\n"
}

# Função para selecionar interface
select_interface() {
    echo -e "\n${YELLOW}Interfaces de rede disponíveis:${NC}\n"
    
    # Listar interfaces (excluindo loopback)
    interfaces=$(ip link show | grep "^[0-9]" | grep -v "lo:" | awk '{print $2}' | sed 's/:$//')
    
    select iface in $interfaces; do
        if [ -n "$iface" ]; then
            echo -e "${GREEN}✓ Interface selecionada: $iface${NC}"
            INTERFACE=$iface
            break
        fi
    done
}

# Função para iniciar captura
start_capture() {
    local filter=$1
    local output_file=$2
    local description=$3
    
    select_interface
    
    echo -e "\n${YELLOW}Iniciando captura...${NC}"
    echo -e "${YELLOW}Descrição: $description${NC}"
    echo -e "${YELLOW}Filtro: $filter${NC}"
    echo -e "${YELLOW}Arquivo: $output_file${NC}"
    echo -e "${YELLOW}Pressione Ctrl+C para parar${NC}\n"
    
    sudo tcpdump -i $INTERFACE $filter -w "captures/$output_file"
    
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✓ Captura salva em: captures/$output_file${NC}"
        echo -e "${GREEN}✓ Para analisar no Wireshark: wireshark captures/$output_file${NC}"
    else
        echo -e "\n${RED}✗ Erro ao capturar tráfego${NC}"
    fi
}

# Función para análise automática
auto_analyze() {
    local pcap_file=$1
    
    if [ ! -f "$pcap_file" ]; then
        echo -e "${RED}✗ Arquivo não encontrado: $pcap_file${NC}"
        return
    fi
    
    echo -e "\n${YELLOW}Analisando arquivo com Python/Scapy...${NC}\n"
    python3 scripts/analyze_pcap.py "$pcap_file"
}

# Main menu loop
while true; do
    show_menu
    read -p "Opção: " choice
    
    case $choice in
        1)
            echo -e "\n${YELLOW}Você selecionou: Captura de Ping (ICMP)${NC}"
            start_capture "icmp" "01_basic_ping.pcap" "Captura de ICMP (ping)"
            ;;
        2)
            echo -e "\n${YELLOW}Você selecionou: DNS Queries${NC}"
            start_capture "port 53" "02_dns_queries.pcap" "Captura de DNS (porta 53)"
            ;;
        3)
            echo -e "\n${YELLOW}Você selecionou: HTTP Traffic${NC}"
            start_capture "port 80" "03_http_traffic.pcap" "Captura de HTTP (porta 80)"
            ;;
        4)
            echo -e "\n${YELLOW}Você selecionou: HTTPS Traffic${NC}"
            start_capture "port 443" "04_https_handshake.pcap" "Captura de HTTPS (porta 443)"
            ;;
        5)
            echo -e "\n${YELLOW}Você selecionou: DHCP Exchange${NC}"
            start_capture "port 67 or port 68" "05_dhcp_exchange.pcap" "Captura de DHCP"
            ;;
        6)
            echo -e "\n${YELLOW}Você selecionou: TCP Handshake${NC}"
            start_capture "tcp[tcpflags] & tcp-syn != 0 or tcp[tcpflags] & tcp-ack != 0" "07_tcp_three_way_handshake.pcap" "Captura de TCP Handshake"
            ;;
        7)
            echo -e "\n${YELLOW}Você selecionou: ARP Traffic${NC}"
            start_capture "arp" "06_arp_traffic.pcap" "Captura de ARP"
            ;;
        8)
            echo -e "\n${YELLOW}Você selecionou: Captura Customizada${NC}"
            read -p "Digite o filtro tcpdump: " custom_filter
            read -p "Digite o nome do arquivo (ex: capture.pcap): " custom_file
            start_capture "$custom_filter" "$custom_file" "Captura customizada"
            ;;
        0)
            echo -e "\n${GREEN}Saindo...${NC}\n"
            exit 0
            ;;
        *)
            echo -e "\n${RED}Opção inválida! Tente novamente.${NC}"
            ;;
    esac
    
    # Perguntar se quer analisar o arquivo
    read -p "Deseja analisar o arquivo capturado? (s/n): " analyze_choice
    if [[ "$analyze_choice" == "s" || "$analyze_choice" == "S" ]]; then
        read -p "Digite o nome do arquivo (ex: 01_basic_ping.pcap): " file_to_analyze
        auto_analyze "captures/$file_to_analyze"
    fi
done
