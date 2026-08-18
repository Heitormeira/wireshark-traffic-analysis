# Análise de Tráfego de Rede — Wireshark + Casos Práticos

> Captura, análise e documentação de tráfego de rede real em diferentes cenários, identificando protocolos, vulnerabilidades e comportamentos

## 📋 Objetivo

Este projeto demonstra na prática como:
- **Capturar pacotes de rede** em tempo real
- **Analisar protocolos** (TCP, UDP, DNS, HTTP, HTTPS, DHCP, ARP)
- **Identificar anomalias** e comportamentos suspeitos
- **Compreender segurança de rede** através de exemplos reais
- **Documentar findings** de forma profissional

## 🔬 O que é Wireshark?

**Wireshark** é um analisador de protocolos de rede de código aberto que permite:
- Capturar pacotes em tempo real
- Examinar dados no nível do byte
- Filtrar e buscar pacotes específicos
- Visualizar fluxos de dados
- Exportar e comparar capturas
- Identificar problemas de rede

## 📦 Pré-requisitos

```bash
# Atualizar pacotes
sudo apt update && sudo apt upgrade -y

# Instalar Wireshark
sudo apt install wireshark -y

# Instalar ferramentas complementares
sudo apt install tcpdump tshark iputils-ping curl wget netcat-openbsd net-tools -y

# Instalar Python e dependências para análise
sudo apt install python3 python3-pip -y
pip install scapy dpkt

# Dar permissão a usuário não-root para capturar pacotes
sudo usermod -aG wireshark $USER
sudo usermod -aG tcpdump $USER
newgrp wireshark

# Opcional: Mininet (para lab simulado)
sudo apt install mininet -y
```

## 📂 Estrutura do Projeto

```
wireshark-traffic-analysis/
├── README.md                          # Este arquivo
├── captures/                          # Arquivos .pcap de captura
│   ├── 01_basic_ping.pcap
│   ├── 02_dns_queries.pcap
│   ├── 03_http_traffic.pcap
│   ├── 04_https_handshake.pcap
│   ├── 05_dhcp_exchange.pcap
│   ├── 06_arp_spoofing_demo.pcap
│   └── 07_tcp_three_way_handshake.pcap
├── scripts/
│   ├── capture_traffic.sh             # Script para capturar pacotes
│   ├── analyze_pcap.py                # Análise programática de .pcap
│   ├── generate_traffic.py            # Gerar tráfego para análise
│   └── filter_examples.sh             # Exemplos de filtros Wireshark
├── docs/
│   ├── PROTOCOLOS.md                  # Explicação de cada protocolo
│   ├── FILTROS.md                     # Referência de filtros
│   ├── ANALISE_CASOS.md               # Análise detalhada de casos
│   ├── TCP_IP_STACK.md                # Camadas OSI e TCP/IP
│   └── SEGURANCA.md                   # Riscos e vulnerabilidades
├── reports/
│   ├── report_01_basic_connectivity.md
│   ├── report_02_dns_analysis.md
│   ├── report_03_http_security.md
│   └── report_04_network_anomalies.md
└── images/
    ├── wireshark_gui.png              # Screenshots da interface
    ├── packet_structure.png
    └── tcp_handshake.png
```

## 🚀 Como Usar

### 1. Clonar o Repositório

```bash
git clone https://github.com/heitormeira/wireshark-traffic-analysis.git
cd wireshark-traffic-analysis
```

### 2. Instalar Dependências

```bash
chmod +x scripts/*.sh
pip install -r requirements.txt
```

### 3. Executar Capturas Básicas

#### 3.1 Captura de Ping (ICMP)

```bash
# Em um terminal: iniciar captura
sudo tcpdump -i eth0 -w captures/01_basic_ping.pcap icmp

# Em outro terminal: gerar tráfego
ping 8.8.8.8 -c 5

# Parar captura (Ctrl+C) e abrir no Wireshark
wireshark captures/01_basic_ping.pcap &
```

**O que analisar:**
- Pacotes ECHO REQUEST (ping enviado)
- Pacotes ECHO REPLY (resposta)
- TTL (Time To Live)
- Tamanho do pacote

#### 3.2 Captura de DNS

```bash
# Iniciar captura de DNS
sudo tcpdump -i eth0 -w captures/02_dns_queries.pcap port 53

# Gerar tráfego DNS
nslookup google.com
nslookup github.com

# Analisar no Wireshark
wireshark captures/02_dns_queries.pcap &
```

**O que analisar:**
- Query DNS (A record para google.com)
- Response DNS com IP resolvido
- Flags (Standard Query, Recursion Desired)
- Resource Records

#### 3.3 Captura de HTTP

```bash
# Iniciar captura
sudo tcpdump -i eth0 -w captures/03_http_traffic.pcap port 80

# Gerar tráfego HTTP
curl -v http://httpbin.org/get

# Analisar
wireshark captures/03_http_traffic.pcap &
```

**O que analisar:**
- TCP Three-Way Handshake (SYN, SYN-ACK, ACK)
- HTTP GET Request (texto puro — INSEGURO!)
- HTTP Response com status code
- Sequence numbers e ACK numbers

#### 3.4 Captura de HTTPS

```bash
# Iniciar captura
sudo tcpdump -i eth0 -w captures/04_https_handshake.pcap port 443

# Gerar tráfego HTTPS
curl -v https://httpbin.org/get

# Analisar
wireshark captures/04_https_handshake.pcap &
```

**O que analisar:**
- TLS/SSL Handshake
- Client Hello, Server Hello
- Certificate Exchange
- Dados criptografados (payload encriptado)

#### 3.5 Captura de DHCP

```bash
# Iniciar captura
sudo tcpdump -i eth0 -w captures/05_dhcp_exchange.pcap port 67 or port 68

# Renovar DHCP (requer privilégios)
sudo dhclient -r
sudo dhclient

# Analisar
wireshark captures/05_dhcp_exchange.pcap &
```

**O que analisar:**
- DHCP DISCOVER (cliente pedindo IP)
- DHCP OFFER (servidor oferecendo IP)
- DHCP REQUEST (cliente confirmando)
- DHCP ACK (servidor confirmando)

#### 3.6 Captura de TCP Handshake

```bash
# Iniciar captura
sudo tcpdump -i eth0 -w captures/07_tcp_three_way_handshake.pcap -A

# Gerar tráfego
telnet example.com 80
(Ctrl+C para sair)

# Analisar
wireshark captures/07_tcp_three_way_handshake.pcap &
```

**O que analisar:**
- SYN (Synchronization) - cliente iniciando
- SYN-ACK (Synchronization + Acknowledgment) - servidor respondendo
- ACK (Acknowledgment) - cliente confirmando
- Sequence numbers e flags TCP

### 4. Filtros Úteis no Wireshark

```
# Protocolos específicos
ip              # Todos os pacotes IP
tcp             # Pacotes TCP
udp             # Pacotes UDP
dns             # Pacotes DNS
http            # Pacotes HTTP
https           # Pacotes HTTPS
arp             # Pacotes ARP

# Por IP
ip.src == 192.168.1.100       # Origem específica
ip.dst == 8.8.8.8             # Destino específico
ip.addr == 192.168.1.100      # Qualquer um (origem ou destino)

# Por porta
tcp.port == 80                # Porta TCP 80
tcp.dstport == 443            # Porta destino 443
udp.srcport == 53             # Porta origem DNS

# Combinações
tcp.port == 80 and ip.src == 192.168.1.100
dns and ip.dst == 8.8.8.8

# Por comprimento de pacote
frame.len > 1000              # Pacotes maiores que 1000 bytes
frame.len < 100               # Pacotes menores que 100 bytes

# Flags TCP
tcp.flags.syn == 1            # Apenas SYN
tcp.flags.reset == 1          # Conexões resetadas
```

## 📊 Análise de Casos Práticos

### Caso 1: Comunicação Normal (HTTP)

1. **Capture o tráfego:**
```bash
sudo tcpdump -i eth0 -w test_http.pcap host example.com
curl http://example.com
```

2. **Analise no Wireshark:**
   - Localize os pacotes TCP (porta 80)
   - Veja o Three-Way Handshake
   - Examine o pedido GET (texto puro!)
   - Veja a resposta HTTP

3. **Conclusão:** HTTP é inseguro — dados visíveis em trânsito

### Caso 2: Comunicação Segura (HTTPS)

1. **Capture:**
```bash
sudo tcpdump -i eth0 -w test_https.pcap host example.com
curl https://example.com
```

2. **Analise:**
   - Veja TLS Handshake
   - Dados são **criptografados** (Application Data)
   - Não consegue ver o conteúdo da requisição

3. **Conclusão:** HTTPS protege dados em trânsito

### Caso 3: Resolução de Nomes (DNS)

1. **Capture:**
```bash
sudo tcpdump -i eth0 -w test_dns.pcap port 53
nslookup google.com
```

2. **Analise:**
   - Query: "Qual é o IP de google.com?"
   - Response: "É 142.251.xx.xxx"
   - Note: DNS é texto puro (pode ser espionado!)

3. **Conclusão:** Use DNS over HTTPS (DoH) para privacidade

## 🔐 Segurança — Vulnerabilidades Encontradas

### 1. **ARP Spoofing**
```bash
# Captura mostraria intrusão
# sudo tcpdump -i eth0 -w arp_attack.pcap arp
```
- Atacante finge ser gateway
- Intercepta tráfego das vítimas
- **Solução:** Usar ARP snooping, DHCP snooping

### 2. **DNS Spoofing**
- Atacante responde query DNS antes do servidor legítimo
- Vítima acessa site malicioso
- **Solução:** DNS over HTTPS, DNSSEC

### 3. **Man-in-the-Middle (MITM) em HTTP**
- Atacante captura HTTP → vê senhas, dados
- **Solução:** Sempre usar HTTPS

### 4. **TCP Connection Hijacking**
- Se capturar Sequence Numbers, pode injetar pacotes
- **Solução:** Use HTTPS (TCP + TLS)

## 📈 Exportar e Comparar Análises

### Exportar Pacotes para CSV

```
Wireshark GUI:
1. File → Export Packet Dissections → As CSV
2. Selecionar campos desejados
3. Salvar arquivo
```

### Converter PCAP para Texto

```bash
# Método 1: tshark
tshark -r capture.pcap -T text > output.txt

# Método 2: tcpdump
tcpdump -r capture.pcap -A > output.txt

# Método 3: Wireshark CLI
wireshark -r capture.pcap -o 'gui.column.format:"Number","Src IP","Dest IP","Protocol","Info"' -O text
```

### Análise Programática (Python)

```python
from scapy.all import rdpcap

# Ler arquivo PCAP
packets = rdpcap('capture.pcap')

# Iterar sobre pacotes
for pkt in packets:
    if pkt.haslayer(IP):
        print(f"Src: {pkt[IP].src} → Dest: {pkt[IP].dst}")
        if pkt.haslayer(TCP):
            print(f"  Porta: {pkt[TCP].sport} → {pkt[TCP].dport}")
```

## 📚 Conceitos Teóricos

### Camadas OSI

| Camada | Nome | Exemplos | Unidade |
|--------|------|----------|---------|
| 7 | Aplicação | HTTP, DNS, SMTP | Dados |
| 6 | Apresentação | Criptografia, Compressão | Dados |
| 5 | Sessão | Gerenciamento de Sessão | Dados |
| 4 | Transporte | TCP, UDP | Segmento/Datagrama |
| 3 | Rede | IP, ICMP | Pacote |
| 2 | Enlace | Ethernet, ARP, MAC | Frame |
| 1 | Física | Cabos, Fibra | Bits |

### TCP vs UDP

| Aspecto | TCP | UDP |
|--------|-----|-----|
| Confiável | Sim | Não |
| Ordenação | Garantida | Não |
| Handshake | Sim (3-way) | Não |
| Velocidade | Mais lenta | Mais rápida |
| Uso | HTTP, FTP, SSH | DNS, VoIP, Gaming |

## 🎓 Referências & Recursos

- [Wireshark Official](https://www.wireshark.org/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [RFC 791 — Internet Protocol](https://tools.ietf.org/html/rfc791)
- [RFC 793 — Transmission Control Protocol](https://tools.ietf.org/html/rfc793)
- [RFC 1035 — Domain Names](https://tools.ietf.org/html/rfc1035)
- [OWASP — Network Testing](https://owasp.org/)

## 👨‍💻 Autor

**Heitor Meira** — Estudante de Ciência da Computação  
UNICAP — Pernambuco, Brasil

## 📄 Licença

Este projeto está sob a licença MIT. Veja `LICENSE` para detalhes.

---

**Última atualização:** Agosto 2025  
**Status:** ✅ Ativo & sendo mantido
