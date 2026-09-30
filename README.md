# Análise de Tráfego de Rede — Wireshark, tcpdump e Scapy

Ferramentas e roteiros para capturar tráfego de rede com **tcpdump**, inspecionar no **Wireshark** e gerar estatísticas automáticas com **Python + Scapy**, cobrindo ICMP, DNS, HTTP, HTTPS, DHCP, ARP e o handshake TCP.

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-4B5563?style=flat-square)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)

---

## O que o projeto faz

| Script | Função |
|---|---|
| `scripts/capture_traffic.sh` | Menu interativo que lista as interfaces de rede, aplica o filtro do cenário escolhido e grava a captura em `captures/*.pcap`. Ao final, oferece rodar a análise automática. |
| `scripts/analyze_pcap.py` | Lê um arquivo `.pcap` e gera um relatório no terminal com contagem por protocolo, top IPs e portas de origem e destino, principais conversas, flags TCP e alertas simples de segurança. |

**Cenários de captura disponíveis no menu:**

| # | Cenário | Filtro tcpdump |
|---|---|---|
| 1 | Ping (ICMP) | `icmp` |
| 2 | Consultas DNS | `port 53` |
| 3 | HTTP | `port 80` |
| 4 | HTTPS / TLS | `port 443` |
| 5 | DHCP | `port 67 or port 68` |
| 6 | Handshake TCP | pacotes com flag SYN ou ACK |
| 7 | ARP | `arp` |
| 8 | Personalizado | filtro digitado pelo usuário |

**Alertas do analisador** (heurísticas simples, para estudo):
- volume alto de pacotes SYN, que pode indicar SYN flood ou varredura de portas;
- muitas conexões encerradas com RST;
- tráfego DNS sem criptografia;
- volume alto de ARP, que pode indicar varredura ou ARP spoofing.

## Estrutura

```
wireshark-traffic-analysis/
├── requirements.txt
└── scripts/
    ├── capture_traffic.sh   # Captura guiada com tcpdump
    └── analyze_pcap.py      # Relatório estatístico com Scapy
```

As capturas são salvas em `captures/`, criada automaticamente na primeira execução.

## Requisitos

- Linux com `tcpdump` (e Wireshark para a análise visual)
- Python 3.8+

```bash
sudo apt install tcpdump wireshark -y
pip install -r requirements.txt
```

## Como usar

```bash
git clone https://github.com/Heitormeira/wireshark-traffic-analysis.git
cd wireshark-traffic-analysis
chmod +x scripts/capture_traffic.sh
./scripts/capture_traffic.sh
```

Com a captura rodando, gere tráfego em outro terminal, por exemplo `ping -c 5 8.8.8.8`, `nslookup github.com` ou `curl https://example.com`, e pare com `Ctrl+C`.

Para analisar qualquer arquivo `.pcap`, inclusive os exportados pelo Wireshark:

```bash
python3 scripts/analyze_pcap.py captures/02_dns_queries.pcap
python3 scripts/analyze_pcap.py captures/02_dns_queries.pcap -v   # detalha os 20 primeiros pacotes
```

## O que observar em cada cenário

| Cenário | Pontos de análise no Wireshark |
|---|---|
| ICMP | Echo Request e Echo Reply, TTL, tempo de resposta |
| DNS | Consulta e resposta, registros A e AAAA, flags de recursão; o conteúdo trafega em texto claro |
| HTTP | Handshake TCP, requisição GET e cabeçalhos visíveis em texto claro |
| HTTPS | Client Hello, Server Hello, certificado e dados de aplicação criptografados |
| DHCP | Sequência DORA: Discover, Offer, Request e Ack |
| TCP | SYN, SYN-ACK e ACK, números de sequência e de confirmação, encerramento com FIN ou RST |
| ARP | Requisições em broadcast e respostas; respostas não solicitadas podem indicar spoofing |

**Filtros de exibição úteis:** `dns`, `http`, `tls.handshake`, `arp`, `ip.addr == 8.8.8.8`, `tcp.port == 443`, `tcp.flags.syn == 1 && tcp.flags.ack == 0`, `tcp.flags.reset == 1`

## Próximos passos

- Publicar capturas de exemplo e relatórios de análise de cada cenário
- Exportar o relatório do analisador em CSV ou JSON
- Detectar de forma específica respostas ARP duplicadas para o mesmo IP

## Autor

**Heitor Meira**, estudante de Ciência da Computação na UNICAP
[LinkedIn](https://linkedin.com/in/heitormeira) · [GitHub](https://github.com/Heitormeira)

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
