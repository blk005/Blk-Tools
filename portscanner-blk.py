#!/usr/bin/env python3
"""
BLK Port Scanner v3.0
Ferramenta de reconhecimento de rede — uso autorizado apenas.
"""

import socket
import sys
import time
import struct
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
#  CORES ANSI
# ─────────────────────────────────────────────
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
MAGENTA = "\033[95m"
GRAY    = "\033[90m"
DIM     = "\033[2m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
def print_banner():
    rows = [
        "██████╗ ██╗     ██╗  ██╗",
        "██╔══██╗██║     ██║ ██╔╝",
        "██████╔╝██║     █████╔╝",
        "██╔══██╗██║     ██╔═██╗",
        "██████╔╝███████╗██║  ██╗",
        "╚═════╝ ╚══════╝╚═╝  ╚═╝",
        "      PORT SCANNER",
    ]
    print(f"\n{RED}{BOLD}")
    for row in rows:
        print(row)
    print(RESET)

    print(f"{CYAN}{BOLD}Reconhecimento de rede via TCP, UDP e ICMP, com multithreading.{RESET}\n")

    print(f"{YELLOW}{BOLD}  FINALIDADE{RESET}")
    print(f"{WHITE}  Varre um host (ou lista de hosts) em busca de portas abertas{RESET}")
    print(f"{WHITE}  {DIM}(TCP/UDP){RESET}{WHITE}, ou descobre quais hosts estao ativos na rede{RESET}")
    print(f"{WHITE}  {DIM}(ICMP/ping){RESET}{WHITE}. Mostra progresso em tempo real, com barra,{RESET}")
    print(f"{WHITE}  ETA e banner dos serviços encontrados.{RESET}\n")

    print(f"{YELLOW}{BOLD}  COMO USAR{RESET}")
    print(f"  {GREEN}❯{RESET} {BOLD}python3 portscanner-blk.py{RESET}")
    print(f"    {DIM}modo interativo -- pergunta o alvo se voce nao passar.{RESET}\n")

    print(f"  {GREEN}❯{RESET} {BOLD}python3 portscanner-blk.py{RESET} {CYAN}192.168.1.1{RESET}")
    print(f"    {DIM}scan TCP rapido (portas 1-1024), direto no alvo informado.{RESET}\n")

    print(f"  {GREEN}❯{RESET} {BOLD}python3 portscanner-blk.py{RESET} {CYAN}192.168.1.1 -m full{RESET}")
    print(f"    {DIM}varre todas as 65535 portas TCP.{RESET}\n")

    print(f"  {GREEN}❯{RESET} {BOLD}python3 portscanner-blk.py{RESET} {CYAN}192.168.1.1 -p icmp{RESET}")
    print(f"    {DIM}so descobre se o host esta vivo (ping), sem checar portas.{RESET}\n")

    print(f"  {GREEN}❯{RESET} {BOLD}python3 portscanner-blk.py --help{RESET}")
    print(f"    {DIM}manual completo -- protocolos, modos, tuning de threads e exemplos.{RESET}")

    print(f"\n{CYAN}{DIM}{'─' * 70}{RESET}\n")


# ─────────────────────────────────────────────
#  SERVIÇOS CONHECIDOS
# ─────────────────────────────────────────────
SERVICES = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",67:"DHCP",68:"DHCP",69:"TFTP",80:"HTTP",
    88:"Kerberos",110:"POP3",111:"RPCBind",119:"NNTP",
    123:"NTP",135:"MSRPC",137:"NetBIOS",138:"NetBIOS",
    139:"NetBIOS",143:"IMAP",161:"SNMP",162:"SNMP-Trap",
    179:"BGP",194:"IRC",389:"LDAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",500:"IKE",514:"Syslog",515:"LPD",
    587:"SMTP-Sub",631:"IPP",636:"LDAPS",993:"IMAPS",
    995:"POP3S",1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",
    1521:"Oracle",1723:"PPTP",2049:"NFS",2181:"Zookeeper",
    2375:"Docker",2376:"Docker-TLS",3000:"Dev-HTTP",
    3128:"Squid",3306:"MySQL",3389:"RDP",4000:"Dev-HTTP",
    4444:"Metasploit",5000:"Dev-HTTP",5432:"PostgreSQL",
    5900:"VNC",5985:"WinRM",5986:"WinRM-S",6379:"Redis",
    6443:"K8s-API",7001:"WebLogic",8000:"HTTP-Alt",
    8080:"HTTP-Alt",8088:"HTTP-Alt",8443:"HTTPS-Alt",
    8888:"Jupyter",9000:"PHP-FPM",9090:"Prometheus",
    9200:"Elasticsearch",9300:"Elasticsearch",9418:"Git",
    11211:"Memcached",15672:"RabbitMQ",27017:"MongoDB",
    27018:"MongoDB",50070:"Hadoop",61616:"ActiveMQ",
}

def get_service(port: int) -> str:
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────
#  RESOLUÇÃO DE HOST
# ─────────────────────────────────────────────
def resolve_host(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n{RED}[!] Não foi possível resolver: {target}{RESET}")
        sys.exit(1)


# ─────────────────────────────────────────────
#  SCAN TCP (connect)
# ─────────────────────────────────────────────
def scan_tcp(host: str, port: int, timeout: float) -> tuple:
    """TCP Connect Scan — cria handshake completo. 100% preciso."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    s.settimeout(0.3)
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    pass
                return port, True, banner
    except Exception:
        pass
    return port, False, ""


# ─────────────────────────────────────────────
#  SCAN UDP
# ─────────────────────────────────────────────
# UDP não é orientado a conexão — a porta é considerada aberta
# se o host responder com dados, ou "open|filtered" se não houver
# resposta (comportamento normal de firewalls e serviços UDP).
UDP_PROBES = {
    53:  b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
         b'\x07version\x04bind\x00\x00\x10\x00\x03',  # DNS version
    161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19'
         b'\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00'
         b'\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
    123: b'\x1b' + b'\x00' * 47,   # NTP
    137: b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
         b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01',  # NetBIOS
}
DEFAULT_UDP_PROBE = b'\x00' * 8

def scan_udp(host: str, port: int, timeout: float) -> tuple:
    """
    UDP Scan — envia probe e aguarda resposta.
    Retorna 'open' se houver resposta, 'open|filtered' se não houver.
    """
    probe = UDP_PROBES.get(port, DEFAULT_UDP_PROBE)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (host, port))
            try:
                data, _ = s.recvfrom(1024)
                banner = data.decode(errors="ignore").strip()
                return port, "open", banner
            except socket.timeout:
                # sem resposta = open|filtered (comportamento UDP normal)
                return port, "open|filtered", ""
    except Exception:
        pass
    return port, "closed", ""


# ─────────────────────────────────────────────
#  SCAN ICMP (ping)
# ─────────────────────────────────────────────
# ICMP requer privilégios de root/admin para criar raw sockets.
def icmp_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def scan_icmp(host: str, timeout: float) -> tuple:
    """
    ICMP Echo Request (ping).
    Requer execução como root/administrador.
    Retorna (host, alive, rtt_ms).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW,
                           socket.IPPROTO_ICMP) as s:
            s.settimeout(timeout)
            pid = 1337 & 0xFFFF
            header = struct.pack("bbHHh", 8, 0, 0, pid, 1)
            payload = b"BLK-SCANNER"
            chk = icmp_checksum(header + payload)
            header = struct.pack("bbHHh", 8, 0, chk, pid, 1)
            packet = header + payload
            t_send = time.time()
            s.sendto(packet, (host, 0))
            s.recvfrom(1024)
            rtt = (time.time() - t_send) * 1000
            return host, True, round(rtt, 2)
    except PermissionError:
        print(f"\n{RED}[!] ICMP requer root/sudo. Execute: sudo python3 {sys.argv[0]}{RESET}")
        sys.exit(1)
    except Exception:
        pass
    return host, False, 0.0


# ─────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────
def print_open_port(proto: str, port: int, state: str, banner: str):
    service  = get_service(port)
    svc_str  = f"{CYAN}[{service}]{RESET}"
    proto_str= f"{MAGENTA}{proto.upper()}{RESET}"
    if state == "open":
        state_str = f"{GREEN}OPEN{RESET}"
    else:
        state_str = f"{YELLOW}OPEN|FILTERED{RESET}"
    banner_str = f"  {DIM}» {banner[:55]}{RESET}" if banner else ""
    print(f"  {GREEN}[+]{RESET} {proto_str} {WHITE}{BOLD}{port:<6}{RESET} {state_str}  {svc_str}{banner_str}")


# ─────────────────────────────────────────────
#  MODOS PRÉ-DEFINIDOS
# ─────────────────────────────────────────────
SCAN_MODES = {
    #        start   end    label                         threads  timeout
    "quick": (1,     1024,  "Portas comuns (1–1024)",       500,   0.5),
    "10k":   (1,    10000,  "Top 10 mil portas (1–10000)",  800,   0.5),
    "full":  (1,    65535,  "Scan completo (1–65535)",     1000,   0.4),
    "custom":(None,  None,  "Intervalo personalizado",      500,   0.5),
}


# ─────────────────────────────────────────────
#  RUN — TCP / UDP
# ─────────────────────────────────────────────
def run_port_scan(target: str, proto: str, start_port: int, end_port: int,
                  threads: int, timeout: float, mode_label: str):

    ip    = resolve_host(target)
    total = end_port - start_port + 1
    scan_fn = scan_tcp if proto == "tcp" else scan_udp

    print(f"{WHITE}  Target    :{RESET} {YELLOW}{target}{RESET}  {DIM}({ip}){RESET}")
    print(f"{WHITE}  Protocolo :{RESET} {MAGENTA}{proto.upper()}{RESET}")
    print(f"{WHITE}  Modo      :{RESET} {MAGENTA}{mode_label}{RESET}")
    print(f"{WHITE}  Portas    :{RESET} {start_port} – {end_port}  {DIM}({total} portas){RESET}")
    print(f"{WHITE}  Threads   :{RESET} {threads}")
    print(f"{WHITE}  Timeout   :{RESET} {timeout}s por porta")
    print(f"{WHITE}  Início    :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n{CYAN}{'─' * 70}{RESET}")
    print(f"  {DIM}{'PROTO':<7}{'PORTA':<8}{'ESTADO':<16}SERVIÇO{RESET}")
    print(f"{CYAN}{'─' * 70}{RESET}\n")

    open_ports = []
    done, bar_len = 0, 42
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_fn, ip, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            port, state, banner = result
            done += 1

            elapsed = time.time() - t_start
            rate    = done / elapsed if elapsed > 0 else 1
            eta     = int((total - done) / rate) if rate > 0 else 0
            pct     = done / total
            filled  = int(bar_len * pct)
            bar     = f"{'█' * filled}{'░' * (bar_len - filled)}"
            eta_str = f"ETA {eta}s" if eta > 0 else "concluindo..."
            print(f"\r  {DIM}[{bar}] {done}/{total}  {pct*100:.1f}%  {eta_str}   {RESET}",
                  end="", flush=True)

            # TCP: state é bool; UDP: state é string
            is_open = (state is True) or (state in ("open", "open|filtered"))
            if is_open:
                state_str = "open" if state is True or state == "open" else "open|filtered"
                print()
                print_open_port(proto, port, state_str, banner)
                open_ports.append(port)

    elapsed_total = time.time() - t_start
    open_ports.sort()

    print(f"\n\n{CYAN}{'─' * 70}{RESET}")
    print(f"\n  {WHITE}{BOLD}Scan finalizado!{RESET}")
    print(f"  {GREEN}Portas abertas    : {len(open_ports)}{RESET}")
    print(f"  {RED}Fechadas/filtradas: {total - len(open_ports)}{RESET}")
    print(f"  Tempo total       : {elapsed_total:.2f}s  "
          f"{DIM}({total/elapsed_total:.0f} portas/s){RESET}")
    print(f"  Finalizado em     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    if open_ports:
        print(f"  {WHITE}Abertas:{RESET}  {', '.join(str(p) for p in open_ports)}")
    print()


# ─────────────────────────────────────────────
#  RUN — ICMP
# ─────────────────────────────────────────────
def run_icmp_scan(targets: list, timeout: float, threads: int):
    print(f"{WHITE}  Protocolo :{RESET} {MAGENTA}ICMP (ping){RESET}")
    print(f"{WHITE}  Targets   :{RESET} {len(targets)} host(s)")
    print(f"{WHITE}  Timeout   :{RESET} {timeout}s por host")
    print(f"{WHITE}  Início    :{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n{CYAN}{'─' * 50}{RESET}")
    print(f"  {DIM}{'HOST':<25}{'ESTADO':<14}RTT{RESET}")
    print(f"{CYAN}{'─' * 50}{RESET}\n")

    alive = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_icmp, t, timeout): t for t in targets}
        for future in as_completed(futures):
            host, is_alive, rtt = future.result()
            if is_alive:
                print(f"  {GREEN}[+]{RESET} {WHITE}{host:<25}{RESET} {GREEN}ALIVE{RESET}    {DIM}{rtt} ms{RESET}")
                alive.append(host)
            else:
                print(f"  {RED}[-]{RESET} {DIM}{host:<25} DOWN{RESET}")

    print(f"\n{CYAN}{'─' * 50}{RESET}")
    print(f"\n  {GREEN}Hosts vivos: {len(alive)}{RESET}  /  {RED}Down: {len(targets)-len(alive)}{RESET}\n")


# ─────────────────────────────────────────────
#  MANUAL COMPLETO  (mostrado via --help)
# ─────────────────────────────────────────────
MANUAL = """
DESCRICAO
---------

  O BLK Port Scanner é uma ferramenta de reconhecimento de rede que
  suporta tres protocolos de varredura: TCP, UDP e ICMP. Utiliza
  multithreading para alta performance e exibe resultados em tempo
  real com barra de progresso e ETA.

  AVISO LEGAL: Use apenas em redes/hosts sob sua autorizacao.
  O uso nao autorizado e crime (Lei 12.737/2012 -- Brasil).


SINTAXE
-------

  python3 portscanner-blk.py <TARGET> [OPCOES]

  TARGET pode ser:
    - IP unico        192.168.1.1
    - Hostname        scanme.nmap.org
    - Lista (ICMP)    192.168.1.1,192.168.1.2,192.168.1.3

  Se TARGET for omitido, o programa pergunta interativamente.


PROTOCOLOS  (-p / --proto)
---------------------------

  tcp   -- TCP Connect Scan  (padrao)
           Realiza handshake TCP completo (SYN -> SYN-ACK -> ACK).
           Metodo mais preciso: sem falsos positivos.
           Nao requer root. Registrado nos logs do alvo.
           Ideal para: auditorias internas, pentests autorizados.

  udp   -- UDP Scan
           Envia probes especificos por servico (DNS, SNMP, NTP, etc.)
           e aguarda resposta. Sem resposta = open|filtered (normal em
           UDP, pois UDP nao confirma entrega).
           Recomendado: sudo para melhor precisao (raw ICMP errors).
           Ideal para: descoberta de DNS, SNMP, TFTP, NTP, NetBIOS.

  icmp  -- ICMP Ping / Host Discovery
           Envia Echo Request e mede RTT (Round-Trip Time).
           Requer root/sudo para criar raw sockets.
           Aceita multiplos targets separados por virgula.
           Ideal para: descobrir quais hosts estao vivos na rede.
           Nota: hosts com firewall podem bloquear ICMP (falso negativo).


MODOS DE SCAN  (-m / --mode)
-----------------------------

  quick   Portas 1-1024   | 500 threads  | Timeout 0.5s
          Cobre todas as portas "well-known" (IANA).
          Tempo estimado: 2-10 segundos.

  10k     Portas 1-10000  | 800 threads  | Timeout 0.5s
          Cobre ~99% dos servicos encontrados em ambientes reais.
          Tempo estimado: 10-40 segundos.

  full    Portas 1-65535  | 1000 threads | Timeout 0.4s
          Varredura completa. Detecta servicos em portas nao-padrao.
          Tempo estimado: 1-5 minutos (depende da rede).

  custom  Intervalo livre | 500 threads  | Timeout 0.5s
          Define start (-s) e end (-e) manualmente.
          Ex: -m custom -s 8000 -e 9000


TUNING: THREADS E TIMEOUT
--------------------------

  Threads controlam o paralelismo. Mais threads = mais rapido,
  mas consome mais CPU/memoria e pode sobrecarregar a rede/alvo.

  Recomendacoes:
    Rede local (LAN)     -> -t 1000 -T 0.3   (muito rapido)
    Rede remota (WAN)    -> -t 500  -T 1.0   (estavel)
    Host instavel/lento  -> -t 200  -T 2.0   (preciso, lento)
    Scan maximo          -> -t 1500 -T 0.2   (agressivo, LAN apenas)

  Limite pratico de threads: ~1500 (acima disso o OS comeca a
  descartar conexoes por falta de descritores de arquivo).
  Para aumentar o limite do OS: ulimit -n 65535


ENTENDENDO O RESULTADO UDP
----------------------------

  open           -- Host respondeu com dados. Porta definitivamente aberta.
  open|filtered  -- Sem resposta. Pode ser aberta (servico ativo mas
                    silencioso) ou filtrada por firewall. Normal em UDP.
  closed         -- Host respondeu com ICMP Port Unreachable.

  Servicos UDP com probes especificos (maior precisao):
    53 DNS, 123 NTP, 137 NetBIOS, 161 SNMP
  Demais portas recebem probe generico (8 bytes zerados).


ENTENDENDO O RESULTADO ICMP
-----------------------------

  ICMP nao escaneia portas -- ele descobre se o host esta ativo.
  Use antes de um scan TCP/UDP pra evitar varrer hosts desligados.

  ICMP requer privilegios de root:
    Linux/Mac:  sudo python3 portscanner-blk.py <targets> -p icmp

  Hosts podem bloquear ICMP sem estarem desligados -- um resultado
  "DOWN" nao garante que o host esta offline.


EXEMPLOS COMPLETOS
-------------------

  # Scan rapido TCP nas portas comuns
  python3 portscanner-blk.py 192.168.1.1

  # Top 10 mil portas
  python3 portscanner-blk.py 192.168.1.1 -m 10k

  # Scan completo de todas as portas
  python3 portscanner-blk.py 192.168.1.1 -m full

  # Scan completo agressivo (LAN)
  python3 portscanner-blk.py 192.168.1.1 -m full -t 1500 -T 0.2

  # Scan UDP das portas comuns
  python3 portscanner-blk.py 192.168.1.1 -p udp -m quick

  # Ping em host unico
  sudo python3 portscanner-blk.py 192.168.1.1 -p icmp

  # Ping em multiplos hosts simultaneamente
  sudo python3 portscanner-blk.py 192.168.1.1,192.168.1.2,192.168.1.254 -p icmp

  # Intervalo personalizado TCP
  python3 portscanner-blk.py 192.168.1.1 -m custom -s 8000 -e 9000

  # Apenas portas de banco de dados
  python3 portscanner-blk.py 10.0.0.5 -m custom -s 1433 -e 5432

  # Aumentar limite de arquivos abertos antes de scan full
  ulimit -n 65535 && python3 portscanner-blk.py 192.168.1.1 -m full -t 1500
"""


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="portscanner-blk.py",
        description=(
            "BLK - Reconhecimento de rede via TCP, UDP e ICMP, com multithreading.\n"
            "Varre portas abertas ou descobre hosts ativos, com progresso em tempo real."
        ),
        epilog=MANUAL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", nargs="?", default=None, metavar="TARGET",
        help="IP, hostname, ou lista separada por virgula -- ICMP (se omitido, o programa pergunta)",
    )
    parser.add_argument(
        "-p", "--proto", default="tcp", choices=["tcp", "udp", "icmp"],
        help="Protocolo de varredura (padrao: tcp)",
    )
    parser.add_argument(
        "-m", "--mode", default="quick", choices=["quick", "10k", "full", "custom"],
        help="Modo de varredura (padrao: quick)",
    )
    parser.add_argument(
        "-s", "--start", type=int, default=1, metavar="N",
        help="Porta inicial (apenas modo custom)",
    )
    parser.add_argument(
        "-e", "--end", type=int, default=1024, metavar="N",
        help="Porta final (apenas modo custom)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=None, metavar="N",
        help="Threads simultaneas (sobrescreve o padrao do modo)",
    )
    parser.add_argument(
        "-T", "--timeout", type=float, default=None, metavar="SEG",
        help="Timeout por porta/host em segundos (sobrescreve o padrao do modo)",
    )

    args = parser.parse_args()

    print_banner()

    target = args.target
    while not target:
        target = input(f"{BOLD}Digite o host (ou hosts separados por virgula, pra ICMP): {RESET}").strip()
        if not target:
            print("  Alvo nao pode ser vazio.\n")

    # ── ICMP: aceita lista de hosts ──
    if args.proto == "icmp":
        targets = [t.strip() for t in target.split(",") if t.strip()]
        timeout  = args.timeout if args.timeout else 1.5
        threads  = args.threads if args.threads else 200
        run_icmp_scan(targets, timeout, threads)
        return

    # ── TCP / UDP ──
    start_d, end_d, label, threads_d, timeout_d = SCAN_MODES[args.mode]

    if args.mode == "custom":
        start_port = args.start
        end_port   = args.end
        label      = f"Custom ({start_port}–{end_port})"
    else:
        start_port = start_d
        end_port   = end_d

    threads = args.threads if args.threads else threads_d
    timeout = args.timeout if args.timeout else timeout_d

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print(f"{RED}[!] Portas devem estar entre 1 e 65535.{RESET}")
        sys.exit(1)
    if start_port > end_port:
        start_port, end_port = end_port, start_port

    run_port_scan(target, args.proto, start_port, end_port,
                  threads, timeout, label)


if __name__ == "__main__":
    main()
