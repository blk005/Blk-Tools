#!/usr/bin/env python3
"""
BLK - SMTP ENUM
================
Ferramenta de enumeração de serviços em rede via banner grabbing e
sondas específicas de protocolo (VRFY no SMTP, login anônimo no FTP,
HEAD request no HTTP, etc).

Modos de uso:
    ./smtpenum.py 172.16.1.5
    ./smtpenum.py 172.16.1.5 --portas 22,25,80
    ./smtpenum.py 172.16.1.5 --timeout 3

Flags:
    host                 IP ou hostname do alvo (obrigatorio)
    -p, --portas         Lista de portas especificas, separadas por
                          virgula (padrao: lista de portas comuns)
    --timeout N          Timeout de conexao em segundos (padrao: 5)
"""

import argparse
import re
import socket

VERMELHO = "\033[91m"
VERDE = "\033[92m"
AMARELO = "\033[93m"
CIANO = "\033[96m"
CINZA = "\033[90m"
BRANCO = "\033[97m"
NEGRITO = "\033[1m"
RESET = "\033[0m"

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def limpar_ansi(texto):
    """Remove os codigos de cor ANSI de uma string (pra salvar texto limpo em arquivo)."""
    return ANSI_RE.sub("", texto)


BANNER = r"""
██████╗ ██╗     ██╗  ██╗
██╔══██╗██║     ██║ ██╔╝
██████╔╝██║     █████╔╝
██╔══██╗██║     ██╔═██╗
██████╔╝███████╗██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝
        SMTP ENUM
""".strip("\n")


def imprimir_banner():
    """Mostra o banner em vermelho brilhante, com um resumo bonito de uso logo abaixo."""
    print(f"{VERMELHO}{NEGRITO}{BANNER}{RESET}\n")

    print(f"{CIANO}{NEGRITO}Enumeracao multi-servico via banner grabbing e sondas de protocolo.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  FINALIDADE{RESET}")
    print(f"{BRANCO}  Conecta num host em varias portas comuns {CINZA}(FTP, SSH, SMTP, HTTP,{RESET}")
    print(f"{BRANCO}  MySQL, RDP...){RESET}{BRANCO}, captura o banner de cada servico encontrado{RESET}")
    print(f"{BRANCO}  e roda sondas especificas em alguns protocolos {CINZA}(VRFY no SMTP,{RESET}")
    print(f"{BRANCO}  login anonimo no FTP, HEAD request no HTTP){RESET}{BRANCO}.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  COMO USAR{RESET}")
    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtpenum.py{RESET}")
    print(f"    {CINZA}modo interativo -- pergunta o host se voce nao passar.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtpenum.py{RESET} {CIANO}172.16.1.5{RESET}")
    print(f"    {CINZA}direto -- testa todas as portas comuns nesse host.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtpenum.py{RESET} {CIANO}172.16.1.5 --portas 22,25,80{RESET}")
    print(f"    {CINZA}testa so as portas especificadas.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtpenum.py --help{RESET}")
    print(f"    {CINZA}manual completo, com a lista de portas e protocolos suportados.{RESET}")
    print(f"\n{CINZA}{'─' * 74}{RESET}\n")

# Portas comuns e o nome do servico associado.
# Usado como lista padrao quando o usuario nao passa --portas.
SERVICOS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
}


def banner_grab(host, port, timeout):
    """Conecta na porta e tenta capturar o banner inicial (se houver)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            data = s.recv(1024)
        except socket.timeout:
            data = b""
        return s, data
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, None


def enum_smtp(s):
    """Tenta confirmar contas de usuario via comando VRFY."""
    resultados = []
    for usuario in ("root", "admin", "postmaster"):
        try:
            s.send(f"VRFY {usuario}\r\n".encode())
            resp = s.recv(1024).decode(errors="ignore").strip()
            resultados.append(f"  VRFY {usuario:<10} -> {resp}")
        except (socket.timeout, OSError):
            break
    return resultados


def enum_ftp(s):
    """Verifica se o servidor FTP aceita login anonimo."""
    resultados = []
    try:
        s.send(b"USER anonymous\r\n")
        resp1 = s.recv(1024).decode(errors="ignore").strip()
        resultados.append(f"  USER anonymous -> {resp1}")

        s.send(b"PASS anonymous@\r\n")
        resp2 = s.recv(1024).decode(errors="ignore").strip()
        resultados.append(f"  PASS anonymous@ -> {resp2}")

        if resp2.startswith("230"):
            resultados.append(f"  {VERMELHO}[!] Login anonimo permitido!{RESET}")
    except (socket.timeout, OSError):
        pass
    return resultados


def enum_http(s, host):
    """Faz um HEAD request basico pra puxar os cabecalhos do servidor web."""
    resultados = []
    try:
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        resp = s.recv(2048).decode(errors="ignore")
        for linha in resp.splitlines()[:6]:
            if linha.strip():
                resultados.append(f"  {linha.strip()}")
    except (socket.timeout, OSError):
        pass
    return resultados


# Mapa de porta -> funcao de enumeracao especifica daquele protocolo.
# Portas que nao estao aqui usam so o banner grab generico.
SONDAS_ESPECIFICAS = {
    21: lambda s, host: enum_ftp(s),
    25: lambda s, host: enum_smtp(s),
    80: lambda s, host: enum_http(s, host),
    443: lambda s, host: enum_http(s, host),
}


def enumerar_host(host, portas, timeout):
    linhas = []  # buffer com as linhas (sem cor ANSI), usado se o usuario pedir pra salvar

    def imprimir(texto=""):
        print(texto)
        linhas.append(limpar_ansi(texto))

    imprimir(f"{NEGRITO}[*] Alvo: {host}{RESET}")
    imprimir(f"{NEGRITO}[*] Portas a testar: {', '.join(str(p) for p in portas)}{RESET}\n")

    encontrados = 0

    for porta, nome in portas.items():
        s, banner = banner_grab(host, porta, timeout)
        if s is None:
            continue

        encontrados += 1
        banner_txt = banner.decode(errors="ignore").strip() if banner else "(sem banner na conexao)"
        imprimir(f"{VERMELHO}[+] {porta}/tcp aberto{RESET} -> {nome}")
        imprimir(f"  Banner: {banner_txt}")

        sonda = SONDAS_ESPECIFICAS.get(porta)
        if sonda:
            for linha in sonda(s, host):
                imprimir(linha)

        imprimir()
        s.close()

    if encontrados == 0:
        imprimir("  Nenhum servico respondeu nas portas testadas.\n")

    imprimir(f"{NEGRITO}[*] Concluido. {encontrados} servico(s) encontrado(s) em {host}.{RESET}")

    return linhas


def perguntar_e_salvar(linhas, host):
    """Pergunta se o usuario quer salvar o resultado e, se sim, com qual nome."""
    resposta = input(f"\n{NEGRITO}Deseja gerar uma saida com esse resultado? [s/N]: {RESET}").strip().lower()
    if resposta != "s":
        return

    nome_arquivo = input(f"{NEGRITO}Nome do arquivo: {RESET}").strip()
    if not nome_arquivo:
        nome_arquivo = f"smtpenum_{host}.txt"
        print(f"  Nenhum nome informado, usando padrao: {nome_arquivo}")

    try:
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write("\n".join(linhas) + "\n")
        print(f"{VERMELHO}[+] Resultado salvo em: {nome_arquivo}{RESET}")
    except OSError as e:
        print(f"{VERMELHO}[!] Nao foi possivel salvar o arquivo: {e}{RESET}")


MANUAL = """
EXEMPLOS DE USO
---------------

  Modo interativo (pergunta o host se voce nao passar):
      python3 smtpenum.py

  Direto, testando todas as portas comuns:
      python3 smtpenum.py 172.16.1.5

  So portas especificas:
      python3 smtpenum.py 172.16.1.5 --portas 22,25,80

  Timeout maior, pra rede lenta ou instavel:
      python3 smtpenum.py 172.16.1.5 --timeout 10


PORTAS TESTADAS POR PADRAO
-----------------------------

  21    FTP      -- banner + tenta login anonimo
  22    SSH      -- so banner (a versao do SSH ja e a info util)
  23    Telnet   -- so banner
  25    SMTP     -- banner + VRFY (root, admin, postmaster)
  80    HTTP     -- banner + HEAD request (cabecalhos do servidor)
  110   POP3     -- so banner
  143   IMAP     -- so banner
  443   HTTPS    -- banner + HEAD request
  445   SMB      -- so deteccao de porta aberta
  3306  MySQL    -- banner (handshake binario)
  3389  RDP      -- so deteccao de porta aberta

  Use --portas pra restringir a varredura a portas especificas, em
  vez de testar a lista inteira.


SALVANDO O RESULTADO
----------------------

  Ao final da enumeracao, o script pergunta se voce quer gerar um
  arquivo de saida com o resultado. Se sim, pede o nome do arquivo
  (ou usa um padrao automatico, se voce deixar em branco).

  O arquivo sai sem os codigos de cor ANSI -- limpo, legivel em
  qualquer editor de texto.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="smtpenum.py",
        description=(
            "BLK - Enumeracao multi-servico via banner grabbing e sondas de protocolo.\n"
            "Conecta nas portas comuns de um host e identifica os servicos ativos."
        ),
        epilog=MANUAL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "host", metavar="HOST", nargs="?", default=None,
        help="IP ou hostname do alvo a ser enumerado (se omitido, o programa pergunta)",
    )
    parser.add_argument(
        "-p", "--portas", metavar="P1,P2,...",
        help="Lista de portas especificas, separadas por virgula (padrao: portas comuns)",
    )
    parser.add_argument(
        "--timeout", type=int, default=5, metavar="N",
        help="Timeout de conexao em segundos (padrao: 5)",
    )
    args = parser.parse_args()

    imprimir_banner()

    host = args.host
    while not host:
        host = input(f"{NEGRITO}Digite o host alvo: {RESET}").strip()
        if not host:
            print("  Host nao pode ser vazio.\n")

    if args.portas:
        portas_alvo = {}
        for p in args.portas.split(","):
            p = int(p.strip())
            portas_alvo[p] = SERVICOS.get(p, "Desconhecido")
    else:
        portas_alvo = SERVICOS

    linhas_resultado = enumerar_host(host, portas_alvo, args.timeout)
    perguntar_e_salvar(linhas_resultado, host)


if __name__ == "__main__":
    main()

