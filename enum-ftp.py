#!/usr/bin/env python3
"""
BLK FTP ENUM
============
Conecta num servidor FTP, captura o banner, tenta login anonimo
(USER ftp / PASS ftp) e lista os comandos disponiveis (HELP) e o
diretorio atual (PWD).

Modos de uso:
    ./ftpenum.py 172.16.1.108
    ./ftpenum.py 172.16.1.108 --porta 2121
    ./ftpenum.py 172.16.1.108 --timeout 3

Flags:
    host                 IP ou hostname do alvo (se omitido, o programa pergunta)
    -p, --porta N        Porta do servico FTP (padrao: 21)
    --timeout N          Timeout de conexao em segundos (padrao: 5)
"""

import argparse
import socket

VERMELHO = "\033[91m"
VERDE = "\033[92m"
AMARELO = "\033[93m"
AZUL = "\033[94m"
MAGENTA = "\033[95m"
CIANO = "\033[96m"
CINZA = "\033[90m"
BRANCO = "\033[97m"
NEGRITO = "\033[1m"
RESET = "\033[0m"

LARGURA = 72

BANNER = r"""
██████╗ ██╗     ██╗  ██╗
██╔══██╗██║     ██║ ██╔╝
██████╔╝██║     █████╔╝
██╔══██╗██║     ██╔═██╗
██████╔╝███████╗██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝
        FTP ENUM
""".strip("\n")


def topo(titulo=""):
    """Linha superior de uma caixa, com titulo opcional embutido."""
    if titulo:
        rotulo = f"─[ {titulo} ]"
        resto = LARGURA - len(rotulo) - 1
        return f"┌{rotulo}{'─' * max(resto, 1)}┐"
    return f"┌{'─' * LARGURA}┐"


def base_caixa():
    """Linha inferior de uma caixa."""
    return f"└{'─' * LARGURA}┘"


def divisor():
    """Linha fina de separacao entre secoes."""
    return f"{CINZA}{'─' * (LARGURA + 2)}{RESET}"


def imprimir_banner():
    """Mostra o banner em vermelho brilhante, com um resumo bonito de uso logo abaixo."""
    print(f"{VERMELHO}{NEGRITO}{BANNER}{RESET}\n")

    print(f"{CIANO}{NEGRITO}Enumeracao basica de FTP -- banner, login anonimo e comandos.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  FINALIDADE{RESET}")
    print(f"{BRANCO}  Conecta num servidor FTP, captura o banner de boas-vindas,{RESET}")
    print(f"{BRANCO}  tenta login anonimo {CINZA}(USER ftp / PASS ftp){BRANCO} e lista os{RESET}")
    print(f"{BRANCO}  comandos disponiveis no servidor e o diretorio atual.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  COMO USAR{RESET}")
    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 ftpenum.py{RESET}")
    print(f"    {CINZA}modo interativo -- pergunta o host se voce nao passar.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 ftpenum.py{RESET} {CIANO}172.16.1.108{RESET}")
    print(f"    {CINZA}direto -- ja roda contra o host informado.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 ftpenum.py{RESET} {CIANO}172.16.1.108 --porta 2121{RESET}")
    print(f"    {CINZA}escolhe uma porta diferente da 21 padrao.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 ftpenum.py --help{RESET}")
    print(f"    {CINZA}manual completo, com todas as flags e exemplos.{RESET}")
    print(f"\n{divisor()}")


def enviar_e_receber(s, comando, tamanho=2048):
    """Manda um comando FTP e le a resposta na hora -- nunca acumula
    duas respostas de comandos diferentes no mesmo recv()."""
    s.send(comando.encode() + b"\r\n")
    try:
        return s.recv(tamanho).decode(errors="ignore").strip()
    except socket.timeout:
        return "(sem resposta -- timeout)"


def enumerar_ftp(host, porta, timeout):
    print(f"\n{CIANO}{NEGRITO}{topo('CONECTANDO')}{RESET}")
    print(f"{CIANO}{NEGRITO}│{RESET} {BRANCO}{host}:{porta}{RESET}")
    print(f"{CIANO}{NEGRITO}{base_caixa()}{RESET}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((host, porta))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"\n{VERMELHO}[!] Falha ao conectar: {e}{RESET}")
        return

    try:
        banner = s.recv(1024).decode(errors="ignore").strip()
        print(f"\n{VERDE}{NEGRITO}{topo('BANNER')}{RESET}")
        print(f"{VERDE}│{RESET} {banner}")
        print(f"{VERDE}{base_caixa()}{RESET}")

        print(f"\n{AMARELO}{NEGRITO}{topo('LOGIN ANONIMO')}{RESET}")
        user_resp = enviar_e_receber(s, "USER ftp")
        print(f"{AMARELO}│{RESET} {CIANO}USER ftp{RESET} -> {user_resp}")

        pass_resp = enviar_e_receber(s, "PASS ftp")
        print(f"{AMARELO}│{RESET} {CIANO}PASS ftp{RESET} -> {pass_resp}")
        print(f"{AMARELO}{base_caixa()}{RESET}")

        if "230" in pass_resp:
            print(f"\n{VERMELHO}{NEGRITO}[!] Login anonimo permitido!{RESET}")

        print(f"\n{MAGENTA}{NEGRITO}{topo('COMANDOS E DIRETORIO')}{RESET}")
        help_resp = enviar_e_receber(s, "HELP")
        print(f"{MAGENTA}│{RESET} {NEGRITO}HELP{RESET}\n{help_resp}\n")

        pwd_resp = enviar_e_receber(s, "PWD")
        print(f"{MAGENTA}│{RESET} {NEGRITO}PWD{RESET}\n{pwd_resp}")
        print(f"{MAGENTA}{base_caixa()}{RESET}")

    except (socket.timeout, OSError) as e:
        print(f"\n{VERMELHO}[!] Erro durante a enumeracao: {e}{RESET}")

    finally:
        s.close()
        print(f"\n{VERDE}[+] Desconectado.{RESET}")


MANUAL = """
EXEMPLOS DE USO
---------------

  Modo interativo (pergunta o host se voce nao passar):
      python3 ftpenum.py

  Direto, host na linha de comando:
      python3 ftpenum.py 172.16.1.108

  Porta alternativa (padrao e 21):
      python3 ftpenum.py 172.16.1.108 --porta 2121

  Timeout maior, pra rede lenta ou instavel:
      python3 ftpenum.py 172.16.1.108 --timeout 10


SOBRE A ENUMERACAO
-------------------

  O script faz, nessa ordem:
    1. Conecta e captura o banner de boas-vindas do servidor
    2. Tenta login anonimo: USER ftp / PASS ftp
    3. Se o login for aceito (resposta 230), avisa destacado na tela
    4. HELP -- lista os comandos suportados pelo servidor
    5. PWD  -- mostra o diretorio atual da sessao

  Cada comando manda e le a resposta separadamente, entao nao tem
  risco de uma resposta "vazar" pra dentro da leitura do comando
  seguinte.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="ftpenum.py",
        description=(
            "BLK - Enumeracao basica de servidor FTP.\n"
            "Conecta, captura o banner, tenta login anonimo e lista comandos/diretorio."
        ),
        epilog=MANUAL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "host", metavar="HOST", nargs="?", default=None,
        help="IP ou hostname do alvo (se omitido, o programa pergunta)",
    )
    parser.add_argument(
        "-p", "--porta", type=int, default=21, metavar="N",
        help="Porta do servico FTP (padrao: 21)",
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

    enumerar_ftp(host, args.porta, args.timeout)


if __name__ == "__main__":
    main()
