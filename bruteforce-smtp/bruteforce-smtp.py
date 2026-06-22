#!/usr/bin/env python3
"""
BLK SMTP BRUTE
==============
Enumeracao em massa de usuarios num servidor SMTP via VRFY,
lendo de uma wordlist local.

Como usar:
    ./smtp_brute.py 172.16.1.108 --wordlist usuarios.txt
    ./smtp_brute.py 172.16.1.108 --porta 587 --timeout 5

Flags:
    host                 IP ou hostname do servidor SMTP
    -w, --wordlist       Arquivo com lista de usuarios (padrao: usuarios.txt)
    -p, --porta          Porta SMTP (padrao: 25)
    --timeout            Timeout de conexao em segundos (padrao: 5)
"""

import argparse
import socket
import sys

VERMELHO = "\033[91m"
VERDE = "\033[92m"
AMARELO = "\033[93m"
CIANO = "\033[96m"
CINZA = "\033[90m"
BRANCO = "\033[97m"
NEGRITO = "\033[1m"
RESET = "\033[0m"

BANNER = r"""
██████╗ ██╗     ██╗  ██╗
██╔══██╗██║     ██║ ██╔╝
██████╔╝██║     █████╔╝
██╔══██╗██║     ██╔═██╗
██████╔╝███████╗██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝
      SMTP BRUTE
""".strip("\n")


def imprimir_banner():
    """Mostra o banner em vermelho brilhante, com um resumo bonito de uso logo abaixo."""
    print(f"{VERMELHO}{NEGRITO}{BANNER}{RESET}\n")

    print(f"{CIANO}{NEGRITO}Enumeracao em massa de usuarios SMTP via VRFY.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  FINALIDADE{RESET}")
    print(f"{BRANCO}  Le uma wordlist de nomes de usuario e tenta confirmar a existencia{RESET}")
    print(f"{BRANCO}  de cada um num servidor SMTP {CINZA}(via comando VRFY){RESET}{BRANCO}. Exibe{RESET}")
    print(f"{BRANCO}  quais usuarios existem, com base na resposta do servidor.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  COMO USAR{RESET}")
    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtp_brute.py{RESET}")
    print(f"    {CINZA}modo interativo -- pergunta o host se voce nao passar.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtp_brute.py{RESET} {CIANO}172.16.1.108{RESET}")
    print(f"    {CINZA}direto -- testa todos os usuarios na wordlist padrao (usuarios.txt).{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtp_brute.py{RESET} {CIANO}172.16.1.108 -w minha_lista.txt{RESET}")
    print(f"    {CINZA}com wordlist customizada.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 smtp_brute.py --help{RESET}")
    print(f"    {CINZA}manual completo, com todas as opcoes.{RESET}")
    print(f"\n{CINZA}{'─' * 74}{RESET}\n")


def enumerar_smtp(host, porta, wordlist_path, timeout):
    """Conecta no servidor SMTP e testa cada usuario da wordlist."""
    print(f"{AMARELO}[*] Abrindo wordlist: {wordlist_path}{RESET}")
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8') as f:
            usuarios = [linha.strip() for linha in f if linha.strip() and not linha.startswith('#')]
    except FileNotFoundError:
        print(f"{VERMELHO}[!] Arquivo nao encontrado: {wordlist_path}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao ler arquivo: {e}{RESET}")
        sys.exit(1)

    print(f"{AMARELO}[*] Total de usuarios a testar: {len(usuarios)}{RESET}")
    print(f"{AMARELO}[*] Conectando em {host}:{porta}...{RESET}\n")

    # Conecta uma unica vez e reutiliza
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(timeout)
        tcp.connect((host, porta))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"{VERMELHO}[!] Falha ao conectar: {e}{RESET}")
        sys.exit(1)

    try:
        # Banner de boas-vindas
        banner = tcp.recv(1024).decode(errors="ignore").strip()
        print(f"{VERDE}[+] Banner:{RESET}\n{banner}\n")
        print(f"{CIANO}{'─' * 74}{RESET}")
        print(f"{CINZA}{'USUARIO':<30}{'RESPOSTA':<44}{RESET}")
        print(f"{CIANO}{'─' * 74}{RESET}\n")

        encontrados = 0

        for usuario in usuarios:
            try:
                # VRFY precisa de \r\n no final
                cmd = f"VRFY {usuario}\r\n"
                tcp.send(cmd.encode())
                resposta = tcp.recv(1024).decode(errors="ignore").strip()

                # Codigo 250 ou 252 = usuario existe
                if resposta.startswith('250') or resposta.startswith('252'):
                    print(f"{VERDE}[+]{RESET} {usuario:<30} {VERDE}{resposta[:40]}{RESET}")
                    encontrados += 1
                elif resposta.startswith('550') or resposta.startswith('551'):
                    # 550/551 = usuario nao existe (opcional, mostrar so se -v)
                    pass
                else:
                    # Outros codigos
                    print(f"{AMARELO}[?]{RESET} {usuario:<30} {resposta[:40]}")

            except socket.timeout:
                print(f"{VERMELHO}[!]{RESET} {usuario:<30} {VERMELHO}Timeout{RESET}")
                break
            except (BrokenPipeError, ConnectionResetError):
                print(f"{VERMELHO}[!] Conexao perdida. Tentando reconectar...{RESET}")
                try:
                    tcp.close()
                except:
                    pass
                try:
                    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tcp.settimeout(timeout)
                    tcp.connect((host, porta))
                    # Re-testa este usuario
                    cmd = f"VRFY {usuario}\r\n"
                    tcp.send(cmd.encode())
                    resposta = tcp.recv(1024).decode(errors="ignore").strip()
                    if resposta.startswith('250') or resposta.startswith('252'):
                        print(f"{VERDE}[+]{RESET} {usuario:<30} {VERDE}{resposta[:40]}{RESET}")
                        encontrados += 1
                except:
                    break
            except Exception as e:
                print(f"{VERMELHO}[!]{RESET} {usuario:<30} Erro: {str(e)[:30]}")

        print(f"\n{CIANO}{'─' * 74}{RESET}")
        print(f"{VERDE}[*] Concluido: {encontrados} usuario(s) encontrado(s).{RESET}\n")

    except Exception as e:
        print(f"{VERMELHO}[!] Erro durante a enumeracao: {e}{RESET}")

    finally:
        tcp.close()
        print(f"{VERDE}[+] Desconectado.{RESET}")


MANUAL = """
EXEMPLOS DE USO
---------------

  Modo interativo:
      python3 smtp_brute.py

  Direto, com wordlist padrao (usuarios.txt):
      python3 smtp_brute.py 172.16.1.108

  Com wordlist customizada:
      python3 smtp_brute.py 172.16.1.108 -w minha_lista.txt

  Porta alternativa (ex: 587 pra SMTP auth):
      python3 smtp_brute.py 172.16.1.108 -p 587

  Timeout maior, pra rede lenta:
      python3 smtp_brute.py 172.16.1.108 --timeout 10


INTERPRETANDO OS RESULTADOS
-----------------------------

  250   -- Usuario existe (resposta positiva do VRFY)
  252   -- Usuario existe, mas nao pode confirmar (tratado como positivo)
  550   -- Usuario nao encontrado (sai silencioso)
  551   -- Usuario nao local (sai silencioso)
  Outro -- Resposta inesperada (exibida com [?])

  Os servidores SMTP podem responder de forma diferente dependendo
  da configuracao, firewall, ou se VRFY esta desabilitado. Se a
  enumeracao nao retornar nada, pode ser que:
    - VRFY esteja desabilitado no servidor
    - Um firewall/IDS esteja bloqueando probes rapidas
    - O servidor seja honeypot ou esteja filtrando

  Dica: combine com outras tecnicas (EXPN, RCPT TO, timing) pra
  confirmar resultados e evitar falsos positivos.


FORMATO DA WORDLIST
--------------------

  Um usuario por linha. Linhas em branco e comeando com # sao ignoradas:

  # Contas de sistema
  root
  admin
  postmaster

  # Servicos
  www-data
  mysql
  postgres

  # Nomes
  joao
  maria
  ...
"""


def main():
    parser = argparse.ArgumentParser(
        prog="smtp_brute.py",
        description=(
            "BLK - Enumeracao em massa de usuarios SMTP via VRFY.\n"
            "Le uma wordlist local e testa cada usuario contra um servidor SMTP."
        ),
        epilog=MANUAL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "host", metavar="HOST", nargs="?", default=None,
        help="IP ou hostname do servidor SMTP (se omitido, o programa pergunta)",
    )
    parser.add_argument(
        "-w", "--wordlist", default="usuarios.txt", metavar="ARQUIVO",
        help="Arquivo com lista de usuarios (padrao: usuarios.txt)",
    )
    parser.add_argument(
        "-p", "--porta", type=int, default=25, metavar="N",
        help="Porta SMTP (padrao: 25)",
    )
    parser.add_argument(
        "--timeout", type=int, default=5, metavar="N",
        help="Timeout de conexao em segundos (padrao: 5)",
    )
    args = parser.parse_args()

    imprimir_banner()

    host = args.host
    while not host:
        host = input(f"{NEGRITO}Digite o host SMTP alvo: {RESET}").strip()
        if not host:
            print("  Host nao pode ser vazio.\n")

    enumerar_smtp(host, args.porta, args.wordlist, args.timeout)


if __name__ == "__main__":
    main()
