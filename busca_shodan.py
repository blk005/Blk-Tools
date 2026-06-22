#!/usr/bin/env python3
"""
busca_shodan.py -- Busca refinada no Shodan, em português simples.

Em vez de exigir que você saiba a sintaxe "filtro:valor" do Shodan de cabeça,
esse script pergunta os parâmetros em português (porta, país, cidade, produto,
versão, etc.), monta a query correta sozinho, consulta a API oficial do
Shodan e mostra os resultados de forma legível.

Requisito:
    pip3 install shodan --break-system-packages

Pegar uma API key gratuita em:
    https://account.shodan.io/

Modos de uso:
    python3 busca_shodan.py
        -> modo interativo: pergunta cada parâmetro, um de cada vez.

    python3 busca_shodan.py --chave "porta: 22, pais: BR, cidade: Manaus"
        -> modo rápido: tudo numa linha só, separado por vírgula.

    python3 busca_shodan.py --query "port:22 country:BR"
        -> modo avançado: query já pronta, na sintaxe nativa do Shodan.

    python3 busca_shodan.py --listar-campos
        -> mostra todas as palavras em português reconhecidas e pra qual
           filtro do Shodan cada uma é traduzida.

Flags extras:
    --key SUA_KEY       API key informada na hora (senão o script pergunta)
    --limite N          Quantos resultados mostrar (padrão: 10)
    -y / --sim          Não pede confirmação antes de buscar (útil em scripts)
"""

import argparse
import getpass
import os
import sys
import unicodedata

try:
    import shodan
except ImportError:
    shodan = None


# Cores ANSI pro terminal
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
      SHODAN SEARCH
""".strip("\n")


def topo(titulo=""):
    """Linha superior de uma caixa, com titulo opcional embutido."""
    if titulo:
        rotulo = f"─[ {titulo} ]"
        resto = LARGURA - len(rotulo) - 1
        return f"┌{rotulo}{'─' * max(resto, 1)}┐"
    return f"┌{'─' * LARGURA}┐"


def base():
    """Linha inferior de uma caixa."""
    return f"└{'─' * LARGURA}┘"


def divisor():
    """Linha fina de separacao entre secoes."""
    return f"{CINZA}{'─' * (LARGURA + 2)}{RESET}"


def imprimir_banner():
    """Mostra o banner de apresentacao da aplicacao em vermelho brilhante, com a ajuda logo abaixo."""
    print(f"{VERMELHO}{NEGRITO}{BANNER}{RESET}\n")

    print(f"\n{CIANO}{NEGRITO}Busca refinada no Shodan, em portugues simples.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  FINALIDADE{RESET}")
    print(f"{BRANCO}  Voce informa o que quer buscar {CINZA}(porta, pais, cidade, produto, versao...){RESET}")
    print(f"{BRANCO}  em portugues, sem precisar saber a sintaxe {CIANO}\"filtro:valor\"{BRANCO} do Shodan{RESET}")
    print(f"{BRANCO}  de cabeca. A ferramenta monta a query certa sozinha, consulta a API{RESET}")
    print(f"{BRANCO}  oficial e mostra os resultados de forma legivel.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  COMO USAR{RESET}")
    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 busca_shodan.py{RESET}")
    print(f"    {CINZA}modo interativo (recomendado) -- pergunta cada parametro, um de cada{RESET}")
    print(f"    {CINZA}vez, e aperta Enter pra pular o que nao interessa.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 busca_shodan.py --chave{RESET} {CIANO}\"porta: 22, pais: BR\"{RESET}")
    print(f"    {CINZA}modo rapido -- tudo numa linha so, separado por virgula.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 busca_shodan.py --query{RESET} {CIANO}\"port:22 country:BR\"{RESET}")
    print(f"    {CINZA}modo avancado -- query ja pronta, na sintaxe nativa do Shodan.{RESET}\n")

    print(f"  {VERDE}❯{RESET} {NEGRITO}python3 busca_shodan.py --help{RESET}")
    print(f"    {CINZA}manual completo, com todas as flags, exemplos e a lista de palavras{RESET}")
    print(f"    {CINZA}em portugues reconhecidas.{RESET}")
    print(f"\n{divisor()}")


# ---------------------------------------------------------------------------
# Mapeamento: palavra simples em português -> filtro real do Shodan
# Pode ter vários sinônimos apontando pro mesmo filtro.
# ---------------------------------------------------------------------------
MAPA_FILTROS = {
    "porta": "port",
    "portas": "port",
    "pais": "country",
    "cidade": "city",
    "rede": "net",
    "subrede": "net",
    "faixa": "net",
    "ip": "ip",
    "organizacao": "org",
    "empresa": "org",
    "org": "org",
    "produto": "product",
    "servico": "product",
    "software": "product",
    "versao": "version",
    "sistema": "os",
    "so": "os",
    "sistemaoperacional": "os",
    "host": "hostname",
    "hostname": "hostname",
    "dominio": "hostname",
    "antes": "before",
    "depois": "after",
    "asn": "asn",
    "titulo": "http.title",
}

# Perguntas do modo interativo: (pergunta exibida, filtro Shodan correspondente)
PERGUNTAS = [
    ("Porta (ex: 22, 80, 443)", "port"),
    ("Pais -- codigo de 2 letras (ex: BR, US)", "country"),
    ("Cidade", "city"),
    ("Produto ou servico (ex: OpenSSH, nginx, MySQL)", "product"),
    ("Versao do produto", "version"),
    ("Organizacao/empresa dona do IP", "org"),
    ("Sistema operacional", "os"),
    ("Rede/faixa de IP em CIDR (ex: 192.168.1.0/24)", "net"),
    ("Hostname/dominio", "hostname"),
    ("So resultados depois de (dd/mm/aaaa)", "after"),
    ("So resultados antes de (dd/mm/aaaa)", "before"),
]


def normalizar(texto):
    """Remove acentos e baixa a caixa, pra comparar palavras-chave sem erro de digitação."""
    if texto is None:
        return ""
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii")
    return sem_acento.strip().lower()


def formatar_valor(valor):
    """Coloca aspas em valores com espaço, do jeito que a sintaxe do Shodan exige."""
    valor = valor.strip()
    if " " in valor and not (valor.startswith('"') and valor.endswith('"')):
        return f'"{valor}"'
    return valor


def montar_query_interativa():
    """Pergunta cada filtro em português simples, um de cada vez. Enter pula a pergunta."""
    print(f"\n{CINZA}Responda o que for relevante. Aperte Enter pra pular qualquer pergunta.{RESET}\n")
    partes = []
    for pergunta, filtro in PERGUNTAS:
        resposta = input(f"  {AMARELO}❯{RESET} {pergunta}: ").strip()
        if resposta:
            partes.append(f"{filtro}:{formatar_valor(resposta)}")

    termo_livre = input(f"\n  {AMARELO}❯{RESET} Alguma palavra-chave livre adicional (opcional): ").strip()
    if termo_livre:
        partes.append(termo_livre)

    return " ".join(partes)


def montar_query_de_texto(texto):
    """
    Modo rápido: aceita uma linha tipo
        'porta: 22, pais: BR, cidade: Manaus, openssh'
    Pedaços com 'chave:valor' reconhecida viram filtro do Shodan.
    Pedaços sem chave reconhecida viram termo de busca livre.
    """
    partes = []
    pedacos = [p.strip() for p in texto.split(",") if p.strip()]
    for pedaco in pedacos:
        chave, valor = None, None
        if ":" in pedaco:
            chave, _, valor = pedaco.partition(":")
        elif "=" in pedaco:
            chave, _, valor = pedaco.partition("=")

        chave_norm = normalizar(chave) if chave else None
        if chave_norm and chave_norm in MAPA_FILTROS and valor and valor.strip():
            filtro = MAPA_FILTROS[chave_norm]
            partes.append(f"{filtro}:{formatar_valor(valor)}")
        else:
            # não reconheceu uma chave válida -> trata o pedaço inteiro como termo livre
            partes.append(pedaco)

    return " ".join(partes)


def obter_api_key(args):
    """
    Busca a API key nesta ordem:
      1. argumento --key (linha de comando, opcional)
      2. se não foi informada, pede na hora (entrada oculta) -- nada fica
         salvo em disco nem fixo no código, sempre opcional/no momento do uso
    """
    if args.key:
        return args.key.strip()

    print(f"\n{AMARELO}⚠ Nenhuma API key informada via --key.{RESET}")
    print(f"{CINZA}Pegue a sua gratuitamente em{RESET} {CIANO}https://account.shodan.io/{RESET}\n")
    chave = getpass.getpass("Cole sua Shodan API key (nao aparece na tela): ").strip()

    return chave


def exibir_resultados(resultado, limite):
    total = resultado.get("total", 0)
    matches = resultado.get("matches", [])

    print(f"\n{VERDE}{NEGRITO}{topo()}{RESET}")
    print(f"{VERDE}{NEGRITO}│{RESET} {BRANCO}{total} resultado(s) encontrados no total{RESET} {CINZA}(mostrando ate {limite}){RESET}")
    print(f"{VERDE}{NEGRITO}{base()}{RESET}\n")

    if not matches:
        print(f"{VERMELHO}✗ Nenhum resultado retornado para esses filtros.{RESET}")
        print(f"{CINZA}  Dica: tente remover algum filtro (cidades pequenas costumam dar 0 resultado).{RESET}\n")
        return

    for i, item in enumerate(matches, start=1):
        ip = item.get("ip_str", "?")
        porta = item.get("port", "?")
        org = item.get("org") or "desconhecida"
        local = item.get("location", {}) or {}
        pais = local.get("country_name") or "desconhecido"
        cidade = local.get("city") or "-"
        produto = item.get("product") or "-"
        versao = item.get("version") or ""
        banner_linhas = (item.get("data") or "").strip().splitlines()
        banner = banner_linhas[0][:80] if banner_linhas else ""

        print(f"{CIANO}{topo(f'{i}')}{RESET}")
        print(f"{CIANO}│{RESET} {NEGRITO}{BRANCO}{ip}:{porta}{RESET}")
        print(f"{CIANO}│{RESET}")
        print(f"{CIANO}│{RESET} {AMARELO}Organizacao{RESET} : {org}")
        print(f"{CIANO}│{RESET} {AMARELO}Local{RESET}       : {cidade}, {pais}")
        print(f"{CIANO}│{RESET} {AMARELO}Produto{RESET}     : {produto} {versao}".rstrip())
        if banner:
            print(f"{CIANO}│{RESET} {AMARELO}Banner{RESET}      : {CINZA}{banner}{RESET}")
        print(f"{CIANO}{base()}{RESET}\n")


def listar_campos():
    print(f"\n{MAGENTA}{NEGRITO}{topo('PALAVRAS RECONHECIDAS')}{RESET}")
    vistos = set()
    for chave, filtro in MAPA_FILTROS.items():
        if filtro in vistos:
            continue
        sinonimos = sorted(k for k, v in MAPA_FILTROS.items() if v == filtro)
        print(f"{MAGENTA}│{RESET} {CIANO}{filtro:14s}{RESET} {CINZA}<-{RESET} {sinonimos[0]}", end="")
        for s in sinonimos[1:]:
            print(f"{CINZA}, {RESET}{s}", end="")
        print()
        vistos.add(filtro)
    print(f"{MAGENTA}{base()}{RESET}")
    print(f"{CINZA}Qualquer palavra fora dessa lista vira termo de busca livre.{RESET}\n")


MANUAL = """
EXEMPLOS DE USO
---------------

  Modo interativo (recomendado pra quem nao sabe a sintaxe do Shodan):
      python3 busca_shodan.py

  Modo rapido, tudo numa linha so, separado por virgula:
      python3 busca_shodan.py --chave "porta: 22, pais: BR, cidade: Manaus"
      python3 busca_shodan.py --chave "produto: OpenSSH, versao: 8.9"
      python3 busca_shodan.py --chave "openssh, porta: 22"   (termo livre + filtro)

  Modo avancado, query ja pronta na sintaxe nativa do Shodan:
      python3 busca_shodan.py --query "port:22 country:BR"

  Ver quais palavras em portugues sao reconhecidas e pra qual filtro viram:
      python3 busca_shodan.py --listar-campos

  Buscar sem precisar confirmar (util em script/automacao):
      python3 busca_shodan.py --chave "porta:22" -y

  Limitar quantos resultados aparecem na tela:
      python3 busca_shodan.py --chave "porta:22" --limite 25


SOBRE A API KEY
---------------

  Precisa de uma conta gratuita em https://account.shodan.io/ pra pegar a key.

  A API key e sempre opcional na linha de comando e nunca fica salva:
      1. flag --key NA_HORA (se voce passar, o script usa direto)
      2. se nao passar, o script pergunta na hora (digitacao oculta, nao
         aparece na tela) -- nada fica fixo no codigo nem salvo em disco


PALAVRAS RECONHECIDAS NO MODO RAPIDO/INTERATIVO
-------------------------------------------------

  porta, portas              -> port
  pais                        -> country
  cidade                       -> city
  rede, subrede, faixa         -> net
  ip                           -> ip
  organizacao, empresa, org    -> org
  produto, servico, software   -> product
  versao                       -> version
  sistema, so                  -> os
  host, hostname, dominio      -> hostname
  antes                        -> before
  depois                       -> after
  asn                          -> asn
  titulo                       -> http.title

  Funciona com ou sem acento e maiuscula/minuscula (PAIS = pais = País).
  Qualquer palavra fora dessa lista vira termo de busca livre, em vez de dar erro.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="busca_shodan.py",
        description=(
            "Busca refinada no Shodan, sem precisar saber a sintaxe 'filtro:valor' de cor.\n"
            "Voce fala os parametros em portugues simples e o script monta a query sozinho."
        ),
        epilog=MANUAL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--query", metavar="TEXTO",
        help="Query ja pronta no formato nativo do Shodan. Ex: 'port:22 country:BR'",
    )
    parser.add_argument(
        "--chave", metavar="TEXTO",
        help="Modo rapido: parametros em portugues numa linha so. Ex: 'porta:22, pais:BR'",
    )
    parser.add_argument(
        "--key", metavar="API_KEY",
        help="API key do Shodan informada na hora (senao o script pergunta)",
    )
    parser.add_argument(
        "--limite", type=int, default=10, metavar="N",
        help="Quantos resultados mostrar na tela (padrao: 10)",
    )
    parser.add_argument(
        "-y", "--sim", action="store_true",
        help="Nao pede confirmacao antes de buscar (util em scripts)",
    )
    parser.add_argument(
        "--listar-campos", action="store_true",
        help="Mostra as palavras em portugues reconhecidas e pra qual filtro cada uma vira, e sai",
    )
    args = parser.parse_args()

    imprimir_banner()

    if args.listar_campos:
        listar_campos()
        return

    if shodan is None:
        print(f"{VERMELHO}✗ Faltando o pacote 'shodan'.{RESET} Instale com:")
        print(f"  {CIANO}pip3 install shodan --break-system-packages{RESET}")
        sys.exit(1)

    if args.query:
        query = args.query.strip()
    elif args.chave:
        query = montar_query_de_texto(args.chave)
    else:
        print(f"{AZUL}{NEGRITO}{topo('MODO INTERATIVO')}{RESET}")
        print(f"{AZUL}{NEGRITO}{base()}{RESET}")
        query = montar_query_interativa()

    if not query:
        print(f"\n{VERMELHO}✗ Nenhum filtro/termo informado{RESET} -- nada pra buscar. Encerrando.")
        sys.exit(1)

    print(f"\n{CIANO}{NEGRITO}Query Shodan montada:{RESET} {BRANCO}{query}{RESET}")
    if not args.sim:
        confirmar = input(f"{AMARELO}Buscar com essa query? [S/n]: {RESET}").strip().lower()
        if confirmar == "n":
            print(f"{CINZA}Cancelado.{RESET}")
            return

    api_key = obter_api_key(args)
    if not api_key:
        print(f"\n{VERMELHO}✗ API key vazia{RESET} -- nao da pra continuar sem ela.")
        sys.exit(1)

    api = shodan.Shodan(api_key)

    try:
        resultado = api.search(query, limit=args.limite)
    except shodan.APIError as erro:
        print(f"\n{VERMELHO}{NEGRITO}✗ Erro da API do Shodan:{RESET} {VERMELHO}{erro}{RESET}")
        print(f"{CINZA}Causas comuns: API key invalida, sem creditos disponiveis, ou query mal formada.{RESET}")
        sys.exit(1)

    exibir_resultados(resultado, args.limite)


if __name__ == "__main__":
    main()
