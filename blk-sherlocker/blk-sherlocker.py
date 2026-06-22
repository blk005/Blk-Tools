#!/usr/bin/env python3
"""
BLK 005 -- SHERLOCKER
======================
OSINT e investigacao digital com dados publicos.

Consulta CPF, CNPJ, email, telefone ou nome, cruzando com fontes
publicas e gratuitas (BrasilAPI -- Receita Federal, CEP, DDD) e
gerando links de busca/dorks. Pra CNPJ, monta tambem um grafo
expansivel da estrutura societaria (socios).

Fontes: BrasilAPI (CNPJ/CEP/DDD) -- gratuita, sem chave.

Como usar:
    python3 sherlocker.py
        -> sobe um servidor local em http://localhost:5005
"""

from flask import Flask, render_template, jsonify, request
import requests
import re
import hashlib
import json

app = Flask(__name__)

BRASILAPI  = "https://brasilapi.com.br/api"
RECEITAWS  = "https://www.receitaws.com.br/v1/cnpj"
HEADERS    = {"User-Agent": "BLK005-SHERLOCKER/1.0", "Accept": "application/json"}
TIMEOUT    = 15

VERMELHO = "\033[91m"
VERDE    = "\033[92m"
AMARELO  = "\033[93m"
CIANO    = "\033[96m"
CINZA    = "\033[90m"
BRANCO   = "\033[97m"
NEGRITO  = "\033[1m"
RESET    = "\033[0m"

BANNER = r"""
██████╗ ██╗     ██╗  ██╗
██╔══██╗██║     ██║ ██╔╝
██████╔╝██║     █████╔╝
██╔══██╗██║     ██╔═██╗
██████╔╝███████╗██║  ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝
   005 — SHERLOCKER
""".strip("\n")

# ═══════════════════════════════════════════════
#  UTILITÁRIOS
# ═══════════════════════════════════════════════

def so_digitos(s: str) -> str:
    return re.sub(r'\D', '', s or '')

def fmt_cnpj(c: str) -> str:
    c = so_digitos(c)
    if len(c) != 14: return c
    return f"{c[:2]}.{c[2:5]}.{c[5:8]}/{c[8:12]}-{c[12:]}"

def fmt_cpf(c: str) -> str:
    c = so_digitos(c)
    if len(c) != 11: return c
    return f"{c[:3]}.{c[3:6]}.{c[6:9]}-{c[9:]}"

def fmt_moeda(v) -> str:
    try:
        return f"R$ {float(v):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return str(v)

def fmt_tel(tel: str) -> str:
    d = so_digitos(tel or '')
    if not d: return ''
    if len(d) == 11: return f"({d[:2]}) {d[2:7]}-{d[7:]}"
    if len(d) == 10: return f"({d[:2]}) {d[2:6]}-{d[6:]}"
    return tel


# ─── Validação de CPF ─────────────────────────────────────────
def validar_cpf(cpf: str) -> bool:
    c = so_digitos(cpf)
    if len(c) != 11 or c == c[0] * 11:
        return False
    def dig(c, n):
        s = sum(int(c[i]) * (n - i) for i in range(n - 1))
        r = (s * 10) % 11
        return 0 if r >= 10 else r
    return int(c[9]) == dig(c, 10) and int(c[10]) == dig(c, 11)


# ─── Validação de CNPJ ────────────────────────────────────────
def validar_cnpj(cnpj: str) -> bool:
    c = so_digitos(cnpj)
    if len(c) != 14 or c == c[0] * 14:
        return False
    def dig(c, w):
        s = sum(int(c[i]) * w[i] for i in range(len(w)))
        r = s % 11
        return 0 if r < 2 else 11 - r
    w1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    w2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    return int(c[12]) == dig(c, w1) and int(c[13]) == dig(c, w2)


# ─── Detecção de tipo ─────────────────────────────────────────
def detectar_tipo(q: str) -> str:
    q = q.strip()
    d = so_digitos(q)
    if len(d) == 14:  return 'cnpj'
    if len(d) == 11:  return 'cpf'
    if '@' in q:      return 'email'
    if re.match(r'^[\d\s\-\(\)\+]+$', q) and 8 <= len(d) <= 13: return 'telefone'
    return 'texto'


# ═══════════════════════════════════════════════
#  CHAMADAS DE API
# ═══════════════════════════════════════════════

def api_cnpj(cnpj: str) -> dict:
    """Consulta CNPJ na BrasilAPI (Receita Federal espelhada)."""
    c = so_digitos(cnpj)
    try:
        r = requests.get(f"{BRASILAPI}/cnpj/v1/{c}", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            return {"ok": True, "data": r.json()}
        if r.status_code == 404:
            return {"ok": False, "erro": "CNPJ não encontrado na Receita Federal."}
        if r.status_code == 429:
            return {"ok": False, "erro": "Limite de requisições atingido. Aguarde alguns segundos."}
        return {"ok": False, "erro": f"Erro HTTP {r.status_code}"}
    except requests.Timeout:
        return {"ok": False, "erro": "Timeout: API não respondeu a tempo."}
    except Exception as e:
        return {"ok": False, "erro": str(e)}


def api_cep(cep: str) -> dict | None:
    try:
        r = requests.get(f"{BRASILAPI}/cep/v1/{so_digitos(cep)}", headers=HEADERS, timeout=8)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def api_ddd(ddd: str) -> dict | None:
    try:
        r = requests.get(f"{BRASILAPI}/ddd/v1/{ddd}", headers=HEADERS, timeout=8)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


# ═══════════════════════════════════════════════
#  ROTAS FLASK
# ═══════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/buscar', methods=['POST'])
def buscar():
    payload = request.get_json() or {}
    q = (payload.get('query') or '').strip()
    if not q:
        return jsonify({"ok": False, "erro": "Query vazia."})

    tipo = detectar_tipo(q)

    # ─── CNPJ ──────────────────────────────────────────
    if tipo == 'cnpj':
        cn = so_digitos(q)
        if not validar_cnpj(cn):
            return jsonify({"ok": False, "erro": "CNPJ inválido — dígitos verificadores incorretos."})
        res = api_cnpj(cn)
        if res['ok']:
            d = res['data']
            d['cnpj_formatado']    = fmt_cnpj(cn)
            d['capital_social_fmt'] = fmt_moeda(d.get('capital_social', 0))
            d['tel1_fmt']           = fmt_tel(d.get('ddd_telefone_1', ''))
            d['tel2_fmt']           = fmt_tel(d.get('ddd_telefone_2', ''))
            res['tipo'] = 'cnpj'
        return jsonify(res)

    # ─── CPF ───────────────────────────────────────────
    elif tipo == 'cpf':
        cp = so_digitos(q)
        valido = validar_cpf(cp)
        return jsonify({
            "ok": True, "tipo": "cpf",
            "data": {
                "cpf_formatado": fmt_cpf(cp),
                "valido": valido,
                "status": "✓ CPF VÁLIDO" if valido else "✗ CPF INVÁLIDO",
                "info": (
                    "CPF válido. Pela LGPD (Lei 13.709/2018) dados pessoais vinculados ao CPF "
                    "não estão disponíveis em APIs públicas gratuitas. Para consulta oficial "
                    "utilize os canais do gov.br ou SERPRO (requer autorização)."
                ) if valido else "Os dígitos verificadores deste CPF não conferem."
            }
        })

    # ─── EMAIL ─────────────────────────────────────────
    elif tipo == 'email':
        partes = q.split('@')
        usuario = partes[0]
        dominio = partes[1].lower() if len(partes) > 1 else ''
        md5     = hashlib.md5(q.strip().lower().encode()).hexdigest()
        enc     = requests.utils.quote(q)
        enc_n   = requests.utils.quote(q.replace('+', ' '))
        return jsonify({
            "ok": True, "tipo": "email",
            "data": {
                "email":          q,
                "usuario":        usuario,
                "dominio":        dominio,
                "formato_valido": bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', q)),
                "gravatar_md5":   md5,
                "links": {
                    "HaveIBeenPwned": f"https://haveibeenpwned.com/account/{enc}",
                    "Google":         f"https://www.google.com/search?q=%22{enc}%22",
                    "LinkedIn":       f"https://www.linkedin.com/search/results/people/?keywords={enc_n}",
                    "Gravatar":       f"https://www.gravatar.com/{md5}"
                },
                "dorks": [
                    f'"{q}"',
                    f'"{q}" site:linkedin.com',
                    f'"{q}" site:facebook.com',
                    f'intext:"{q}" filetype:pdf',
                    f'"{q}" site:jusbrasil.com.br'
                ]
            }
        })

    # ─── TELEFONE ──────────────────────────────────────
    elif tipo == 'telefone':
        digs = so_digitos(q)
        ddd  = digs[:2] if len(digs) >= 10 else None
        num  = digs[2:] if ddd else digs
        cel  = len(num) == 9 and num[0] == '9'

        ddd_info = api_ddd(ddd) if ddd else None

        if ddd and len(num) >= 8:
            split = 5 if cel else 4
            fmt   = f"({ddd}) {num[:split]}-{num[split:]}"
        else:
            fmt = q

        return jsonify({
            "ok": True, "tipo": "telefone",
            "data": {
                "numero_formatado": fmt,
                "ddd":       ddd,
                "numero":    num,
                "tipo_linha": "📱 Celular" if cel else "☎️ Fixo",
                "regiao":    ddd_info,
                "links": {
                    "Truecaller": f"https://www.truecaller.com/search/br/{digs}",
                    "Google":     f"https://www.google.com/search?q=%22{digs}%22+OR+%22+{ddd}+{num}%22"
                }
            }
        })

    # ─── TEXTO / NOME ──────────────────────────────────
    else:
        enc = requests.utils.quote(q)
        return jsonify({
            "ok": True, "tipo": "texto",
            "data": {
                "query": q,
                "links": {
                    "Google":    f"https://www.google.com/search?q=%22{enc}%22",
                    "LinkedIn":  f"https://www.linkedin.com/search/results/people/?keywords={enc}",
                    "JusBrasil": f"https://www.jusbrasil.com.br/busca?q={enc}",
                    "Facebook":  f"https://www.facebook.com/search/people/?q={enc}"
                },
                "dorks": [
                    f'"{q}"',
                    f'"{q}" CPF OR CNPJ',
                    f'"{q}" site:jusbrasil.com.br',
                    f'"{q}" site:linkedin.com',
                    f'"{q}" filetype:pdf'
                ]
            }
        })


@app.route('/api/expandir', methods=['POST'])
def expandir():
    """Expande um nó CNPJ no grafo, retornando sócios como novos nós."""
    payload = request.get_json() or {}
    cnpj    = so_digitos(payload.get('cnpj', ''))

    if not validar_cnpj(cnpj):
        return jsonify({"ok": False, "erro": "CNPJ inválido."})

    res = api_cnpj(cnpj)
    if not res['ok']:
        return jsonify(res)

    d      = res['data']
    nos    = []
    arestas = []
    status  = (d.get('descricao_situacao_cadastral') or 'ATIVA').upper()
    cor_map = {'ATIVA': '#00ff88', 'BAIXADA': '#ff3366', 'INAPTA': '#ffd700', 'SUSPENSA': '#ff8c00'}
    cor     = cor_map.get(status, '#888899')

    # Nó principal (empresa pesquisada)
    nos.append({
        "id":        cnpj,
        "label":     ((d.get('nome_fantasia') or d.get('razao_social') or 'Empresa')[:22]
                      + "\n" + fmt_cnpj(cnpj)),
        "tipo":      "cnpj_root",
        "cor":       cor,
        "title":     f"{d.get('razao_social','')}\nCNPJ: {fmt_cnpj(cnpj)}\nSituação: {status}",
        "expansivel": False
    })

    for s in (d.get('qsa') or []):
        doc      = so_digitos(s.get('cnpj_cpf_do_socio') or '')
        nome     = s.get('nome_socio') or 'Sócio'
        id_socio = s.get('identificador_de_socio', 0)

        # id_socio: 1=CPF, 2=CNPJ, 3=Estrangeiro
        is_pj      = (id_socio == 2) or (len(doc) == 14)
        expansivel = is_pj and len(doc) == 14

        sid = doc if doc else re.sub(r'\W+', '_', nome)[:30]

        nos.append({
            "id":        sid,
            "label":     nome[:22],
            "tipo":      "cnpj_pj" if is_pj else "cpf_pf",
            "cor":       "#338fff" if is_pj else "#a855f7",
            "title":     (
                f"{nome}\nQualificação: {s.get('qualificacao_socio','')}\n"
                + (f"CNPJ: {fmt_cnpj(doc)}" if is_pj and len(doc)==14 else
                   f"CPF: {fmt_cpf(doc)}" if not is_pj and len(doc)==11 else
                   "Doc: Não informado")
            ),
            "expansivel": expansivel,
            "doc":        doc
        })

        arestas.append({
            "de":    cnpj,
            "para":  sid,
            "label": (s.get('qualificacao_socio') or 'Sócio')[:20]
        })

    return jsonify({
        "ok":      True,
        "nos":     nos,
        "arestas": arestas,
        "empresa": d.get('razao_social')
    })


# ═══════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════
if __name__ == '__main__':
    print(f"\n{VERMELHO}{NEGRITO}{BANNER}{RESET}\n")

    print(f"{CIANO}{NEGRITO}OSINT e investigacao digital com dados publicos (BrasilAPI).{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  FINALIDADE{RESET}")
    print(f"{BRANCO}  Consulta CPF, CNPJ, email, telefone ou nome e cruza com fontes{RESET}")
    print(f"{BRANCO}  publicas e gratuitas {CINZA}(BrasilAPI -- Receita Federal, CEP, DDD){RESET}")
    print(f"{BRANCO}  gerando links de busca/dorks e, pra CNPJ, um grafo de socios.{RESET}\n")

    print(f"{AMARELO}{NEGRITO}  COMO USAR{RESET}")
    print(f"  {VERDE}❯{RESET} Deixe este terminal aberto -- ele é o servidor.")
    print(f"  {VERDE}❯{RESET} Abra o navegador em {CIANO}http://localhost:5005{RESET}")
    print(f"  {VERDE}❯{RESET} Digite um CPF, CNPJ, email, telefone ou nome na busca.")
    print(f"  {VERDE}❯{RESET} Em resultado de CNPJ, clique num sócio pra expandir o grafo.\n")

    print(f"{CINZA}{'─' * 70}{RESET}\n")

    app.run(debug=True, host='0.0.0.0', port=5005)
