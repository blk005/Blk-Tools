# BLK 005 — SHERLOCKER v1.0
### OSINT & Digital Investigation Tool | BLK Project

```
╔══════════════════════════════════════════════════════╗
║    BLK 005 — SHERLOCKER  v1.0                       ║
║    OSINT & Digital Investigation Tool               ║
╚══════════════════════════════════════════════════════╝
```

---

## O que é?

Ferramenta de investigação OSINT com interface web, inspirada no Sherlocker.com.br.
Consulta **dados públicos oficiais** via BrasilAPI (espelho da Receita Federal),
visualiza conexões societárias em **grafo interativo**, e gera **dorks** para
investigação avançada.

---

## Funcionalidades

| Módulo            | O que faz                                                         |
|-------------------|-------------------------------------------------------------------|
| **CNPJ**          | Dados cadastrais completos (RF), QSA (sócios), CNAE, endereço    |
| **CPF**           | Validação dos dígitos verificadores                               |
| **Email**         | Análise de domínio, links de investigação, Google Dorks           |
| **Telefone**      | DDD → Estado/Cidades, tipo (celular/fixo), links externos         |
| **Nome/Texto**    | Links diretos (Google, LinkedIn, JusBrasil) + Google Dorks        |
| **Grafo**         | Mapa interativo CNPJ→Sócios com expansão recursiva               |
| **Export**        | Imprimir relatório / Copiar JSON bruto                            |

---

## Instalação

### Pré-requisitos
- Python 3.10+
- Kali Linux (ou qualquer distro com Python)

### Passos

```bash
# 1 — Entrar na pasta da ferramenta
cd BLK_005_SHERLOCKER

# 2 — Criar ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

# 3 — Instalar dependências
pip install -r requirements.txt

# 4 — Iniciar o servidor
python3 blk005_sherlocker.py
```

### Acessar

Abra o navegador em: **http://localhost:5005**

---

## Como usar

1. Digite um **CNPJ**, **CPF**, **email**, **telefone** ou **nome** na barra de busca
2. A ferramenta detecta o tipo automaticamente (badge no canto do campo)
3. Pressione **ENTER** ou clique em **INVESTIGAR**
4. Para CNPJ: o **grafo** é gerado automaticamente com todos os sócios
5. Clique num **nó azul (PJ)** no grafo para expandir as conexões daquele CNPJ
6. Use os **dorks** gerados para pesquisa avançada no Google

---

## API utilizada

| API            | Endpoint                                     | Autenticação |
|----------------|----------------------------------------------|--------------|
| BrasilAPI CNPJ | `brasilapi.com.br/api/cnpj/v1/{cnpj}`        | Nenhuma      |
| BrasilAPI CEP  | `brasilapi.com.br/api/cep/v1/{cep}`          | Nenhuma      |
| BrasilAPI DDD  | `brasilapi.com.br/api/ddd/v1/{ddd}`          | Nenhuma      |

---

## Limitações (comparado ao Sherlocker pago)

| Feature                          | BLK 005   | Sherlocker |
|----------------------------------|-----------|------------|
| Dados cadastrais CNPJ (RF)       | ✅         | ✅         |
| Quadro societário (QSA)          | ✅         | ✅         |
| Grafo de conexões PJ             | ✅         | ✅         |
| Google Dorks integrados          | ✅         | ❌         |
| Dados pessoais CPF               | ❌ (LGPD)  | ✅ (pago)  |
| +50 bases privadas               | ❌         | ✅ (pago)  |
| Monitoramento 24/7               | ❌         | ✅ (pago)  |
| Relatórios IA                    | ❌         | ✅ (pago)  |

> **Nota:** Consultas a dados pessoais (CPF, endereço de pessoa física, veículos etc.)
> exigem autorização legal e acesso via canais oficiais (SERPRO, gov.br).
> Esta ferramenta opera **exclusivamente** com dados públicos.

---

## Stack

- **Backend:** Python 3 + Flask
- **Frontend:** HTML5 + CSS3 puro + vanilla JS
- **Grafo:** [vis.js](https://visjs.github.io/vis-network/) (CDN)
- **Ícones:** Font Awesome 6 (CDN)
- **API:** BrasilAPI (open source, sem chave)

---

## Estrutura do projeto

```
BLK_005_SHERLOCKER/
├── blk005_sherlocker.py   # Backend Flask + API routes
├── templates/
│   └── index.html         # Frontend (dark UI + vis.js)
├── requirements.txt
└── README.md
```

---

*BLK Project — uso educacional / investigação com dados públicos*
