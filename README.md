# CF_RECON.py
# cf_recon.py

Ferramenta de reconhecimento passivo e semi-ativo para aplicações web atrás de Cloudflare (CDN + WAF). Python puro, sem dependências externas, 7 módulos de análise executados em sequência.

> **Uso autorizado apenas.** Esta ferramenta deve ser usada somente em sistemas com autorização explícita (bug bounty, pentest contratado, laboratório próprio). Uso não autorizado pode constituir crime (Art. 154-A do Código Penal Brasileiro).

## O que faz

| Módulo | Função |
|---|---|
| DNS | Resolve A/AAAA, detecta Cloudflare, sonda subdomínios comuns em busca de IP de origem |
| SSL/TLS | Extrai certificado, SANs, cifra e protocolo — SANs podem revelar subdomínios internos |
| HTTP Baseline | Analisa headers de segurança, cookies, stack tecnológica |
| Bypass Headers | Testa 10 headers forjados (CF-Connecting-IP, X-Forwarded-For etc.) contra o baseline |
| Path Discovery | Sonda 70+ paths sensíveis em paralelo (admin, .env, .git, backups) |
| WAF Fingerprint | Envia 9 vetores de ataque não-destrutivos para medir agressividade do WAF |
| Info Disclosure | Analisa headers coletados em busca de CORS aberto, CSP fraca, HSTS fraco |

## Instalação

Zero dependências — só biblioteca padrão do Python 3.6+.

```bash
chmod +x cf_recon.py
python3 cf_recon.py --help
```

## Uso

```bash
python3 cf_recon.py -t https://alvo-autorizado.com --threads 20 --ai-context -o recon.json
```

Gera `recon.json` (estruturado) e `recon_ai_context.txt` (formatado para análise por LLM).

Flags principais: `--skip-waf` (recomendado em produção), `--skip-paths`, `--skip-bypass`, `--threads N`.

## Validação

Testado em ambiente de testes autorizado montado por **Jacqueline Teixeira**, líder do capítulo OWASP Belém. *(ajustar se também validado em outro contexto)*

## Autor

Victor Soares de Miranda — [LinkedIn](https://linkedin.com/in/victor-miranda-130b88295)
