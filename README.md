# Gerador de token JWT por imagem (Python)

Este projeto gera um token JWT com base **nos bytes da imagem** e com camadas criptograficas:

1. SHA3-512 sobre o conteudo da imagem
2. PBKDF2-HMAC-SHA512 (key stretching)
3. HMAC-SHA512 com segredo
4. SHA-256 para material final do token

Sem fingerprint visual no payload.

## Instalar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
python3 image_token.py caminho/para/imagem.jpg --secret "minha-chave"
```

Com variavel de ambiente:

```bash
python3 image_token.py caminho/para/imagem.jpg
```

Ajustando nivel de hardening (iteracoes PBKDF2):

```bash
python3 image_token.py caminho/para/imagem.jpg --secret "minha-chave" --iterations 500000
```

## Observacoes

- O retorno agora e um JWT no formato `header.payload.signature`.
- `--secret` (ou `IMAGE_TOKEN_SECRET`) e obrigatorio para seguranca.
- A mesma imagem com o mesmo `--secret` e `--iterations` gera o mesmo token.
- Pequenas alteracoes na imagem podem mudar o token.
- O payload contem `img_token` derivado criptograficamente do arquivo, sem fingerprint visual.
