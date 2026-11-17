# ⚡ Automação Pix ➔ Carteira Cripto via WhatsApp

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/lucassimas77-dev/robo-pix-cripto)

Sistema automático 24h onde o cliente pede um Pix no **WhatsApp** informando apenas o valor (zero CPF ou perguntas no chat), recebe na hora o **Link Privado Único de Pagamento + QR Code**, paga em qualquer banco e o valor cai convertido direto na sua **carteira cripto de autocustódia** (na DePix App, direto no endereço Liquid configurado na conta Merchant em `depixapp.com/#merchant`).

## Como funciona na prática (3 passos pelo navegador)

1. **Proteger o Painel e Conectar Conta:** No primeiro acesso, defina a senha do painel e cole sua Chave de API da DePix App (`sk_live_...` ou `sk_test_...`) — ou configure endereço/rede caso use Hodle/NoxPay.
2. **Conectar WhatsApp:** Leia o QR Code do WhatsApp na própria página (com filtro inteligente para responder apenas mensagens sobre Pix).
3. **Receber Pagamentos Automaticamente:** Quando alguém enviar uma mensagem pedindo Pix (ex: *"Me manda um Pix de 50"*), o robô gera a cobrança privada única, monitora o prazo e confirma automaticamente no WhatsApp quando o pagamento compensar.
