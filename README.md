# ⚡ Automação Pix ➔ Carteira Cripto via WhatsApp

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/lucassimas77-dev/robo-pix-cripto)

Sistema simples de autoatendimento onde o cliente pede um Pix no **WhatsApp**, recebe na hora o **QR Code + Pix Copia e Cola** (sem precisar informar CPF no chat), paga em qualquer banco e o valor cai convertido direto na **carteira cripto de autocustódia** configurada no painel.

## Como funciona na prática (3 passos pelo navegador)

1. **Conectar Conta & Carteira:** Cole sua chave de API (ex: DePix App / Liquid Network) e o endereço da sua carteira cripto direto na tela inicial.
2. **Conectar WhatsApp:** Leia o QR Code do WhatsApp na própria página.
3. **Receber Pagamentos:** Quando alguém mandar mensagem pedindo Pix (ex: *"Me manda um Pix de 100"*), o sistema gera a chave dinâmica, vigia o vencimento e confirma automaticamente quando o pagamento cair.
