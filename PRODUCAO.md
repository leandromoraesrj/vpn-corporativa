# VPN Corporativa 1.0 — Produção

Esta é a versão consolidada de produção 1.0.

## Conteúdo do pacote

- código-fonte completo;
- instalador e desinstalador;
- helpers privilegiados de conexão, desconexão e diagnóstico;
- interface gráfica;
- suíte de testes;
- auditoria da instalação;
- documentação técnica e operacional;
- notas de validação e histórico das revisões.

## Comportamento confirmado

- fechar a janela pelo **X** apenas oculta a interface e mantém a VPN;
- selecionar **Sair** desconecta a VPN antes de encerrar o aplicativo;
- aliases internos de `/etc/hosts` podem conter `_`;
- o helper privilegiado revalida os arquivos de configuração;
- senha da instalação inicial não é transmitida nos argumentos do processo;
- timeout de conexão usa `TERM` e `KILL` como último recurso;
- logs e relatórios ficam em `~/.local/state/vpn`;
- arquivos de configuração ficam em `~/.config/vpn`.

## Fluxo recomendado

```bash
./validate_release.sh
sudo ./install.sh
sudo ~/.local/share/vpn/auditar_vpn.sh
```

A limpeza de logs e temporários permanece uma operação manual e separada do
instalador, por decisão de projeto.

Os valores publicados em `examples/` são reservados para documentação. A
instalação real deve usar parâmetros fornecidos de forma autorizada e mantidos
somente em `~/.config/vpn/`.

## Auditoria final

O script `auditar_vpn.sh` não grava relatório em disco. Toda a saída é apresentada somente no terminal.
