# VPN Corporativa 1.1.0 — Produção

Esta é a release de segurança 1.1.0.

## Compatibilidade e requisitos

O ambiente oficialmente testado é Linux Mint, com Cinnamon em sessão X11, em
uma base Debian/Ubuntu com instalação de dependências via `apt`. Outras
distribuições Linux e sessões Wayland ainda não foram validadas. Windows e
macOS não são suportados. Diferentes resoluções, escalas DPI e ambientes
gráficos ainda precisam de testes adicionais; não se declara compatibilidade
universal com Linux.

O `install.sh` verifica ou instala `openfortivpn`, `python3`, `python3-gi`,
`gir1.2-gtk-3.0`, `gir1.2-ayatanaappindicator3-0.1`, `libnotify-bin`,
`xdg-utils`, `curl`, `wmctrl` e `xdotool`. É necessário um navegador padrão
para autenticação web, e o cliente BIG-IP/F5 deve ser fornecido ou instalado
separadamente. **Ocultar F5** e **Exibir F5** dependem de `wmctrl` e `xdotool`
e podem não funcionar corretamente em Wayland.

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
- senha da VPN principal armazenada no GNOME Keyring/Secret Service;
- snapshots e arquivos de configuração não contêm a senha;
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
