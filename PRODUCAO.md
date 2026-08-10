# Centro de Controle da Rede e VPN 1.1.3 — Produção

Esta é a release de segurança, diagnóstico e configuração 1.1.3.

## Compatibilidade e requisitos

O ambiente oficialmente testado é Linux Mint, com Cinnamon em sessão X11, em
uma base Debian/Ubuntu com instalação de dependências via `apt`. Outras
distribuições Linux e sessões Wayland ainda não foram validadas. Windows e
macOS não são suportados. Diferentes resoluções, escalas DPI e ambientes
gráficos ainda precisam de testes adicionais; não se declara compatibilidade
universal com Linux.

O `install.sh` verifica ou instala `openfortivpn`, `python3`, `python3-gi`,
`gir1.2-gtk-3.0`, `gir1.2-ayatanaappindicator3-0.1`, `gir1.2-secret-1`,
`libnotify-bin`, `xdg-utils`, `curl`, `wmctrl`, `xdotool` e `openssl`. É
necessário um navegador padrão para autenticação web da VPN secundária, e o
cliente oficial compatível deve ser fornecido ou instalado separadamente. Os
controles de janela da VPN secundária dependem de `wmctrl` e `xdotool` e podem
não funcionar corretamente em Wayland.

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
- selecionar **Sair** encerra a interface gráfica e preserva os túneis ativos;
- aliases internos de `/etc/hosts` podem conter `_`;
- o helper privilegiado revalida os arquivos de configuração;
- senha da instalação inicial não é transmitida nos argumentos do processo;
- senha da VPN principal armazenada no GNOME Keyring/Secret Service;
- `connection.conf` gerado e snapshots privilegiados não contêm a senha;
- credencial enviada em frame delimitado pela entrada padrão e configuração
  transitória criada em `memfd` selado;
- a aplicação não persiste nem exibe a credencial em seus logs ou relatórios;
- timeout de conexão usa `TERM` e `KILL` como último recurso;
- logs e relatórios ficam em `~/.local/state/vpn`;
- arquivos de configuração ficam em `~/.config/vpn`;
- políticas TLS explícitas cobrem pin legado, CA do sistema e CA do sistema com
  fallback por pin, sem confiança automática;
- o diagnóstico geral integra informações de certificado e separa os resultados
  de cadeia CA, hostname/SAN e correspondência do fingerprint; o perfil
  confirmado do `openfortivpn 1.21.0` não envia SNI e usa `X509_check_host`,
  enquanto versões sem perfil comprovado permanecem indeterminadas;
- a reconexão automática da VPN principal é configurável, persistida sem senha
  e pode ser cancelada durante uma tentativa;
- a identidade visual atual é **Centro de Controle da Rede e VPN**, com a
  terminologia genérica **VPN secundária** nos controles visíveis;
- o estado operacional da VPN secundária usa uma interface de túnel
  explicitamente configurada, ativa e com IPv4 válido; a associação do processo
  e das rotas permanece no diagnóstico técnico;
- processos, interfaces, endereços e rotas existentes antes do fluxo manual
  são registrados como snapshot e não validam sozinhos uma nova conexão;
- `tun0` é apenas o fallback quando a diretiva `interface` está ausente; uma
  diretiva explicitamente vazia mantém o modo manual e uma diretiva preenchida
  usa exatamente a interface configurada;
- a lista de descoberta contém candidatas para seleção, não substitui a
  interface salva, não escolhe a primeira automaticamente e exige confirmação
  antes de alterar a configuração;
- o `vpn-diagnose` avalia a interface secundária configurada e só informa `OK`
  para túnel `tun`/`tap`/`ppp` ativo, com IPv4 válido e sem conflito com a VPN
  principal; outros túneis são somente informativos e não validam essa conexão.

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
