# Changelog

## 1.1.3 — 2026-08-09

- Reforçada a proteção da credencial da VPN principal com GNOME Keyring,
  transporte enquadrado pela entrada padrão e configuração transitória em
  `memfd` selado.
- Tornadas explícitas as políticas de certificado e integrado ao diagnóstico
  geral um relatório TLS correlacionado, sem alteração automática de confiança.
- Alinhado o perfil TLS confirmado do `openfortivpn 1.21.0`, sem SNI e com
  validação de hostname por `X509_check_host`; versões sem perfil comprovado
  permanecem como resultado indeterminado.
- Tornada configurável a interface da VPN secundária, com fallback `tun0`
  somente quando a diretiva está ausente, modo manual explícito e descoberta
  assistida sem seleção automática.
- Alinhado o `vpn-diagnose` ao estado operacional da aplicação, exigindo
  interface configurada ativa, tipo de túnel compatível, IPv4 válido e ausência
  de conflito com a VPN principal.
- Tornada configurável e cancelável a reconexão automática da VPN principal,
  inclusive quando a desconexão manual ocorre durante o backoff.
- Corrigidos estados, ações, foco, visibilidade e atualização da interface e da
  bandeja sem alterar o autostart desconectado.
- Unificada a validação estrutural usada pelo diagnóstico e pelo helper
  privilegiado para rejeitar diretivas duplicadas, desconhecidas ou inseguras.
- Ampliadas as validações automatizadas de credencial, TLS, concorrência,
  interface secundária, diagnóstico, instalação e remoção.

## 1.1.2 — 2026-08-07

- Renomeada a interface visual para **Centro de Controle da Rede e VPN** e
  padronizada a terminologia visível da VPN secundária.
- Corrigidas a detecção de visibilidade, a alternância dos controles da janela
  secundária, a atualização da bandeja e a remoção dos ícones divididos.
- Consolidado o uso do GNOME Keyring, com senha fora do `connection.conf`
  gerado e dos snapshots privilegiados, frame pela entrada padrão e configuração
  transitória em `memfd` selado.
- Adicionadas políticas TLS explícitas e diagnóstico de certificado integrado ao
  diagnóstico geral, sem confiança automática.
- Adicionada configuração da interface secundária com fallback `tun0` somente
  quando a diretiva está ausente, modo manual vazio e seleção explícita entre
  candidatas de descoberta.
- Tornada configurável a reconexão automática da VPN principal, incluindo o
  cancelamento de tentativas, sem alterar o autostart desconectado.
- Atualizado o `vpn-diagnose` para usar a interface secundária configurada e
  tratar outros túneis somente como informação.
- Alterado **Sair** para encerrar a interface gráfica preservando os túneis
  ativos.
- Manifesto, documentação e testes sincronizados com os arquivos atuais.

## 1.1.1 — 2026-08-07

- Aprimorado o ícone da bandeja com estados independentes das duas VPNs.
- Reorganizado o menu com status, ações, abertura do painel e controle da janela.
- Atualizados título, aba principal, foco e testes do tray.

## 1.1.0 — 2026-08-07

- Protegida a credencial da VPN principal com GNOME Keyring/Secret Service.
- Configuração do `openfortivpn` criada em `memfd` selado; a aplicação deixou de
  persistir ou exibir a senha em seus arquivos, snapshots, logs e relatórios.
- Migração legada, reconexão automática, auditoria, uninstall e testes de
  segurança atualizados.

## 1.0.1 — 2026-08-03

- Corrigida a nomenclatura visível da VPN principal para OpenFortiVPN.
- Documentado o ambiente oficialmente validado: Linux Mint, Cinnamon e X11.
- Registrados os limites de compatibilidade com outras distribuições, Wayland,
  resoluções, escalas DPI e ambientes gráficos.
- Documentadas as dependências verificadas pelo instalador e os requisitos
  externos da autenticação web e do cliente BIG-IP/F5.
- Nenhuma funcionalidade de conexão ou rede foi alterada.

## 1.0 — 2026-08-03

- Primeira versão de produção.
- Split tunneling restrito às redes corporativas configuradas.
- Painel gráfico com métricas separadas de Internet e VPN principal.
- VPN secundária por autenticação web via BIG-IP/F5.
- Diagnóstico de Internet, LAN, VPN principal, VPN secundária, Tailscale,
  Docker e firewall.
- Inicialização automática apenas na bandeja e sem conexão automática.
- Instância única e auditoria própria da instalação.

- Preservados espaços significativos no início e no fim de senhas da VPN.
- Corrigidos tanto o parser privilegiado quanto a leitura da configuração pela interface.
- Adicionados testes de regressão para senha com espaços e senha composta apenas por espaços.

### Revisão de robustez

- Corrigida resolução de usuário e grupo principal.
- Configuração inicial validada antes da gravação.
- Processos de conexão encerrados com TERM/KILL após timeout.
- Logs e diagnóstico movidos de `/tmp` para `~/.local/state/vpn`.
- Auditoria final com saída exclusiva no terminal, sem gerar relatório em disco.
- Nome visual estabilizado como `VPN Corporativa`.
- Removida chamada duplicada de finalização do diagnóstico.
- Alegações de validação real não comprovadas foram removidas.


### Revisão de segurança e rede

- Interface da VPN vinculada ao estado gerenciado em `/run/vpn/interface`.
- Outras interfaces PPP deixam de ser identificadas como VPN principal.
- Tratamento visual de erros ao salvar conexão, sub-redes e hosts.
- Proteção contra quebras de linha nos campos de conexão.
- Validação numérica completa do endereço IPv4 público.
- Docker e Tailscale removidos das dependências obrigatórias de integridade.
- Dependências não utilizadas removidas do instalador.
- Tempo de espera do aplicativo alinhado ao helper de conexão.
- Testes isolados adicionados.
- Configurações existentes preservadas durante atualizações.
- Notificações limitadas a erros reais.
