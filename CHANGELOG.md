# Changelog

## 1.1.0 — 2026-08-07

- Protegida a credencial da VPN principal com GNOME Keyring/Secret Service.
- Configuração do `openfortivpn` criada em `memfd` selado, sem senha em arquivos,
  snapshots, argumentos, ambiente ou logs.
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
