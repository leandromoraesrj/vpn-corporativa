# Centro de Controle da Rede e VPN 1.1.3 — Segurança, diagnóstico e configuração

Esta versão consolida a proteção da credencial, as políticas TLS, o diagnóstico
e a configuração da VPN secundária, além de atualizar a identidade visual e os
controles operacionais.

## Alterações da versão 1.1.3

- identidade visual renomeada para **Centro de Controle da Rede e VPN**, com a
  terminologia genérica **VPN secundária** nos controles atuais;
- detecção da visibilidade da janela secundária pelo estado real do gerenciador
  de janelas, remoção do estado minimizado ao exibi-la e sincronização dos
  botões e do menu;
- status do menu identificados como **VPN Principal** e **VPN Secundária** e
  correção da limpeza dos ícones divididos no uninstall;
- senha da VPN principal armazenada no GNOME Keyring via Secret Service, fora do
  `connection.conf` gerado e dos snapshots privilegiados;
- credencial enviada em frame delimitado pela entrada padrão ao helper, que cria
  a configuração transitória do `openfortivpn` em `memfd` selado;
- a aplicação não persiste nem exibe a credencial em seus logs ou relatórios;
- configuração salva revalidada pelo mesmo parser estrutural usado pelo helper
  privilegiado, com rejeição de diretivas duplicadas, desconhecidas ou fixas em
  valores inseguros;
- políticas `legacy-pinned`, `system-ca` e
  `system-ca-with-pinned-fallback`, com requisitos explícitos para
  `trusted-cert` e sem aceitação automática de certificado;
- diagnóstico TLS integrado ao diagnóstico geral, com resultados separados para
  cadeia CA, hostname/SAN, validade e correspondência do fingerprint, sem
  instalar CA, alterar confiança ou implementar TOFU;
- perfil confirmado do `openfortivpn 1.21.0` reproduzido sem SNI, por IPv4 e com
  `X509_check_host` sobre o certificado da mesma observação; versões sem perfil
  comprovado produzem aviso indeterminado e nunca um falso resultado `OK`;
- interface da VPN secundária configurável: `tun0` é fallback somente quando a
  diretiva está ausente, valor vazio mantém o modo manual e um nome preenchido é
  usado exatamente como salvo;
- descoberta manual que lista candidatas sem confundi-las com a interface salva,
  sem seleção implícita e com confirmação antes de persistir uma escolha;
- reconexão automática da VPN principal configurável e cancelável, sem conexão
  automática no autostart e sem reconexão da VPN secundária, com revalidação do
  cancelamento após cada backoff e antes de iniciar o helper privilegiado;
- `vpn-diagnose` alinhado à interface secundária configurada, com outros túneis
  apresentados somente como informação e estado `OK` restrito a interfaces
  `tun`/`tap`/`ppp` ativas, com IPv4 válido e sem conflito com a VPN principal;
- **Sair** encerra a interface gráfica e preserva os túneis ativos;
- correções de estado, foco, visibilidade, controles e atualização do painel e
  da bandeja;
- manifesto, documentação e suíte de testes sincronizados com os arquivos e as
  regras de validação atuais.

## Alterações consolidadas da versão 1.1.1

- senha da VPN principal armazenada no GNOME Keyring via Secret Service;
- configuração transitória do `openfortivpn` criada em `memfd` selado;
- a aplicação não persiste nem exibe a credencial em arquivos, snapshots ou
  seus próprios logs e relatórios;
- migração legada e remoção opcional do segredo no uninstall.
- ícone da bandeja dividido entre as duas VPNs, com menu sincronizado
  aos controles do painel.
- status independente por metade, incluindo espera, conexão e erro;
- menu com abertura do painel, estados informativos e alternância dos comandos;
- título, aba principal e foco da janela revisados.

## Correções consolidadas da versão anterior

- o painel identifica a VPN principal como **OpenFortiVPN**;
- o ambiente oficialmente testado é Linux Mint, com Cinnamon em sessão X11;
- o instalador é destinado a distribuições baseadas em Debian/Ubuntu com `apt`;
- outras distribuições Linux e sessões Wayland ainda não foram validadas;
- Windows e macOS não são suportados;
- diferentes resoluções, escalas DPI e ambientes gráficos ainda precisam de
  testes adicionais;
- as dependências do instalador e os requisitos externos do BIG-IP/F5 foram
  documentados.

Não há declaração de compatibilidade universal com Linux. O cliente BIG-IP/F5
e um navegador padrão para autenticação web são requisitos externos. **Ocultar F5**
e **Exibir F5** dependem de `wmctrl` e `xdotool` e podem não funcionar corretamente
em Wayland.

## Correções consolidadas

- identificação exclusiva da interface PPP gerenciada;
- proteção contra conflito com outras conexões PPP;
- validação de porta e bloqueio de caracteres de controle;
- mensagens claras ao salvar configurações inválidas;
- validação numérica do IPv4 público;
- Docker e Tailscale tratados como opcionais;
- dependências sem uso removidas;
- resolução segura de usuário e grupo principal;
- validação inicial compartilhada entre instalador e aplicação;
- encerramento do processo de conexão após timeout;
- logs persistentes em `~/.local/state/vpn`;
- auditoria sem acúmulo de relatórios;
- remoção de resíduos antigos em `/tmp`;
- nome visual estável como **VPN Corporativa**;
- correção da chamada duplicada ao finalizar o diagnóstico.

## Validação automatizada

A release é validada por testes unitários, análise de sintaxe Python e Bash e
verificações estáticas dos arquivos do instalador. Esses testes não conectam à
VPN real e não alteram rotas, `/etc/hosts` ou firewall.

## Validação manual

A validação manual registrada em `VALIDATION.md` confirmou:

- conexão e desconexão;
- rota padrão fora da interface PPP;
- split tunneling;
- Internet e rede local;
- coexistência com a VPN secundária, Tailscale e Docker;
- reconexão após queda;
- diagnóstico completo.

## Revisão de segurança

- senha da configuração inicial transmitida ao validador pela entrada
  padrão, sem exposição nos argumentos do processo;
- helper privilegiado revalida `connection.conf`, `routes.conf` e
  `hosts.conf` antes de alterar rede, rotas ou `/etc/hosts`;
- links simbólicos e diretivas desconhecidas são rejeitados;
- timeout direto do `vpn-connect` usa TERM, espera limitada e KILL como
  último recurso;
- auditoria do sudoers funciona tanto como root quanto como usuário comum,
  sem pressupor autorização para executar `visudo` sem senha;
- testes de regressão ampliados.


## Revisão de validação de hosts

- aliases internos em `hosts.conf` agora podem conter `_`;
- a regra continua rejeitando espaços, barras, dois-pontos, caracteres de
  controle, labels vazios e pontuação inválida nas extremidades;
- incluído teste específico para aliases internos com `_`.


## Histórico da revisão de encerramento

- naquela revisão, a opção **Sair** passou a executar `vpn-disconnect` antes de
  encerrar o GTK;
- o estado de reconexão automática era desativado antes da desconexão;
- a aplicação aguardava até 20 segundos pelo helper;
- fechar apenas a janela ocultava o aplicativo e mantinha a VPN, enquanto
  **Sair** encerrava a VPN e o programa.

Na versão 1.1.2, esse comportamento histórico foi substituído: **Sair** encerra
a interface gráfica e preserva os túneis ativos.

## Revisão de credenciais

- o parser privilegiado remove apenas o único espaço de formatação após `=` na diretiva `password`;
- espaços adicionais no início e no fim da senha são preservados como parte da credencial;
- a leitura da configuração pela interface segue a mesma regra;
- senha formada somente por espaços continua inválida;
- adicionados testes específicos de regressão.
