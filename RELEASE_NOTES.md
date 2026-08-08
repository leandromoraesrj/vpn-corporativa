# VPN Corporativa 1.1.1 — Ícone e menu

Esta versão corrige a documentação de compatibilidade e a nomenclatura técnica
da VPN principal, sem alterar funcionalidades.

## Alterações da versão 1.1.1

- senha da VPN principal armazenada no GNOME Keyring via Secret Service;
- configuração transitória do `openfortivpn` criada em `memfd` selado;
- snapshots, argumentos, ambiente e logs sem a credencial;
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
e um navegador padrão para autenticação web são requisitos externos. **Ocultar
F5** e **Exibir F5** dependem de `wmctrl` e `xdotool` e podem não funcionar
corretamente em Wayland.

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


## Revisão de encerramento

- a opção **Sair** agora executa `vpn-disconnect` antes de encerrar o GTK;
- o estado de reconexão automática é desativado antes da desconexão;
- a aplicação aguarda até 20 segundos pelo helper;
- fechar apenas a janela continua ocultando o aplicativo e mantém a VPN,
  enquanto **Sair** encerra a VPN e o programa.

## Revisão de credenciais

- o parser privilegiado remove apenas o único espaço de formatação após `=` na diretiva `password`;
- espaços adicionais no início e no fim da senha são preservados como parte da credencial;
- a leitura da configuração pela interface segue a mesma regra;
- senha formada somente por espaços continua inválida;
- adicionados testes específicos de regressão.
