# Centro de Controle da Rede e VPN 1.1.3

Aplicação Linux para conexão a uma VPN corporativa com split tunneling, painel GTK,
configuração integrada e diagnóstico de rede.

## Documentação do projeto

- `RELEASE_NOTES.md`: alterações da versão atual;
- `CHANGELOG.md`: histórico de versões;
- `VALIDATION.md`: testes automatizados e roteiro de validação real;
- `SECURITY.md`: política de reporte de vulnerabilidades;
- `CONTRIBUTING.md`: requisitos para contribuições;
- `AGENTS.md`: contexto técnico e orientações para futuras sessões de trabalho.

## Funcionalidades consolidadas

- ícone na bandeja com estados cinza, amarelo, verde e vermelho;
- conexão manual, com reconexão automática opcional da VPN principal (ativada por padrão);
- Internet, LAN, Docker e Tailscale preservados fora da VPN principal;
- rotas corporativas controladas por `routes.conf`;
- mapa de hosts controlado por `hosts.conf`;
- painel agrupado por contexto;
- métricas separadas da Internet/rede local e da VPN principal;
- diagnóstico conectado ou desconectado;
- diagnóstico TLS integrado ao diagnóstico geral;
- feedback de início e término do diagnóstico;
- configuração de conexão, sub-redes e hosts dentro da aplicação;
- interface da VPN secundária configurável, com descoberta manual assistida;
- log técnico da conexão;
- verificação de integridade sob demanda;
- auditoria específica da instalação;
- coleta completa somente com a janela visível.

## Instalação

```bash
chmod +x install.sh uninstall.sh auditar_vpn.sh
sudo ./install.sh
```

O instalador preserva configurações existentes, encerra versões antigas e inicia
o ícone na bandeja sem conectar automaticamente. O autostart após reinício do
sistema também inicia desconectado; a preferência de reconexão automática só
controla novas quedas durante a execução do programa e não altera esse
comportamento.

### Compatibilidade validada

O ambiente oficialmente testado é Linux Mint, com desktop Cinnamon em sessão
X11. O instalador é destinado a distribuições baseadas em Debian/Ubuntu que
utilizam `apt`.

Outras distribuições Linux ainda não foram validadas. Windows e macOS não são
suportados, e sessões Wayland não foram validadas. Diferentes resoluções,
escalas DPI e ambientes gráficos ainda precisam de testes adicionais. Portanto,
o projeto não declara compatibilidade universal com Linux.

### Dependências

O `install.sh` verifica ou instala, por meio do `apt`, os seguintes pacotes:

- `openfortivpn`;
- `python3`;
- `python3-gi`;
- `gir1.2-gtk-3.0`;
- `gir1.2-ayatanaappindicator3-0.1`;
- `gir1.2-secret-1`;
- `libnotify-bin`;
- `xdg-utils`;
- `curl`;
- `wmctrl`;
- `xdotool`;
- `openssl`.

Também é necessário ter um navegador padrão para a autenticação web da VPN
secundária. O cliente oficial compatível com a infraestrutura corporativa deve
ser fornecido ou instalado separadamente. Os controles de janela da VPN
secundária dependem de `wmctrl` e `xdotool` e podem não funcionar corretamente
em Wayland.

## Configuração

```text
~/.config/vpn/connection.conf
~/.config/vpn/routes.conf
~/.config/vpn/hosts.conf
~/.config/vpn/secondary.conf
~/.config/vpn/preferences.conf
```

Os arquivos em `examples/` contêm apenas endereços e nomes reservados para
documentação. Antes da primeira conexão, substitua-os localmente pelos valores
autorizados do ambiente. A configuração existente é preservada em atualizações.
A URL de autenticação web da VPN secundária pode ser informada na aba
**Configuração**, sem ser incorporada ao código ou aos logs.

Na configuração da VPN secundária, as rotas são informadas por linhas
repetíveis `route = valor`. A diretiva `interface` tem três comportamentos:

- diretiva ausente: usa `tun0` como fallback de compatibilidade;
- `interface =` explicitamente vazia: mantém o modo manual, sem assumir uma
  interface e sem exibir a VPN secundária como conectada;
- `interface = nome`: monitora exatamente a interface Linux configurada, sem
  substituí-la por `tun0` ou por outro túnel detectado.

O botão **Atualizar interfaces** apenas lista candidatas de túnel para auxiliar
a descoberta manual. A lista não representa a interface salva e não altera a
configuração: é necessário selecionar uma candidata e confirmar em **Salvar
configurações da VPN secundária**. Se a interface já salva não estiver entre as
candidatas atuais, nenhuma outra é selecionada automaticamente e o valor salvo
é preservado até uma nova confirmação.

A lista informa nome, estado, tipo, IPv4, rotas observadas e uma observação
técnica sanitizada. Interfaces Ethernet, bridges, interfaces de contêineres e
outros tipos não compatíveis não são oferecidos. O seletor não inicia conexão
nem autenticação; conecte a VPN secundária manualmente antes de atualizar a
lista quando necessário.

A opção **Reconexão automática da VPN principal** fica na aba **Configuração**.
Ela é ativada por padrão para preservar o comportamento atual, pode ser
desativada pelo usuário e é persistida separadamente, sem armazenar senha.
Cada tentativa recupera a senha do GNOME Keyring. Desativar a preferência
também cancela uma reconexão em espera ou em andamento. O programa não
reconecta automaticamente a VPN secundária e não conecta nenhuma VPN no
autostart.

A senha da VPN principal é armazenada no GNOME Keyring pelo Secret Service.
O `connection.conf` gerado e os snapshots privilegiados contêm somente os
parâmetros não secretos. Durante a conexão, a aplicação envia uma mensagem
delimitada por tamanho pela entrada padrão do helper privilegiado; ele monta a
configuração do `openfortivpn` em um `memfd` selado, sem criar arquivo de senha.
A aplicação não persiste nem exibe a credencial em seus logs ou relatórios;
saídas de componentes externos devem continuar a ser tratadas como sensíveis.

### Políticas de certificado

As políticas aceitas em `connection.conf` são:

- `legacy-pinned`: padrão quando `certificate-policy` está ausente; exige
  `trusted-cert` como fingerprint SHA-256 hexadecimal de 64 caracteres;
- `system-ca`: usa a validação normal pela cadeia de confiança do sistema e pelo
  hostname/SAN; exige configuração explícita e não aceita `trusted-cert`;
- `system-ca-with-pinned-fallback`: exige `trusted-cert` e permite o pin como
  fallback quando a validação normal não é suficiente; não é o padrão.

Um fingerprint correspondente não deve ser interpretado isoladamente como
validação do hostname/SAN.

O botão **Executar diagnóstico geral** integra a coleta de subject, SAN, emissor,
validade e fingerprint SHA-256 do certificado. O relatório separa cadeia CA,
hostname/SAN e correspondência com o `trusted-cert`, permitindo interpretar o
resultado conforme a política configurada. O diagnóstico é somente informativo:
não atualiza a confiança, não instala CA, não implementa TOFU e não aceita um
certificado automaticamente. Os campos de política e fingerprint permanecem
fora da interface gráfica.

O perfil confirmado do `openfortivpn 1.21.0` é diagnosticado por IPv4, sem SNI
e com a mesma semântica `X509_check_host` aplicada ao certificado da observação.
Uma versão do cliente sem perfil comprovado resulta em aviso indeterminado, sem
afirmar equivalência ou aceitar fallback automaticamente.

## Modelo de rede e limitações

O programa é uma alternativa técnica local para Linux, sujeita à
compatibilidade com os servidores e políticas corporativas. Não substitui
oficialmente clientes comerciais ou clientes fornecidos pelo fabricante.

O split tunneling mantém o tráfego comum pela interface local e direciona
somente as redes corporativas pelas interfaces VPN. Rotas específicas podem ser
configuradas, e nomes podem ser resolvidos para IPv4 antes de uma rota ser
aplicada. Alterações de DNS podem mudar os endereços; por isso, valores
resolvidos não são persistidos automaticamente. Redes sobrepostas entre as
duas VPNs dependem da prioridade efetiva do sistema e podem tornar o destino
ambíguo; a aplicação deve sinalizar a inconsistência em vez de escolher uma
interface silenciosamente.

A VPN secundária depende do navegador e do cliente oficial disponibilizado para
o ambiente corporativo. A autenticação sensível continua manual.

O diagnóstico técnico da VPN secundária avalia processo, interface, endereço
IPv4 e todas as rotas configuradas. Antes do fluxo manual, a aplicação registra
um snapshot privado de processos, interfaces, endereços e rotas. Estados antigos,
órfãos, múltiplos candidatos ou evidências insuficientes permanecem como
inconsistentes ou ambíguos no diagnóstico.

O estado operacional exibido separa-se do diagnóstico técnico. A aplicação só
considera a interface salva em `secondary.conf`; ela precisa ser um túnel ativo
e ter IPv4 válido para aparecer como **CONECTADA**. As interfaces mostradas na
descoberta são apenas opções para seleção e não se tornam operacionais até serem
salvas. O diagnóstico técnico pode continuar indicando associação ambígua ou
inconsistente.

O certificado do servidor precisa ser validado pela cadeia confiável do sistema
ou por uma impressão digital previamente conhecida. Falhas não aceitam o
primeiro certificado automaticamente.

## Arquivos de estado

```text
~/.local/state/vpn/connection.log
~/.local/state/vpn/diagnostic-latest.txt
~/.local/state/vpn/launcher.log
~/.local/state/vpn/tray-icon-*.svg
```

A versão 1.1.3 não usa `/tmp` para logs permanentes e remove resíduos conhecidos
de versões anteriores durante a instalação.

Os SVGs `tray-icon-*.svg` são estados transitórios do ícone dividido e não
contêm credenciais.

## Remoção

```bash
sudo ./uninstall.sh
```

O desinstalador pergunta separadamente se deve preservar a configuração e se
deve remover a credencial do GNOME Keyring. A remoção do segredo só prossegue
após confirmação explícita e, se falhar, a desinstalação é interrompida.

## Testes isolados

As validações que não exigem uma VPN real podem ser executadas sem privilégios:

```bash
python3 -m unittest discover -s tests -v
```

Os testes usam diretórios temporários e comandos de rede simulados; não alteram
rotas, `/etc/hosts` ou a instalação ativa.

## Política de notificações

A versão 1.1.3 exibe notificações do sistema somente em caso de erro real:

- falha ao conectar;
- falha definitiva após as tentativas de reconexão;
- falha encontrada pelo diagnóstico;
- erro interno da aplicação.

Conexões, reconexões, salvamentos e diagnósticos concluídos com sucesso são
mostrados apenas no painel, no estado do ícone ou na aba correspondente.

O ícone da bandeja é dividido entre a VPN principal e a VPN secundária: cada
metade fica verde quando a VPN correspondente está
conectada. O menu oferece **Conectar**/**Desconectar**,
status independente das duas conexões, **Conectar VPN Principal**/**Desconectar
VPN Principal**, **Autenticar VPN Secundária**, controles da janela da VPN
secundária e **Abrir Centro de Controle**.
Esse último item executa novamente o teste de integridade antes de abrir e
focar o painel.

## Diagnóstico final

Eventos esperados e não problemáticos são classificados como `INFO`, sem
aumentar a contagem de avisos:

- VPN secundária ativa na interface configurada;
- tráfego específico usando outro túnel conhecido;
- host corporativo corretamente resolvido e roteado, mas sem resposta ICMP.

O `vpn-diagnose` usa exatamente a interface configurada para o estado da VPN
secundária. `tun0` é usado apenas quando a diretiva `interface` está ausente; no
modo manual nenhuma interface é assumida. Outros túneis detectados são exibidos
somente como informação e não validam a VPN secundária. O estado `OK` exige uma
interface `tun`, `tap` ou `ppp` ativa, com IPv4 válido e sem conflito com a VPN
principal.

Avisos permanecem reservados para situações que podem exigir atenção.

## Comportamento ao fechar

- fechar a janela pelo **X** apenas oculta a interface e mantém a VPN;
- selecionar **Sair** encerra a interface gráfica e preserva os túneis ativos.

## Auditoria da instalação

A auditoria é exibida somente no terminal e não gera arquivo TXT:

```bash
sudo ~/.local/share/vpn/auditar_vpn.sh
```
