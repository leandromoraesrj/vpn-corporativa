# VPN Corporativa 1.0

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
- conexão somente por ação manual;
- Internet, LAN, Docker e Tailscale preservados fora da VPN principal;
- rotas corporativas controladas por `routes.conf`;
- mapa de hosts controlado por `hosts.conf`;
- painel agrupado por contexto;
- métricas separadas da Internet/rede local e da VPN principal;
- diagnóstico conectado ou desconectado;
- feedback de início e término do diagnóstico;
- configuração de conexão, sub-redes e hosts dentro da aplicação;
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
o ícone na bandeja sem conectar automaticamente.

## Configuração

```text
~/.config/vpn/connection.conf
~/.config/vpn/routes.conf
~/.config/vpn/hosts.conf
~/.config/vpn/secondary.conf
```

Os arquivos em `examples/` contêm apenas endereços e nomes reservados para
documentação. Antes da primeira conexão, substitua-os localmente pelos valores
autorizados do ambiente. A configuração existente é preservada em atualizações.
A URL de autenticação web da VPN secundária pode ser informada na aba
**Configuração**, sem ser incorporada ao código ou aos logs.

## Arquivos de estado

```text
~/.local/state/vpn/connection.log
~/.local/state/vpn/diagnostic-latest.txt
~/.local/state/vpn/launcher.log
```

A versão 1.0 não usa `/tmp` para logs permanentes e remove resíduos conhecidos
de versões anteriores durante a instalação.

## Remoção

```bash
sudo ./uninstall.sh
```

## Testes isolados

As validações que não exigem uma VPN real podem ser executadas sem privilégios:

```bash
python3 -m unittest discover -s tests -v
```

Os testes usam diretórios temporários e comandos de rede simulados; não alteram
rotas, `/etc/hosts` ou a instalação ativa.

## Política de notificações

A versão 1.0 exibe notificações do sistema somente em caso de erro real:

- falha ao conectar;
- falha definitiva após as tentativas de reconexão;
- falha encontrada pelo diagnóstico;
- erro interno da aplicação.

Conexões, reconexões, salvamentos e diagnósticos concluídos com sucesso são
mostrados apenas no painel, no estado do ícone ou na aba correspondente.
## Diagnóstico final

Eventos esperados e não problemáticos são classificados como `INFO`, sem
aumentar a contagem de avisos:

- VPN secundária ativa em `tun0`;
- tráfego específico usando outro túnel conhecido;
- host corporativo corretamente resolvido e roteado, mas sem resposta ICMP.

Avisos permanecem reservados para situações que podem exigir atenção.


## Comportamento ao fechar

- fechar a janela pelo **X** apenas oculta a interface e mantém a VPN;
- selecionar **Sair** no menu desconecta a VPN e encerra o aplicativo.

## Auditoria da instalação

A auditoria é exibida somente no terminal e não gera arquivo TXT:

```bash
sudo ~/.local/share/vpn/auditar_vpn.sh
```
