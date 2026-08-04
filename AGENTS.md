# Contexto para futuras sessões

## Projeto

Este repositório contém o instalador e o código-fonte da VPN Corporativa para
Linux. A aplicação usa Python 3, GTK 3, Ayatana AppIndicator e `openfortivpn`.
Os scripts Bash cuidam da instalação, conexão, desconexão, diagnóstico e
auditoria.

Idioma de comunicação com o usuário: português do Brasil.

## Estado atual

- A conexão, desconexão, atalho, autostart, auditoria e split tunneling foram
  testados com sucesso.
- Internet, LAN, Docker e Tailscale permaneceram funcionais durante os testes.
- Os testes automatizados existentes estão documentados em `VALIDATION.md`.

Consulte `VALIDATION.md` para os resultados detalhados e as limitações.

## Decisões importantes

- A VPN principal não deve ser identificada procurando qualquer interface PPP.
- O helper `vpn-connect` registra a interface criada em `/run/vpn/interface`.
- Aplicação, diagnóstico e desconexão devem usar esse estado gerenciado.
- A rota padrão nunca deve apontar para a interface PPP da VPN principal.
- Apenas as redes presentes em `~/.config/vpn/routes.conf` devem usar a VPN.
- Internet, rede local, Docker, Tailscale e outros túneis devem ser preservados.
- A conexão acontece somente por ação manual; o autostart inicia desconectado.
- Configurações existentes devem ser preservadas durante atualizações.
- Nunca exibir ou registrar o conteúdo de `connection.conf`, pois contém senha.

## Arquivos principais

- `vpn.py`: ponto de entrada.
- `vpn_app/app.py`: interface GTK e controle do ciclo de conexão.
- `vpn_app/network.py`: consultas de interfaces, rotas e métricas.
- `vpn_app/config_store.py`: leitura, validação e gravação das configurações.
- `vpn-connect`: inicia `openfortivpn`, identifica a nova PPP e aplica rotas.
- `vpn-disconnect`: encerra a conexão gerenciada e limpa o estado.
- `vpn-diagnose`: diagnóstico de conectividade e split tunneling.
- `install.sh`: atualização/instalação do aplicativo.
- `auditar_vpn.sh`: auditoria da instalação real.
- `tests/`: testes isolados que não alteram a rede do sistema.

## Validação antes de entregar mudanças

Execute, no mínimo:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile vpn.py vpn_app/*.py
for arquivo in install.sh uninstall.sh auditar_vpn.sh vpn-connect vpn-disconnect vpn-diagnose; do
    bash -n "$arquivo" || exit
done
```

Testes reais de instalação, rotas, GTK ou VPN exigem autorização explícita do
usuário. Não solicitar que o usuário envie senha de `sudo` ou credenciais VPN.

## Instalação atual

- Aplicação: `~/.local/share/vpn/`
- Configuração: `~/.config/vpn/`
- Helpers: `/usr/local/libexec/vpn-*`
- Ícones: `/usr/local/share/icons/vpn*.svg`
- Sudoers: `/etc/sudoers.d/vpn`
- Atalho: `~/.local/share/applications/vpn.desktop`
- Autostart: `~/.config/autostart/vpn.desktop`

## Commits

- Nunca criar commits automaticamente.
- Sempre apresentar um resumo das alterações antes de criar qualquer commit.
- Aguardar confirmação explícita do usuário antes de executar `git commit`.

## GitHub

- Nunca executar `git push`.
- Nunca criar Pull Requests automaticamente.
- Sempre aguardar autorização explícita.

## Segurança

Nunca:

- exibir senhas;
- exibir tokens;
- exibir certificados privados;
- exibir conteúdo de arquivos sensíveis;
- publicar informações pessoais;
- modificar regras de sudoers sem justificativa;
- remover validações de segurança existentes.

## Auditoria

Antes de considerar uma tarefa concluída:

- procurar credenciais;
- procurar caminhos absolutos;
- procurar arquivos temporários;
- procurar __pycache__;
- procurar logs;
- procurar artefatos de build;
- verificar documentação;
- verificar .gitignore;

## Refatoração

Não alterar arquitetura apenas por preferência.

Priorizar:

- menor diff possível;
- preservar comportamento;
- preservar compatibilidade;
- preservar testes existentes.
