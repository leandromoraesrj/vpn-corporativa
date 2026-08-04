# Registro de validação

## Versão 1.0.1 — 03/08/2026

### Validação isolada

- Testes automatizados do pacote aprovados.
- Compilação dos módulos Python aprovada.
- Sintaxe dos scripts Bash aprovada.
- Detecção da interface testada com comando `ip` simulado.
- Cenário com PPP preexistente aprovado: a interface antiga é ignorada.
- Cenário com PPP preexistente e uma nova PPP aprovado: a nova é selecionada.
- Validações de porta, rotas, hosts, permissões e IPv4 aprovadas.

Comando dos testes:

```bash
python3 -m unittest discover -s tests -v
```

### Validação manual informada

O layout e as funcionalidades foram validados manualmente no Linux Mint, com
desktop Cinnamon em sessão X11. Foram confirmados conexão, desconexão, split
tunneling, Internet, LAN, Docker, Tailscale e coexistência com a VPN secundária.
Nenhum novo problema foi relatado após a validação final.

### Limites da validação

- Os testes automatizados usam comandos simulados e arquivos temporários.
- Eles não conectam ao servidor corporativo e não alteram rotas reais.
- Mudanças em Linux, GTK, `openfortivpn`, firewall ou topologia exigem nova
  validação prática.
- Outras distribuições Linux ainda não foram validadas; o instalador foi
  validado somente no contexto Debian/Ubuntu com `apt`.
- Windows e macOS não são suportados.
- Sessões Wayland não foram validadas.
- Diferentes resoluções, escalas DPI e ambientes gráficos ainda precisam de
  testes adicionais.
- Não há alegação de compatibilidade universal com Linux.

## Procedimento recomendado após mudanças futuras

1. Executar testes automatizados e validações de sintaxe.
2. Instalar pelo `install.sh`.
3. Confirmar que a aplicação inicia desconectada.
4. Testar conexão e desconexão.
5. Confirmar `/run/vpn/interface` durante a conexão.
6. Confirmar que a rota padrão não usa a PPP corporativa.
7. Testar Internet, LAN, Docker, Tailscale e outros túneis ativos.
8. Executar `~/.local/share/vpn/auditar_vpn.sh`.
