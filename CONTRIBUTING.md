# Contribuindo

Antes de propor uma alteração:

1. Não inclua credenciais, configurações locais nem identificadores reais de
   infraestrutura.
2. Use somente endereços e domínios reservados para documentação em exemplos e
   testes.
3. Preserve o split tunneling, o estado gerenciado em `/run/vpn` e a fronteira
   entre a interface do usuário e os helpers privilegiados.
4. Não sobrescreva `connection.conf`, `routes.conf`, `hosts.conf` ou
   `secondary.conf` durante atualizações.
5. Execute `./validate_release.sh` e `git diff --check`.

Mudanças que alterem rede, sudoers, instalação ou interface gráfica devem ser
descritas com o impacto e com o procedimento de validação manual aplicável.
