# Detector de Força Bruta em Logs de Autenticação

Ferramenta em Python para análise de logs de autenticação (estilo `auth.log` do Linux/SSH), desenvolvida como projeto prático na minha transição de carreira para Cibersegurança (Blue Team / SOC).

## O que a ferramenta faz

- Lê um arquivo de log de autenticação e separa tentativas de login **falhas** e **bem-sucedidas**
- Agrupa as tentativas falhas por IP de origem
- Identifica **padrões de força bruta**: um mesmo IP com um número alto de tentativas falhas dentro de uma janela curta de tempo (parâmetros configuráveis — padrão: 10 tentativas em 5 minutos)
- Lista os usuários que foram alvo das tentativas (ex: `admin`, `root`, `test`)
- **Correlaciona eventos**: verifica se, após o padrão de força bruta, houve um login bem-sucedido vindo do mesmo IP — sinal de possível comprometimento, com recomendação de escalonamento

## Por que este projeto

Identificar tentativas de força bruta e correlacionar eventos suspeitos com o histórico de acessos é uma das tarefas centrais de um Analista de SOC Jr na triagem diária de alertas. Este projeto simula, de forma simplificada, esse processo de análise: da leitura bruta do log até a conclusão acionável ("possível comprometimento, escalar").

## Como usar

```python
from detector_forca_bruta import detectar_forca_bruta

detectar_forca_bruta('auth.log')
```

Parâmetros opcionais:

```python
detectar_forca_bruta('auth.log', limite=10, janela=300)  # 10 tentativas em 300 segundos
```

Um script `gerar_log.py` está incluído para gerar um log de exemplo sintético (sem dados reais), simulando tráfego normal misturado a um ataque de força bruta seguido de comprometimento.

## Exemplo de saída

```
=======================================================
DETECTOR DE FORÇA BRUTA - RELATÓRIO
=======================================================

Total de linhas analisadas: 56
Total de tentativas falhas: 40
Total de logins bem-sucedidos: 16

=======================================================
ALERTAS DE FORÇA BRUTA
=======================================================

[!] IP SUSPEITO: 185.220.101.47
    Tentativas falhas: 40
    Usuários testados: admin, oracle, root, test, ubuntu
    Janela do ataque: 2026-09-23 10:15:00 até 2026-09-23 10:17:36
    >>> ALERTA CRÍTICO: login bem-sucedido detectado a partir
    desse IP após o ataque (usuário: root, horário: 2026-09-23 10:17:44) <<<
    Recomendação: possível comprometimento — escalar para
    nível superior e revogar credenciais imediatamente.
```

## Próximos passos planejados

- Suporte a logs no formato de Windows Event Viewer (Security log)
- Verificação de reputação do IP suspeito via API pública (ex: AbuseIPDB)
- Exportação do relatório em CSV/JSON para integração com outras ferramentas

## Autor

**Vinicius Huan Cardoso**
Em transição de Suporte Técnico / Redes para Cibersegurança (Blue Team / SOC Jr)
[LinkedIn](https://www.linkedin.com/in/vinicius-huan-cardoso-771465234/) · [GitHub](https://github.com/TI-Vinicius-Huan)
