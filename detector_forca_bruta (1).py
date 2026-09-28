"""
Detector de Força Bruta em Logs de Autenticação
Autor: Vinicius Huan Cardoso

Analisa um arquivo de log de autenticação (formato estilo auth.log do Linux/SSH)
e identifica padrões de força bruta: múltiplas tentativas de login falhas
vindas do mesmo IP em uma janela curta de tempo.

Uso:
    detectar_forca_bruta('auth.log')
"""

import re
from datetime import datetime
from collections import defaultdict

LIMITE_TENTATIVAS = 10      # nº de falhas para considerar suspeito
JANELA_SEGUNDOS = 300        # 5 minutos


def detectar_forca_bruta(caminho_log, limite=LIMITE_TENTATIVAS, janela=JANELA_SEGUNDOS):
    with open(caminho_log, 'r') as f:
        linhas = f.readlines()

    padrao_falha = re.compile(
        r'(?P<data>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) sshd: Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)'
    )
    padrao_sucesso = re.compile(
        r'(?P<data>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) sshd: Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)'
    )

    falhas_por_ip = defaultdict(list)
    sucessos = []

    for linha in linhas:
        m_falha = padrao_falha.search(linha)
        if m_falha:
            ts = datetime.strptime(m_falha.group('data'), '%Y-%m-%d %H:%M:%S')
            falhas_por_ip[m_falha.group('ip')].append((ts, m_falha.group('user')))
            continue
        m_sucesso = padrao_sucesso.search(linha)
        if m_sucesso:
            ts = datetime.strptime(m_sucesso.group('data'), '%Y-%m-%d %H:%M:%S')
            sucessos.append((ts, m_sucesso.group('user'), m_sucesso.group('ip')))

    print("=" * 55)
    print("DETECTOR DE FORÇA BRUTA - RELATÓRIO")
    print("=" * 55)
    print(f"\nTotal de linhas analisadas: {len(linhas)}")
    print(f"Total de tentativas falhas: {sum(len(v) for v in falhas_por_ip.values())}")
    print(f"Total de logins bem-sucedidos: {len(sucessos)}")

    alertas = []

    for ip, tentativas in falhas_por_ip.items():
        tentativas.sort(key=lambda x: x[0])
        # Verifica se há `limite` tentativas dentro da janela de tempo
        for i in range(len(tentativas) - limite + 1):
            inicio = tentativas[i][0]
            fim = tentativas[i + limite - 1][0]
            if (fim - inicio).total_seconds() <= janela:
                usuarios_tentados = set(u for _, u in tentativas)
                alertas.append({
                    'ip': ip,
                    'total_tentativas': len(tentativas),
                    'usuarios_tentados': sorted(usuarios_tentados),
                    'inicio': inicio,
                    'fim': tentativas[-1][0],
                })
                break

    print(f"\n{'=' * 55}")
    print("ALERTAS DE FORÇA BRUTA")
    print(f"{'=' * 55}")

    if not alertas:
        print("Nenhum padrão de força bruta detectado.")
    else:
        for alerta in alertas:
            print(f"\n[!] IP SUSPEITO: {alerta['ip']}")
            print(f"    Tentativas falhas: {alerta['total_tentativas']}")
            print(f"    Usuários testados: {', '.join(alerta['usuarios_tentados'])}")
            print(f"    Janela do ataque: {alerta['inicio']} até {alerta['fim']}")

            # Checa se esse IP também teve login de SUCESSO depois do ataque
            comprometido = [s for s in sucessos if s[2] == alerta['ip'] and s[0] >= alerta['inicio']]
            if comprometido:
                print(f"    >>> ALERTA CRÍTICO: login bem-sucedido detectado a partir "
                      f"desse IP após o ataque (usuário: {comprometido[0][1]}, "
                      f"horário: {comprometido[0][0]}) <<<")
                print(f"    Recomendação: possível comprometimento — escalar para "
                      f"nível superior e revogar credenciais imediatamente.")

    print(f"\n{'=' * 55}")
    return alertas


# Exemplo de uso:
# detectar_forca_bruta('auth.log')
