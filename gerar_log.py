"""
Gerador de log de exemplo (sintético) para testar o detector_forca_bruta.py

Simula um dia de acessos SSH: tráfego normal misturado a um ataque de
força bruta seguido de um login bem-sucedido (possível comprometimento).

Nenhum dado real é utilizado — todos os IPs, usuários e horários são
gerados artificialmente apenas para fins de demonstração.
"""

import random
from datetime import datetime, timedelta

usuarios = ['admin', 'root', 'vinicius', 'suporte', 'backup']
ips_normais = ['192.168.1.10', '192.168.1.22', '10.0.0.5']
ip_atacante = '185.220.101.47'

linhas = []
base_time = datetime(2026, 9, 23, 8, 0, 0)

# Logins normais ao longo do dia
for i in range(15):
    t = base_time + timedelta(minutes=random.randint(0, 480))
    ip = random.choice(ips_normais)
    user = random.choice(usuarios)
    linhas.append(f"{t.strftime('%Y-%m-%d %H:%M:%S')} sshd: Accepted password for {user} from {ip} port 22")

# Ataque de força bruta: 40 tentativas falhas em poucos minutos, mesmo IP
attack_start = base_time + timedelta(hours=2, minutes=15)
for i in range(40):
    t = attack_start + timedelta(seconds=i * 4)
    user = random.choice(['admin', 'root', 'test', 'oracle', 'ubuntu'])
    linhas.append(f"{t.strftime('%Y-%m-%d %H:%M:%S')} sshd: Failed password for {user} from {ip_atacante} port 22")

# Login de sucesso do atacante logo depois (indício de comprometimento)
t = attack_start + timedelta(seconds=41 * 4)
linhas.append(f"{t.strftime('%Y-%m-%d %H:%M:%S')} sshd: Accepted password for root from {ip_atacante} port 22")

linhas.sort()

with open('auth.log', 'w') as f:
    f.write('\n'.join(linhas) + '\n')

print(f"Log gerado com {len(linhas)} linhas -> auth.log")
