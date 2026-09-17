from pathlib import Path
import base64, gzip, hashlib, json, random, sys
from datetime import datetime, timezone
from urllib.parse import urlencode
import pyzipper
from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, DNSRR, Raw, wrpcap

ROOT = Path(__file__).resolve().parent
PLAYERS = ROOT / 'joueurs'
ADMIN = ROOT / 'organisateur'
FLAG = 'ESD{la_derniere_ligne_droite}'
KEY = 0x5A
PASSWORD = b'ESD-Racing-2026'
SRC = '10.42.0.26'
EXTERNAL = '198.51.100.77'
RESOLVER = '10.42.0.53'
SESSION = 'a7c9'
DOMAIN = 'telemetry-aero.test'
rng = random.Random(20260917)
packets = []
clock = datetime(2026, 9, 17, 7, 42, tzinfo=timezone.utc).timestamp()


def add(packet, delay=0.035):
    global clock
    clock += delay
    packet.time = clock
    packets.append(packet)


def ethernet(src, dst):
    return Ether(src='02:00:00:42:00:26' if src == SRC else '02:00:00:42:00:01',
                 dst='02:00:00:42:00:26' if dst == SRC else '02:00:00:42:00:01')


def dns_exchange(name, client=SRC, server=RESOLVER, nxdomain=False):
    port = rng.randrange(49152, 65535)
    tid = rng.randrange(65536)
    query = DNS(id=tid, rd=1, qd=DNSQR(qname=name, qtype='A'))
    add(ethernet(client, server) / IP(src=client, dst=server) / UDP(sport=port, dport=53) / query)
    answer = DNS(id=tid, qr=1, aa=int(server == EXTERNAL), rd=1, ra=int(server == RESOLVER),
                 rcode=3 if nxdomain else 0, qd=DNSQR(qname=name, qtype='A'))
    if not nxdomain:
        answer.an = DNSRR(rrname=name, type='A', ttl=60, rdata='203.0.113.20')
    add(ethernet(server, client) / IP(src=server, dst=client) / UDP(sport=53, dport=port) / answer)


def http_exchange(host, body='', server='10.42.0.10', path='/health', client=SRC):
    port = rng.randrange(49152, 65535)
    cseq, sseq = rng.randrange(100000, 900000), rng.randrange(100000, 900000)
    def tcp(src, dst, sport, dport, seq, ack, flags, payload=b''):
        p = ethernet(src, dst) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        if payload:
            p /= Raw(payload)
        add(p)
    tcp(client, server, port, 80, cseq, 0, 'S')
    tcp(server, client, 80, port, sseq, cseq + 1, 'SA')
    cseq += 1
    sseq += 1
    tcp(client, server, port, 80, cseq, sseq, 'A')
    data = body.encode('ascii')
    request = (f'{"POST" if body else "GET"} {path} HTTP/1.1\r\nHost: {host}\r\n'
               'User-Agent: ESD-Racing-Agent/1.0\r\nConnection: close\r\n'
               + (f'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(data)}\r\n' if body else '')
               + '\r\n').encode('ascii') + data
    tcp(client, server, port, 80, cseq, sseq, 'PA', request)
    cseq += len(request)
    tcp(server, client, 80, port, sseq, cseq, 'A')
    content = b'OK\n'
    response = (f'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(content)}\r\nConnection: close\r\n\r\n').encode() + content
    tcp(server, client, 80, port, sseq, cseq, 'PA', response)
    sseq += len(response)
    tcp(client, server, port, 80, cseq, sseq, 'A')
    tcp(server, client, 80, port, sseq, cseq, 'FA')
    sseq += 1
    tcp(client, server, port, 80, cseq, sseq, 'FA')
    cseq += 1
    tcp(server, client, 80, port, sseq, cseq, 'A')


def noise(count=3):
    for _ in range(count):
        client = rng.choice([SRC, '10.42.0.31', '10.42.0.44'])
        dns_exchange(rng.choice(['intranet.esd-racing.test', 'git.esd-racing.test', 'meteo.test',
                                 'timing.esd-racing.test', 'updates.test']), client=client)


def generate():
    PLAYERS.mkdir(exist_ok=True)
    ADMIN.mkdir(exist_ok=True)
    rows = ['ESD Racing / ESD Academy - Programme aerodynamique PHOENIX',
            'CONFIDENTIEL - recherche interne - donnees fictives',
            'run,front_wing_deg,rear_wing_deg,drag_coeff,downforce_N']
    for i in range(120):
        rows.append(f'{i:03d},{rng.uniform(2,12):.3f},{rng.uniform(9,25):.3f},{rng.uniform(.2,.5):.6f},{rng.uniform(1700,2900):.3f}')
    rows += ['', 'Validation de la derniere serie :', FLAG, 'Fin du rapport PHOENIX.']
    research = ('\n'.join(rows) + '\n').encode('utf-8')
    compressed = gzip.compress(research, mtime=0)
    armored = base64.b64encode(compressed)
    masked = bytes(b ^ KEY for b in armored)
    encoded = base64.b32encode(masked).decode().rstrip('=').lower()
    chunks = [encoded[i:i+48] for i in range(0, len(encoded), 48)]
    noise(24)
    http_exchange('intranet.esd-racing.test')
    dns_exchange('connectivity-aero.test')
    probe = urlencode({'user': 'j.berthier', 'workstation': 'ESD-AERO-026', 'project': 'PHOENIX',
                       'session': SESSION, 'test': 'outbound', 'mask': '0x5a',
                       'memo': 'compress > base64 > xor-byte > base32; seq starts at 0'})
    http_exchange('connectivity-aero.test', probe, EXTERNAL, '/probe')
    noise(10)
    order = list(range(len(chunks)))
    rng.shuffle(order)
    retransmits = 0
    for position, seq in enumerate(order):
        name = f'{SESSION}.{seq:04d}-{len(chunks):04d}.{chunks[seq]}.{DOMAIN}'
        dns_exchange(name, server=EXTERNAL, nxdomain=True)
        if position % 17 == 0:
            dns_exchange(name, server=EXTERNAL, nxdomain=True)
            retransmits += 1
        noise(rng.randrange(1, 4))
        if position % 19 == 0:
            http_exchange('timing.esd-racing.test', path='/api/session/status', client='10.42.0.31')
    noise(16)
    capture = PLAYERS / 'soc_esd_racing.pcap'
    wrpcap(str(capture), packets)
    statement = '''# La dernière ligne droite

Catégorie : Réseau / Cryptographie  
Difficulté estimée : Intermédiaire — 200 points  
Pièce jointe : `soc_esd_racing.pcap`

Julien Berthier était ingénieur aérodynamique chez ESD Racing depuis six ans. Licencié du jour au lendemain sans motif clair, il a eu le temps, avant de rendre son badge, de tenter une dernière manœuvre : exfiltrer des données de recherche confidentielles de l'écurie vers l'extérieur, en évitant toute détection par les outils de surveillance classiques.

Avant de lancer son exfiltration, il a d'abord testé sa connexion vers l'extérieur avec un envoi rapide, sans réfléchir à ce qu'il laissait passer en clair.

Persuadé que personne ne remonterait à la source, il a ensuite mis en place un canal plus discret pour faire sortir les vraies données, en les découpant et en les chiffrant au passage. Mal lui en a pris : le SOC d'ESD Racing a intercepté le trafic, juste avant la coupure définitive de son accès.

Votre mission : analysez la capture réseau récupérée par le SOC. Plusieurs couches se cachent derrière les données que vous trouverez : à vous de les retirer une par une jusqu'au flag final.

Indices : le canal utilisé pour les vraies données n'est pas un simple transfert de fichier classique. Une fois la donnée brute extraite, plusieurs encodages/chiffrements successifs la protègent, dont un XOR sur une clé d'un seul octet.

Le flag est une chaîne de validation présente dans le document de recherche reconstitué, au format `ESD{...}`. Respectez la casse et soumettez la chaîne complète. Il n'y a pas de combinaison d'informations à inventer.

Bonne chance !

Scénario et données fictifs. Challenge conçu dans le cadre d'ESD Academy. La résolution est entièrement hors ligne.
'''
    (PLAYERS / 'ENONCE.md').write_text(statement, encoding='utf-8')
    (ADMIN / 'flag.txt').write_text(FLAG + '\n', encoding='utf-8')
    (ROOT / 'requirements.txt').write_text('scapy==2.7.0\npyzipper==0.4.0\n', encoding='utf-8')
    (ADMIN / 'manifest.json').write_text(json.dumps({'title': 'La dernière ligne droite', 'category': 'Réseau / Cryptographie',
        'difficulty': 'Intermédiaire', 'points': 200, 'source': SRC, 'destination': EXTERNAL,
        'session': SESSION, 'fragments': len(chunks), 'retransmissions': retransmits, 'packets': len(packets),
        'sha256': hashlib.sha256(capture.read_bytes()).hexdigest(), 'zip_password': PASSWORD.decode()}, indent=2, ensure_ascii=False), encoding='utf-8')
    archive = ROOT / 'challenge_esd_racing.zip'
    with pyzipper.AESZipFile(archive, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(PASSWORD)
        z.setencryption(pyzipper.WZ_AES, nbits=256)
        for filename in ['ENONCE.md', 'soc_esd_racing.pcap']:
            z.write(PLAYERS / filename, arcname=filename)
    print(f'Capture : {len(packets)} paquets, {len(chunks)} fragments, {retransmits} doublons')
    print(f'Archive : {archive.name}')


if __name__ == '__main__':
    generate()

