"""Résolution indépendante depuis la capture uniquement (aucun import du générateur)."""
import argparse
import base64
import gzip
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs
from scapy.all import rdpcap, DNS, DNSQR, IP, UDP, TCP, Raw


def solve(capture):
    packets = rdpcap(str(capture))
    probes = []
    for packet in packets:
        if TCP in packet and Raw in packet and packet[TCP].dport == 80:
            raw = bytes(packet[Raw])
            if raw.startswith(b'POST /probe HTTP/1.1\r\n'):
                header, body = raw.split(b'\r\n\r\n', 1)
                probes.append((packet[IP].src, packet[IP].dst, parse_qs(body.decode('ascii'))))
    if len(probes) != 1:
        raise ValueError('Un seul test HTTP /probe attendu')
    source, destination, form = probes[0]
    session = form['session'][0]
    key = int(form['mask'][0], 16)
    if not 0 <= key <= 255:
        raise ValueError('La clé doit tenir sur un octet')
    pattern = re.compile(r'^' + re.escape(session) + r'\.(\d{4})-(\d{4})\.([a-z2-7]{1,63})\.(.+)\.$', re.I)
    fragments = {}
    totals, domains = set(), set()
    duplicates = 0
    for packet in packets:
        if IP not in packet or UDP not in packet or DNS not in packet or DNSQR not in packet:
            continue
        if packet[IP].src != source or packet[IP].dst != destination or packet[UDP].dport != 53 or packet[DNS].qr != 0:
            continue
        match = pattern.fullmatch(packet[DNSQR].qname.decode('ascii'))
        if not match:
            continue
        seq, total = int(match[1]), int(match[2])
        value = match[3].upper()
        totals.add(total)
        domains.add(match[4])
        if seq in fragments:
            if fragments[seq] != value:
                raise ValueError(f'Fragments contradictoires pour index {seq}')
            duplicates += 1
        fragments[seq] = value
    if len(totals) != 1 or len(domains) != 1:
        raise ValueError('Nombre total ou domaine incohérent')
    total = totals.pop()
    if set(fragments) != set(range(total)):
        raise ValueError('Fragments manquants ou index hors limites')
    encoded = ''.join(fragments[i] for i in range(total))
    masked = base64.b32decode(encoded + '=' * ((-len(encoded)) % 8))
    armored = bytes(byte ^ key for byte in masked)
    compressed = base64.b64decode(armored, validate=True)
    if compressed[:2] != b'\x1f\x8b':
        raise ValueError('Signature gzip absente')
    recovered = gzip.decompress(compressed)
    flags = re.findall(rb'ESD\{[A-Za-z0-9_]+\}', recovered)
    if len(flags) != 1:
        raise ValueError('Un seul flag attendu dans le rapport')
    info = {'source': source, 'destination': destination, 'session': session, 'key': f'0x{key:02x}',
            'domain': next(iter(domains)), 'fragments': total, 'duplicates': duplicates, 'packets': len(packets)}
    return flags[0].decode(), recovered, info


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--sortie', type=Path, help='Enregistrer le document reconstitué')
    args = parser.parse_args()
    flag, recovered, info = solve(args.capture)
    for name, value in info.items():
        print(f'{name}: {value}')
    if args.sortie:
        args.sortie.write_bytes(recovered)
        print(f'Document reconstitué : {args.sortie}')
    print(f'Flag : {flag}')

