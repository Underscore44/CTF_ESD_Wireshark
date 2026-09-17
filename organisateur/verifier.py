"""Contrôles indépendants sur la capture, le solveur et l'archive."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import pyzipper
from scapy.all import rdpcap, wrpcap, DNS, DNSQR, Raw, TCP, IP

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('solveur', ROOT / 'organisateur' / 'resoudre.py')
solver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(solver)
capture = ROOT / 'joueurs' / 'soc_esd_racing.pcap'
manifest = json.loads((ROOT / 'organisateur' / 'manifest.json').read_text(encoding='utf-8'))
flag, recovered, info = solver.solve(capture)
assert flag == (ROOT / 'organisateur' / 'flag.txt').read_text(encoding='utf-8').strip()
assert info['fragments'] == manifest['fragments']
assert info['duplicates'] == manifest['retransmissions']
assert hashlib.sha256(capture.read_bytes()).hexdigest() == manifest['sha256']
packets = rdpcap(str(capture))
assert all(b'ESD{' not in bytes(p) for p in packets), 'Flag visible en clair dans un paquet'
queries = [p for p in packets if DNS in p and DNSQR in p and p[DNS].qr == 0
           and p[DNSQR].qname.startswith(b'a7c9.')]
assert len(queries) == info['fragments'] + info['duplicates']
for p in queries:
    name = p[DNSQR].qname.rstrip(b'.')
    assert len(name) <= 253
    assert all(0 < len(label) <= 63 for label in name.split(b'.'))

with pyzipper.AESZipFile(ROOT / 'challenge_esd_racing.zip') as archive:
    assert set(archive.namelist()) == {'ENONCE.md', 'soc_esd_racing.pcap'}
    assert all(item.flag_bits & 1 for item in archive.infolist())
    try:
        archive.read('soc_esd_racing.pcap', pwd=b'incorrect')
    except (RuntimeError, ValueError):
        pass
    else:
        raise AssertionError('Le ZIP accepte un mauvais mot de passe')
    archive.setpassword(manifest['zip_password'].encode())
    assert archive.read('soc_esd_racing.pcap') == capture.read_bytes()
    assert archive.read('ENONCE.md') == (ROOT / 'joueurs' / 'ENONCE.md').read_bytes()
print('OK : resolution, SHA-256, limites DNS, flag absent en clair, ZIP chiffre et contenu joueurs uniquement')

with tempfile.TemporaryDirectory(prefix='esd-validation-') as directory:
    path = Path(directory) / 'test.pcap'
    # Supprimer toutes les copies du meme fragment, pour ne pas confondre perte et doublon.
    target = queries[0][DNSQR].qname
    truncated = [p for p in packets if not (DNSQR in p and p[DNSQR].qname == target)]
    wrpcap(str(path), truncated)
    try:
        solver.solve(path)
    except ValueError as e:
        assert 'manquants' in str(e)
    else:
        raise AssertionError('Fragment manquant non detecte')
    # Injecter un doublon de meme index avec des donnees contradictoires.
    corrupted = queries[0].copy()
    labels = corrupted[DNSQR].qname.split(b'.')
    labels[2] = (b'b' if labels[2][:1] == b'a' else b'a') + labels[2][1:]
    corrupted[DNSQR].qname = b'.'.join(labels)
    corrupted.time = packets[-1].time + 1
    wrpcap(str(path), list(packets) + [corrupted])
    try:
        solver.solve(path)
    except ValueError as e:
        assert 'contradictoires' in str(e)
    else:
        raise AssertionError('Doublon contradictoire non detecte')
print('OK : fragments manquants et doublons contradictoires refuses')
