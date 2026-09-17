# Validation — La dernière ligne droite

Contrôles réalisés avec Python 3.14, Scapy 2.7.0, pyzipper 0.4.0 et TShark 4.6.8.

## Capture

- PCAP Ethernet reconnu par `capinfos` : 826 paquets.
- Hiérarchie reconnue par TShark : 746 paquets DNS et 80 paquets TCP ; 16 messages HTTP.
- POST `/probe` reconnu au paquet 64, formulaire décodé avec la session et la clé.
- 105 fragments DNS uniques, 7 répétitions identiques, soit 112 questions du tunnel.
- Horodatages strictement croissants ; durée d'environ 28,875 secondes.
- Filtre `_ws.malformed || tcp.analysis.lost_segment || tcp.analysis.retransmission` : aucun paquet.
- Validation IP, TCP et UDP activée : aucune checksum incorrecte.

Commandes de contrôle :

```powershell
& 'C:/Program Files/Wireshark/capinfos.exe' joueurs/soc_esd_racing.pcap
& 'C:/Program Files/Wireshark/tshark.exe' -r joueurs/soc_esd_racing.pcap -q -z io,phs
& 'C:/Program Files/Wireshark/tshark.exe' -r joueurs/soc_esd_racing.pcap -Y '_ws.malformed || tcp.analysis.lost_segment || tcp.analysis.retransmission' -T fields -e frame.number
& 'C:/Program Files/Wireshark/tshark.exe' -r joueurs/soc_esd_racing.pcap -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE -Y 'ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0' -T fields -e frame.number
python organisateur/verifier.py
```

## Résolution et distribution

Le solveur indépendant retrouve le flag depuis la capture seule. Il valide les index, le padding Base32, le XOR, le Base64 et la décompression gzip. La chaîne `ESD{` n'est présente en clair dans aucun paquet.

Le vérificateur contrôle aussi les limites de longueur DNS. Un fragment manquant et un doublon contradictoire provoquent chacun une erreur explicite.

Le ZIP est protégé par AES-256 : un mauvais mot de passe est refusé, le bon restitue exactement les fichiers joueurs. Il contient uniquement `ENONCE.md` et `soc_esd_racing.pcap`.

L'empreinte SHA-256 est enregistrée dans `manifest.json` :

```text
079384fe363ea85615d98b84bab6aa5da7c17313b00279d1ff4745656e33eddb
```

## Limites du rendu pédagogique

La capture est synthétique, pas issue d'une intrusion réelle. Le document `Write_Up.docm` de l'ENT n'était pas disponible. Le corrigé est fourni en Markdown et les preuves sont textuelles ; les trois captures d'écran indiquées dans le write-up restent à ajouter pour satisfaire le format du rendu scolaire.
