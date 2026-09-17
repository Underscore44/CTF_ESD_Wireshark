# Le dernier tour

Challenge Wireshark hors ligne pour ESD Academy. Catégorie Réseau / Cryptographie, difficulté estimée Intermédiaire (200 points).

## Distribution

Distribuer uniquement `challenge_esd_racing.zip`. Mot de passe : `ESD-Racing-2026`. Ouvrir avec 7-Zip ou un autre outil compatible ZIP AES-256. Le ZIP contient uniquement l'énoncé et la capture.

Les mêmes fichiers non archivés sont dans `joueurs/`. Garder le générateur et `organisateur/` privés : ils révèlent la résolution et le flag.

## Utilisation

Depuis ce dossier :

```powershell
python -m pip install -r requirements.txt
python generer_challenge.py
python organisateur/resoudre.py joueurs/soc_esd_racing.pcap
python organisateur/verifier.py
```

Le générateur construit une capture synthétique avec Scapy. Il n'envoie aucun paquet. La graine aléatoire et les horodatages sont fixes. Les données de recherche sont fictives ; la résolution ne dépend d'aucun service extérieur.

## Organisateur

- `WRITEUP.md` : corrigé détaillé et reproductible.
- `resoudre.py` : résolution depuis la capture, indépendante du générateur.
- `verifier.py` : contrôles de l'intégrité et des cas d'erreur.
- `flag.txt` : chaîne de validation sensible à la casse — `ESD{D3rn13r_V1r4g3}`.
- `manifest.json` : paramètres et empreinte SHA-256.
- `VALIDATION.md` et `preuves/` : résultats des vérifications.

La note de cadrage demande le modèle `Write_Up.docm` de l'ENT, absent du dossier. Le write-up Markdown contient le texte à reporter dans ce modèle. Les captures d'écran Wireshark à ajouter au rendu sont indiquées dans le corrigé ; les sorties TShark fournies servent de preuves textuelles.
