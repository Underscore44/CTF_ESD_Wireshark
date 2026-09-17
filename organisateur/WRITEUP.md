# Write-up — La dernière ligne droite

## Présentation et réflexion

Catégorie : Réseau / Cryptographie. Difficulté estimée : Intermédiaire, 200 points.

L'énoncé distingue un test initial en clair et une exfiltration fragmentée. Je cherche donc d'abord une conversation lisible pour identifier le poste, le destinataire et les éléments utiles au déchiffrement. Ensuite, j'observe les communications sortantes du même poste.

Tout se résout hors ligne. Le canal transporte des données dans les noms des requêtes DNS. Il n'y a ni stéganographie, ni OSINT, ni mot de passe à deviner. Le XOR sur un octet est volontairement faible.

## 1. Trouver le test en clair

Ouvrir `joueurs/soc_esd_racing.pcap` dans Wireshark. Dans Statistiques > Hiérarchie des protocoles, constater la présence de DNS et de HTTP. Dans Statistiques > Conversations > IPv4, examiner le poste `10.42.0.26`.

Filtrer :

```text
http.request.method == "POST"
```

Le paquet 64 contient un POST `/probe` vers `198.51.100.77`. Clic droit > Suivre > Flux TCP. Le corps du formulaire expose ces valeurs, URL-encodées dans le flux :

```text
user=j.berthier
workstation=ESD-AERO-026
project=PHOENIX
session=a7c9
mask=0x5a
memo=compress > base64 > xor-byte > base32; seq starts at 0
```

Wireshark décode les valeurs dans « HTML Form URL Encoded ». Ce test indique le poste impliqué, la session, la clé XOR hexadécimale (`0x5a`, soit 90) et l'ordre des transformations à l'envoi. Pour résoudre, il faudra inverser cet ordre. Le format de compression sera identifié par sa signature.

Équivalent en ligne de commande, depuis la racine du projet :

```powershell
& 'C:/Program Files/Wireshark/tshark.exe' -r joueurs/soc_esd_racing.pcap -Y 'http.request.method == "POST"' -V
```

Preuve textuelle : `preuves/01_http_probe.txt`.

## 2. Identifier le canal DNS

Filtrer :

```text
ip.src == 10.42.0.26 && ip.dst == 198.51.100.77 && dns.flags.response == 0
```

Les noms sous `telemetry-aero.test` sont longs et variables. Leur label de données utilise seulement `a-z` et `2-7`, alphabet de Base32 RFC 4648. Ils suivent la structure :

```text
a7c9.<index sur 4 chiffres>-<total sur 4 chiffres>.<fragment>.telemetry-aero.test
```

Les champs sont la session, l'index à partir de zéro, le nombre total et le fragment. La session correspond au formulaire HTTP. Chaque fragment fait au maximum 48 caractères, sous la limite DNS de 63 caractères par label.

Les réponses NXDOMAIN n'empêchent pas le serveur de recevoir les données : elles sont présentes dans la question DNS. Le trafic DNS normal passe par le résolveur interne `10.42.0.53`.

## 3. Reconstituer les données

Exporter les questions :

```powershell
& 'C:/Program Files/Wireshark/tshark.exe' -r joueurs/soc_esd_racing.pcap -Y 'ip.src == 10.42.0.26 && ip.dst == 198.51.100.77 && dns.flags.response == 0' -T fields -e dns.qry.name
```

La capture contient 112 questions du tunnel : 105 fragments distincts et 7 doublons. Les index vont de 0000 à 0104 et le total vaut 0105. Les paquets arrivent dans un ordre différent de celui des données.

Trier les index numériquement. Conserver une seule copie de chaque fragment identique. Signaler tout doublon contradictoire et vérifier que tous les index de zéro à `total - 1` sont présents. Ne pas ajouter les réponses DNS aux données.

Concaténer uniquement les labels des fragments. Convertir en majuscules et remettre le padding Base32 : ajouter `(-longueur) % 8` signes `=`. La suppression de ce padding dans les noms DNS est volontaire.

Preuve textuelle : `preuves/02_dns_fragments.tsv`.

## 4. Inverser les transformations

Le solveur applique au contenu extrait :

```python
masked = base64.b32decode(encoded + '=' * ((-len(encoded)) % 8))
armored = bytes(byte ^ key for byte in masked)
compressed = base64.b64decode(armored, validate=True)
recovered = gzip.decompress(compressed)
```

Base32 restitue les octets masqués. Le XOR avec `0x5a` retrouve un texte Base64 valide. Le décodage Base64 donne un fichier commençant par `1f 8b`, signature gzip. La décompression contrôle également le CRC et la taille du contenu.

On peut reproduire ces opérations dans CyberChef : From Base32, XOR avec la clé hexadécimale `5a`, From Base64, Gunzip. Le script fournit une alternative entièrement locale et vérifie aussi les fragments.

## 5. Retrouver le flag

Depuis la racine du projet :

```powershell
python organisateur/resoudre.py joueurs/soc_esd_racing.pcap --sortie organisateur/rapport_reconstitue.txt
```

Le script découvre la source, la destination, la clé et la session dans le POST. Il extrait les fragments DNS et inverse les transformations. Il ne lit ni `flag.txt`, ni `manifest.json`, ni le générateur.

Le rapport du programme PHOENIX contient des résultats aérodynamiques fictifs puis la chaîne de validation :

```text
ESD{la_derniere_ligne_droite}
```

Soumettre la chaîne exacte, avec sa casse et ses accolades.

Preuve textuelle : `preuves/03_resolution.txt`.

## Indices progressifs

1. Le premier essai utilise un protocole où l'on peut suivre une conversation en clair.
2. Les noms de domaine peuvent transporter autre chose que des noms de machines.
3. Trier les questions DNS par index et ne compter chaque fragment qu'une fois.
4. Inverser la recette du formulaire. `mask` est un nombre hexadécimal d'un octet.
5. Après Base64, `1f 8b` indique gzip.

## Captures d'écran pour le rendu ENT

La note demande des captures d'écran et le modèle `Write_Up.docm`. Ce modèle n'est pas présent dans le dossier. Le texte ci-dessus est prêt à y être reporté. Ajouter trois captures réelles :

1. Le paquet 64 et les champs du formulaire HTTP, illustrant la fuite initiale.
2. La liste Wireshark filtrée sur les questions du tunnel, illustrant les index et les fragments.
3. Le résultat du solveur et le flag dans le rapport reconstitué.

Les fichiers de `preuves/` sont des sorties textuelles TShark et Python, et non des captures d'écran.
