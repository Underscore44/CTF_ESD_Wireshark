# La dernière ligne droite

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
