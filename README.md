# ./Remora.sh
### Pour quoi remora ?
Remora est un poisson en symbiose avec le requin, tout comme ce script est en symbiose avec wireshark

### A quoi sert-il ?

Ce script à pour but de stocker, chiffrer, analyser, combiner des logs de wireshark.

# idées pour le projet
- exporter les paquets de wireshark en .csv
- traiter ces données en fonction des besoins (exemples: )

| IP-Source     | IP-Destination  |        Nombre de paquet échangé |
| :------------ | :-------------: | :-------------  |
| 192.168.1.1   |     0.0.0.0     |        50       |


- extraire la liste des adresses IP les plus communes
- pouvoir chiffrer le rendu

# Arguments
-gpwd : generate password: genere votre password à GARDER ABSOLUMENT

-a : add -> ajout une log à notre coffre fort

-ip [ip]: recuperer des paquets envoyés/recus à une ip sépcifique 

-ns : notsafe -> sorti de tout les paquets non sécurisé (sans chiffrement)

-p [protocole]: procole -> sortie de tous les paquets en relation avec ce protocole

-rec : reccurent [chiffre] -> affiche toutes les adressses où les échanges sont les plus nombreux

-tar : encrypt -> creer un tar du coffre-fort(chiffré)

-scp:user:ip:repertoire -> envoie des logs sur un serveur distant

# Utilisation recommandée
Nous vous conseillons d'utiliser SharkVault sur un micro-ordinateur portatif, par exemple un raspberry pi plus un disque dur SSD de 120Go.

Ainsi devenu portatif il sera très facile à utilisé pour vous les techniciens.

#### Partitionnement recommandé sur le raspberry

Avant toutes choses, si votre raspberry est composé d'un stockage principale (comme une carte SD) vous pouvez réalisé un RAID1 avec le stockage additionnel (SSD conseillé).

#### plan de partionnement recommandé (120Go): 

![halt-text](https://i.ibb.co/93hYz7R/bien-se-passer.png)

## Benchmark

tests réalisés avec:

CPU: IntelCore i5 - 8300H
RAM: DDR4 8go

![halt-text](https://i.ibb.co/gPYXpXq/Sans-titre.png)
