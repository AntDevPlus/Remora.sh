# idées pour le projet
- exporter les paquets de wireshark en .csv
- traiter ces données en fonction des besoins (exemples: )

| IP-Source     | IP-Destination  |        Nombre de paquet échangé |
| :------------| :-------------: | :------------- |
| 192.168.1.1   |     0.0.0.0     |        50      |


- extraire la liste des adresses IP les plus communes
- pourvoir chiffrer le rendu

# Arguments
-a : all -> Signifie une sortie de toute les fonctionnalités listé ci dessus

-p : procole -> sortie de tous les paquets en relation avec ce protocole

-b : binaire -> nous des les adresses IP en binaire

-l : last -> sortie des derniers echanges

-rec : reccurent [chiffre] -> affiche toutes les adressses où les échanges sont les plus nombreux

-enc : encrypt -> creer les logs chiffrés avec votre mot de passe

-scp:user:ip:repertoire -> envoie des logs sur un serveur distant

-nf : notsafe -> sorti de tout les paquets non sécurisé (sans chiffrement)
