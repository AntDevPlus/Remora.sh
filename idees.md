# idées pour le projet
- exporter les paquets de wireshark en .csv
- traiter ces données en fonction des besoins (exemples: )

| IP-Source     | IP-Destination  |        Nombre de paquet échangé |
| :------------ | :-------------: | :-------------  |
| 192.168.1.1   |     0.0.0.0     |        50       |


- extraire la liste des adresses IP les plus communes
- pouvoir chiffrer le rendu

# Arguments
-a : add -> ajout une log à notre coffre fort

-p [protocole]: procole -> sortie de tous les paquets en relation avec ce protocole

-rec : reccurent [chiffre] -> affiche toutes les adressses où les échanges sont les plus nombreux

-ip [ip]: recuperer des paquets envoyés/recus à une ip sépcifique 

-tar : encrypt -> creer un tar du coffre-fort(chiffré)

-scp:user:ip:repertoire -> envoie des logs sur un serveur distant

-ns : notsafe -> sorti de tout les paquets non sécurisé (sans chiffrement)

-gpwd : generate password: genere votre password à GARDER ABSOLUmENT