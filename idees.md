# idées pour le projet
- exporter les paquets de wireshark en .csv
- traiter ces données en fonction des besoins (exemples: )

| IP-Source     | IP-Destination  |        Nombre de paquet échangé |
| :------------ | :-------------: | :-------------  |
| 192.168.1.1   |     0.0.0.0     |        50       |


- extraire la liste des adresses IP les plus communes
- pouvoir chiffrer le rendu

# Arguments
-a : add -> ajout une log à noter coffre fort

-p [protocole]: procole -> sortie de tous les paquets en relation avec ce protocole

-b : binaire -> nous des les adresses IP en binaire

-l : last -> sortie des derniers echanges

-rec : reccurent [chiffre] -> affiche toutes les adressses où les échanges sont les plus nombreux

-enc : encrypt -> creer les logs chiffrés avec votre mot de passe

-scp:user:ip:repertoire -> envoie des logs sur un serveur distant

-nf : notsafe -> sorti de tout les paquets non sécurisé (sans chiffrement)

-v : vault -> creer un coffre-fort de vos logs

-gpw : generate password: genere votre password à GARDER ABSOLUmENT