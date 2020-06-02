#!/bin/bash
##############################################################################
#   Name: extendedLogs.sh
#   Auteur: 81AETU
#   Version: 1.0
#   Rôle: Ce script est une boite à outil pour la lecture de paquets wireshark
#   Usage: ./extendedLogs.sh <args>, (cf idees.md)
#   Limites connues: Auncune au moment de l'écriture de cette cartouche
#   Dépendances, prérequis: wireshark, grep, tar, cut, openSSL,md5sum
#   Historique: 
#       Date:
#       Numéro de version:
#       Auteur:
#       Commentaire court:
#       Licence:
################################################################################

#POUR DE LE DEVELOPPEMENT
# "No.","Time","Source","Destination","Protocol","Length","Info"
#  1      2        3        4            5          6       7

#Constantes
LOGS_DIR="./logs/"
VAULT="./vault/"
LOGS_VAULT="$VAULT/logs/"
LOGS_TEMP="./temp/"
HOST=$(echo $(hostname -I) | tr " " ";" | cut -d";" -f2)
VOID_HASH=$(cat /dev/null | md5sum |tr -d "-")
#Fonctions

#Genere ou non les répertoires obligatoire
checkDir(){
    #if [ -e $LOGS_TEMP ]; then rm $LOGS_TEMP*; fi
    if [ ! -e $LOGS_DIR ]; then mkdir $LOGS_DIR; fi
    if [ ! -e $LOGS_VAULT ]; then mkdir $LOGS_VAULT; fi
    if [ ! -e $VAULT ]; then mkdir $VAULT; fi
    if [ ! -e $LOGS_TEMP ]; then mkdir $LOGS_TEMP; fi
    chmod 500 $VAULT
}
#Génération d'un mot de passe
generatePassword(){
    #génération d'un mot de passe de 42 caractères
    password=$(openssl rand -base64 42)
    echo $password > $VAULT/generation.pwd

    echo -e '\E[47;31m'"Un fichier avec votre mot de passe à été générer dans ./vault/generate.pwd !"
    echo -e '\E[47;31m'"DUPLIQUER le dans un endroit plus adapté, apres avoir mémoriser celui-ci"
    tput sgr0
}

addLogs(){
    logs=$@
    #Nous pouvons renseignez plusieurs logs
    for log in $logs
    do 
        if [ -f $log ]
        then
            date=$(echo $(date) | tr " " "-" | tr -d ":")
            #chiffrement symétrique avec le mot de passe de notre utilisateur
            openssl enc -aes-256-cbc -salt -in $log -out "./vault/logs/$log-$date.logs" -k $(cat vault/generation.pwd) 2>/dev/null
        fi
    done
    echo "les logs ont bien été ajoutées au coffre-fort"
}

decryptAllVaulted(){
    #Je récupere la liste des logs chiffrés dans le coffre-fort (la crypte)
    logs_list=$(find ./vault/logs/)
    iterator=0
    for file in $logs_list
    do
        #find renseigne également des réperoires, je filtre donc seulement les fichiers
        if [ ! -d $file ]
        then
            #je déchiffre les logs depuis le coffre-fort pour pouvoir les manipuler
            #je leurs donne un nom simple ici 0.csv etc...
            openssl enc -aes-256-cbc -d -in $file -out $LOGS_TEMP/$iterator.csv -k $(cat ./vault/generation.pwd) 2>/dev/null
            cat "temp/$iterator.csv" > temp/oeuvre.csv
            (( iterator= iterator + 1 ))
        fi
    done
    #cut -d"," -f1,2,3,4,5,6,7 $LOGS_TEMP/*.csv > $LOGS_TEMP/oeuvre.csv
}
#fonction pour récuperer et echo les échanges de paquets en relation avec un protocole donné
displayWithProtocol(){
    #déchiffrage des données
    decryptAllVaulted
    #petite pause le temps que toutes les donnes soit déchiffrées
    sleep 5
    #cat "./temp/oeuvre.csv" | head -n 10 ==> pour débug
    #Je récupere le protocole
    protocol=$1
    #je récupere les logs combinés
    log="./temp/oeuvre.csv"
    #Ici les lignes qui nous interesse
    utiles=$(cat $log | cut -d"," -f3,4,5 | grep -E $protocol | tr -d " ")
    #echo $utiles
    source=$(echo "$utiles" | cut -d"," -f1 )
    dest=$(echo "$utiles" | cut -d"," -f2 )
    echo $source > "$LOGS_TEMP/source"
    echo $dest > "$LOGS_TEMP/dest"
    #Jé découpe en fichiers temporaires
    cat "./temp/source" | tr " " "\n" > ./temp/finalsource
    cat "./temp/dest" | tr " " "\n" > ./temp/finaldest
    rm "./temp/source"; rm "./temp/dest"
    #cette méthode n'est pas la meilleur mais elle fonctionne 
    paste -d";" temp/finalsource temp/finaldest | tr -d "\"" > temp/sourcedest.csv
    rm "temp/finalsource"; rm "temp/finaldest"
    cat /dev/null > displayWithProtocol
    numligne=1
    #lecture ligne par ligne pour réalisé un sort | uniq
    while [ $numligne -le $( cat "temp/sourcedest.csv" | wc -l ) ]
    do
        ligne=$(cat "temp/sourcedest.csv" | head -n $numligne | tail -1 )
        vsource=$( echo $ligne | cut -d";" -f1)
        vdest=$( echo $ligne | cut -d";" -f2)
        echo "$vsource -> $vdest" >> displayWithProtocol
        ((numligne=numligne + 1))
    done
    echo "Nombre de requetes identiques | IPsource -> IPdestination"
    #supression des fichiers temporaires et affichage du résultat
    cat displayWithProtocol | sort | uniq -c | sort -n -r | sed "s/$HOST/vous/g"
    rm "temp/sourcedest.csv"
    rm displayWithProtocol
}
#Fonction pour nous montrez les échanges les plus fréquents
displayRecurentInformation(){
    max=$1
    log="./temp/oeuvre.csv"
    decryptAllVaulted
    cat /dev/null > displayRecurentInformation
    numligne=1
    while [ $numligne -le $( cat $log | wc -l ) ]
    do
    #toujours le meme principe je récupere les champs qui correspondent à ma fonction
        ligne=$(cat $log | head -n $numligne | tail -1 )
        vsource=$( echo $ligne | cut -d"," -f3)
        vdest=$( echo $ligne | cut -d"," -f4)
        #stockage dans un fichier résultat temporaire
        echo "$vsource -> $vdest" >> displayRecurentInformation
        ((numligne=numligne + 1))
    done
    echo "nb échange | IPsource -> IPdest"
        cat displayRecurentInformation | sort | uniq -c | sort -n -r | head -n $max | tr -d "\"" | sed "s/$HOST/vous/g"
        rm displayRecurentInformation
}
#fonction pour récupérer et echo les échanges avec une liste @IP passé en commentaire
displayWithIPInformation(){
    ips=$@
    cat /dev/null > displayWithIPInformation
    for ip in $ips
    do
        log="./temp/oeuvre.csv"
        decryptAllVaulted  
        numligne=1
        #Le lis ligne par ligne le fichier compilé de logs déchiffrées
        while [ $numligne -le $( cat $log | wc -l ) ]
        do
            #je récupere un ligne puis découpe les champs qui m'interesse
            ligne=$(cat $log | head -n $numligne | tail -1 )
            vsource=$( echo $ligne | cut -d"," -f3)
            vdest=$( echo $ligne | cut -d"," -f4)
            vprot=$( echo $ligne |cut -d',' -f5)
            vinfo=$( echo $ligne | cut -d"," -f7)
            echo "$vsource -> $vdest, protocole: $vprot, infos: $vinfo" | tr -d '"' >> displayWithIPInformation
            ((numligne=numligne + 1))
        done
        cat displayWithIPInformation | grep -E $ip | sed "s/$HOST/vous/g"
        rm displayWithIPInformation

    done
}
#fonction affichant les échanges de paquets via des protcoles non sécurisé
displayNotSafeProtocolInformation(){
    #Je liste ici les protocole non sécurisé
    for ns in "HTTP" "FTP" "DNS" "NTP" "POP" "ARP" "ICMP" "TELNET" "RIP"
    do
        log="./temp/oeuvre.csv"
        decryptAllVaulted
        cat /dev/null > displayNotSafeProtocolInformation
        numligne=1
        while [ $numligne -le $( cat $log | wc -l ) ]
        do
            #echo $ns
            ligne=$(cat $log | grep -e "$ns" | head -n $numligne | tail -1 )
            #echo $lignes
            if [ ! $ligne = "" ]
            then
                #Meme opération qu'avant, je découpe les champs qui m'interesse
                vsource=$( echo $ligne | cut -d"," -f3)
                vdest=$( echo $ligne | cut -d"," -f4)
                vprot=$( echo $ligne | cut -d"," -f5)
                #compilage dans un fichier de résultat
                echo "[$vprot] :$vsource -> $vdest" >> displayNotSafeProtocolInformation    
            fi
            ((numligne=numligne + 1))
        done
    done
    #ICI à l'aide de l'empreinte cryptographique je compare si le fichier de résultat est vide
    if [ ! $(cat displayNotSafeProtocolInformation | md5sum | tr -d "-") = $VOID_HASH ]
    then
        cat displayNotSafeProtocolInformation | sort | uniq -c | sort -n -r | head -n 1 | tr -d "\"" | sed "s/$HOST/vous/g"
        rm displayNotSafeProtocolInformation
    else
    echo "Aucune des requetes était extraite d'un protocole non sécurisé"
    rm displayNotSafeProtocolInformation
    fi
}
#Fonction pour archiver et compresser la crypte (coffre-fort)
tarVault(){
    tar cvzf vault.tar.gz $VAULT > /dev/null
}

scpVault(){
    tarVault
    args=$1
    #echo $args
    user=$(echo $args | cut -d":" -f1)
    ip=$(echo $args | cut -d":" -f2)
    dir=$(echo $args | cut -d":" -f3)
    scp "./vault.tar.gz" $user@$ip://$dir
}

#Aide utilisateur

#Blindage des entrées
#Blindage du premier argument
case $1 in
    #je liste ici les argument qui ne nécessite aucun argument
  "-gpwd" | "-tar" | "-ns") 
    if [ $# -gt 1 ]
    then
        echo "Ce parametre ne nécessite aucun autre argument !"
        exit 1
    fi;;
    #je liste ici les arguments qui nécéssite plus que 0 arguments
  "-a" | "-p" |"-rec" | "-ip" | "-scp") 
  if [ $# -lt 2 ]
  then
        echo "Ce parametre nécessite des arguments suplémentaires !"
        exit 1
  fi;;
  #Ici passe les arguments non valables
  *) echo "Veuillez inserer un parametre valide !"; exit 1
esac
#Blindage du deuxieme caractère
case $1 in
#je filtre ici les argument qui ne nécéssite seulement 2 arguments et un fichier
  "-a") 
    if [ ! $# -eq 2 ]
    then
        echo "Veuillez renseigner seulement un fichier logs avec cet arguments"
        exit 1
    elif [ ! -f $2 ]
    then
        echo "Seul un fichier log de wireshark est désiré"
    fi;;
#Ici je précise qu'il ne faut que 2 deux arguments et qu'il ne soit pas un chiffre
  "-p")
    if [ ! $# -eq 2 ]
    then
        echo "La fonction protocole nécéssite un seul protcole en argument ex: (TCP)"        
        exit 1
    fi
    if [ $(echo $2 | grep -E [a-Z] | wc -l) -eq 0 ]
    then
        echo "$2 ne doit pas etre un chiffre"
        exit 1
    fi;;
    #je précise ici qu'il faut que l'argument 2 soit un chiffre et rien d'autre
  "-rec")
    if [ ! $# -eq 2 ]
    then
        echo "La fonction récurent nécéssite seulemement un chiffre en argument"
        exit 1  
    elif [ $(echo $2 | grep -E [a-Z] | wc -l) -gt 0 ]
    then
        echo "$2 n'est pas un nombre"
        exit 1
    fi;;
    "-scp")
        if [ ! $# -eq 2 ]
        then
            echo "Les nombre d'argument nécéssaire n'est pas respecté (1 max/min)"
            exit 1
        elif [ $(echo $2 | grep -E ":" | wc -l) -gt 2 ]
        then
            echo "$2 n'est pas valide"
            exit 1
        fi;;
esac

#Programme
#Je réalise le test de présence des répertoires indispensables
checkDir
case $1 in
    #j'effectue les fonctions en fonction des arguments chosisi par l'utilisateur
    "-a") addLogs $2;;
    "-p") displayWithProtocol $2;;
    "-rec") displayRecurentInformation $2;;
    "-ip") 
    #ici je liste 1 par 1 les IPs fournies par l'utilisateur
        for ip in $@
        do
            if [ ! $ip = $1 ]
            then 
                displayWithIPInformation $2
            fi
        done;;
    "-tar") tarVault;;
    "-ns") displayNotSafeProtocolInformation;;
    "-scp") scpVault $2;;
    "-gpwd") 
    #MESSAGE de prévention
    echo -e '\E[47;31m'"ATTENTION, SI VOTRE FORT CONTIENT DEJA DES LOGS ELLE SERONT INUTILISABLE, sinon CTRL+D (10sec)"
    tput sgr0
    #temps d'annuler la commande
    sleep 10
    generatePassword;;
    #Si un utilisateur en est arrivé là, je ne comprends plus...
    *) echo "Vous avez réussi à percer le blindage ?"
esac

#Sortie avec un code de retour
exit 0