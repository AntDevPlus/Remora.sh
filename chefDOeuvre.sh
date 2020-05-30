#!/bin/bash
##############################################################################
#   Name: extendedLogs.sh
#   Auteur: 81AETU
#   Version: 1.0
#   Rôle: Ce script est une boite à outil pour la lecture de paquets wireshark
#   Usage: ./extendedLogs.sh <args>, (cf idees.md)
#   Limites connues: Auncune au moment de l'écriture de cette cartouche
#   Dépendances, prérequis: wireshark, grep, cut, openSSL
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
    for log in $logs
    do 
        if [ -f $log ]
        then
            date=$(echo $(date) | tr " " "-" | tr -d ":")
            #chiffrement symétrique avec le mot de passe de notre utilisateur
            openssl enc -aes-256-cbc -salt -in $log -out "./vault/logs/$log-$date.logs" -k $(cat vault/generation.pwd) 2>/dev/null
        fi
    done
}

decryptAllVaulted(){
    logs_list=$(find ./vault/logs/)
    iterator=0
    for file in $logs_list
    do
        if [ ! -d $file ]
        then
            openssl enc -aes-256-cbc -d -in $file -out $LOGS_TEMP/$iterator.csv -k $(cat ./vault/generation.pwd) 2>/dev/null
            cat "temp/$iterator.csv" > temp/oeuvre.csv
            (( iterator= iterator + 1 ))
        fi
    done
    #cut -d"," -f1,2,3,4,5,6,7 $LOGS_TEMP/*.csv > $LOGS_TEMP/oeuvre.csv
}

displayWithProtocol(){
    decryptAllVaulted
    sleep 5
    #cat "./temp/oeuvre.csv" | head -n 10
    protocol="DNS"
    log="./temp/oeuvre.csv"
    utiles=$(cat $log | cut -d"," -f3,4,5 | grep -E $protocol | tr -d " ")
    #echo $utiles
    source=$(echo "$utiles" | cut -d"," -f1 )
    dest=$(echo "$utiles" | cut -d"," -f2 )
    echo $source > "$LOGS_TEMP/source"
    echo $dest > "$LOGS_TEMP/dest"
    cat "./temp/source" | tr " " "\n" > ./temp/finalsource
    cat "./temp/dest" | tr " " "\n" > ./temp/finaldest
    rm "./temp/source"; rm "./temp/dest"
    paste -d";" temp/finalsource temp/finaldest | tr -d "\"" > temp/sourcedest.csv
    rm "temp/finalsource"; rm "temp/finaldest"
    cat /dev/null > displayWithProtocol
    numligne=1
    while [ $numligne -le $( cat "temp/sourcedest.csv" | wc -l ) ]
    do
        ligne=$(cat "temp/sourcedest.csv" | head -n $numligne | tail -1 )
        vsource=$( echo $ligne | cut -d";" -f1)
        vdest=$( echo $ligne | cut -d";" -f2)
        echo "$vsource -> $vdest" >> displayWithProtocol
        ((numligne=numligne + 1))
    done
    cat displayWithProtocol | sort | uniq -c | sort -n -r
    rm "temp/sourcedest.csv"
}


#Aide utilisateur

#Blindage des entrées

#Programme

checkDir
#decryptAllVaulted
#generatePassword
#addLogs "logs_wireshark.csv"
displayWithProtocol

#Sortie avec un code de retour
exit 0