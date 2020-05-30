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
HOST=$(echo $(hostname -I) | tr " " ";" | cut -d";" -f2)
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
    protocol="TCP"
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
    cat displayWithProtocol | sort | uniq -c | sort -n -r | sed "s/$HOST/vous/g"
    rm "temp/sourcedest.csv"
    rm displayWithProtocol
}

displayRecurentInformation(){
    max=$1
    log="./temp/oeuvre.csv"
    decryptAllVaulted
    cat /dev/null > displayRecurentInformation
    numligne=1
    while [ $numligne -le $( cat $log | wc -l ) ]
    do
        ligne=$(cat $log | head -n $numligne | tail -1 )
        vsource=$( echo $ligne | cut -d"," -f3)
        vdest=$( echo $ligne | cut -d"," -f4)
        echo "$vsource -> $vdest" >> displayRecurentInformation
        ((numligne=numligne + 1))
    done
    cat displayRecurentInformation | sort | uniq -c | sort -n -r | head -n $max | tr -d "\"" | sed "s/$HOST/vous/g"
    rm displayRecurentInformation
}

displayWithIPInformation(){
    ips=$@
    for ip in $ips
    do
        log="./temp/oeuvre.csv"
        decryptAllVaulted  
        numligne=1
        cat /dev/null > displayWithIPInformation
        while [ $numligne -le $( cat $log | wc -l ) ]
        do
            ligne=$(cat $log | head -n $numligne | tail -1 )
            vsource=$( echo $ligne | cut -d"," -f3)
            vdest=$( echo $ligne | cut -d"," -f4)
            vprot=$( echo $ligne |cut -d',' -f5)
            vinfo=$( echo $ligne | cut -d"," -f7)
            echo "$vsource -> $vdest, protocole: $vprot, infos: $vinfo" | tr -d '"' >> displayWithIPInformation
            ((numligne=numligne + 1))
        done
        cat displayWithIPInformation | grep -E $ip | sed "s/$HOST/vous/g"

    done
}

tarVault(){
    tar cvzf vault.tar.gz $VAULT > /dev/null
}

#Aide utilisateur

#Blindage des entrées

#Programme

checkDir
#decryptAllVaulted
#generatePassword
 #addLogs "logs_wireshark_complet.csv"
#displayWithProtocol
#displayRecurentInformation 3
#displayWithIPInformation 192.168.1.24
tarVault
#Sortie avec un code de retour
exit 0