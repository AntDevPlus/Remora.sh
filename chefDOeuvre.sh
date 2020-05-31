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
    protocol=$1
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
    echo "Nombre de requetes identiques | IPsource -> IPdestination"
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
    echo "nb échange | IPsource -> IPdest"
        cat displayRecurentInformation | sort | uniq -c | sort -n -r | head -n $max | tr -d "\"" | sed "s/$HOST/vous/g"
        rm displayRecurentInformation
}

displayWithIPInformation(){
    ips=$@
    cat /dev/null > displayWithIPInformation
    for ip in $ips
    do
        log="./temp/oeuvre.csv"
        decryptAllVaulted  
        numligne=1
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
        rm displayWithIPInformation

    done
}

displayNotSafeProtocolInformation(){
    for ns in "POP" "FTP" "HTML" "telnet"
    do
        log="./temp/oeuvre.csv"
        decryptAllVaulted
        cat /dev/null > displayNotSafeProtocolInformation
        numligne=1
        while [ $numligne -le $( cat $log | wc -l ) ]
        do
            ligne=$(cat $log | grep -e "$ns" | head -n $numligne | tail -1 )
            if [ ! $ligne = "" ]
            then
                vsource=$( echo $ligne | cut -d"," -f3)
                vdest=$( echo $ligne | cut -d"," -f4)
                vprot=$( echo $ligne | cut -d"," -f5)
                echo "[$vprot] :$vsource -> $vdest" >> displayNotSafeProtocolInformation    
            fi
            ((numligne=numligne + 1))
        done
    done
    if [ ! $(cat displayNotSafeProtocolInformation | md5sum | tr -d "-") = $VOID_HASH ]
    then
        cat displayNotSafeProtocolInformation | sort | uniq -c | sort -n -r | head -n 1 | tr -d "\"" | sed "s/$HOST/vous/g"
        rm displayNotSafeProtocolInformation
    else
    echo "Aucune des requetes était extraite d'un protocole non sécurisé"
    rm displayNotSafeProtocolInformation
    fi
}

tarVault(){
    tar cvzf vault.tar.gz $VAULT > /dev/null
}

#Aide utilisateur

#Blindage des entrées
#Blindage du premier argument
case $1 in
  "-gpwd" | "-tar" | "-ns") 
    if [ $# -gt 1 ]
    then
        echo "Ce parametre ne nécessite aucun autre argument !"
        exit 1
    fi;;
  "-a" | "-p" |"-rec" | "-ip") 
  if [ $# -lt 2 ]
  then
        echo "Ce parametre nécessite des arguments suplémentaires !"
        exit 1
  fi;;
  *) echo "Veuillez inserer un parametre valide !"; exit 1
esac
#Blindage du deuxieme caractère
case $1 in
  "-a") 
    if [ ! $# -eq 2 ]
    then
        echo "Veuillez renseigner seulement un fichier logs avec cet arguments"
        exit 1
    elif [ ! -f $2 ]
    then
        echo "Seul un fichier log de wireshark est désiré"
    fi;;
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
esac

#Programme

checkDir
case $1 in
    "-a") addLogs $2;;
    "-p") displayWithProtocol $2;;
    "-rec") displayRecurentInformation $2;;
    "-ip") 
        for ip in $@
        do
            if [ ! $ip = $1 ]
            then 
                displayWithIPInformation $2
            fi
        done;;
    "-tar") tarVault;;
    "-ns") displayNotSafeProtocolInformation;;
    "-gpwd") 
    echo -e '\E[47;31m'"ATTENTION, SI VOTRE FORT CONTIENT DEJA DES LOGS ELLE SERONT INUTILISABLE, sinon CTRL+D (10sec)"
    tput sgr0
    sleep 10
    generatePassword;;
    *) echo "Vous avez réussi à percer le blindage ?"
esac

#Sortie avec un code de retour
exit 0