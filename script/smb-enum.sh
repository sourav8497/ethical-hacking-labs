#!/bin/bash 

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip>"
    exit 1

fi

TARGET=$1

echo "[*]startin smb enumeration for $TARGET"
echo "[*] starting smbmap .........."
#---------------------------------------------
smbmap -H $TARGET


echo "[*] starting enum4linux ..............."





enum4linux -a $TARGET



echo "starting smbclient ............."


smbclient -L //#TARGET//


echo "[✔] SMB enumeration completed for $TARGET " 
