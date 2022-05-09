#!/bin/bash

# coded by Xenion_
# Installer - version 1.0


#@> CHECK CONNECTION
wget -q --spider http://google.com
if [ $? -ne 0 ];then
    echo "Connect to internet"
    exit 
fi


#Colors
RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"
BOLD="\033[1m"




#@> VARIABLES
ip_device=
ADB_OUT=
ADB_PATH=
##=======path for burp cert
FILE=





#@> PRINT USAGE
USAGE(){
echo -e "${BLUE}
 \ \ / /                (_)                
  \ V /    ___   _ __    _    ___    _ __  
   > <    / _ \ | '_ \  | |  / _ \  | '_ \ 
  / . \  |  __/ | | | | | | | (_) | | | | |
 /_/ \_\  \___| |_| |_| |_|  \___/  |_| |_|
 ${RESET}
[${YELLOW}Xenion${RESET}] == INSTALLER TOOLS FOR ANDROID PENTEST (${GREEN} @Xenion_${RESET})

"
echo -e ""
echo -e "Example Usage:"
echo -e "./setup.sh [-i ip for android Device in network] [-f file fo CA burp] "
echo -e ""
echo -e "Flags:"
echo -e "   -i, --ip                 ${BK}string${RESET}      Android Emulator IP Address             -i 192.168.241.101"
echo -e "   -f, --file               ${BK}string${RESET}      Burp's CA certificate                   -f cacert.der"

exit 0

}

#@> CHECK IF ARGS == 0
if [[ $# -eq 0 ]]; then
  USAGE
  exit 
fi  

while [ -n "$1" ]; do
    case $1 in
            -i|--ip)
                ip_device=$2
                shift 
                ;;
                
            -f|--file)
                FILE=$2
                shift 
                ;;
                
            -h|--help)
                USAGE
                shift 
                ;;

           *)
                USAGE
                ;;
    esac
    shift
done



#@> MAKE FOLDERS
MAKDR(){
echo -e "${GREEN}====[ Setting things up ]====${RESET}"
cd /root 
mkdir android-tools 
cd android-tools 
mkdir firda   
mkdir dorzer
mkdir nucli
mkdir burp
mkdir FireBaseScanner
}


#@> INSTALL LANGUAGE
LANGUAGES(){
echo -e "${RED}\n[+] update apt ${RESET}"
sudo apt -y update  > /dev/null 2>&1
sudo apt -y upgrade  > /dev/null 2>&1

echo -e "${RED}\n[+] install python3  & pip3${RESET}"
sudo apt-get -y install python3 python3-pip  > /dev/null 2>&1

echo -e "${RED}\n[+] install python2.7  & pip2.7${RESET}"
sudo apt-get -y install python2.7 > /dev/null 2>&1
cd /usr/lib/python2.7
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py — output get-pip.py > /dev/null 2>&1
python2.7 get-pip.py > /dev/null 2>&1

echo -e "${RED}\n[+] install JAVA JDK${RESET}"
sudo apt -y install default-jdk > /dev/null 2>&1

echo -e "${RED}\n[+] install go-lang${RESET}"
#download compress file
wget https://go.dev/dl/go1.18.1.linux-amd64.tar.gz > /dev/null 2>&1
#cleaning previous installations  decompressing to /usr/local
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz > /dev/null 2>&1
#add variables to .bashrc 
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export GOPATH=$HOME/go'   >> ~/.bashrc            
echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc   
source ~/.bashrc

}


#@ >Tools
TOOLS(){
echo -e "${RED}\n[+] install ADB${RESET}"
sudo apt -y install adb > /dev/null 2>&1

echo -e "${RED} install jadx${REST}"
sudo apt install jadx  > /dev/null 2>&1

echo -e "${RED} install apktool${REST}"
sudo apt install apktool > /dev/null 2>&1

echo -e "${RED} install apkleaks${REST}"
#sudo pip3 install apkleaks > /dev/null 2>&1

#sudo apt-get -y install openssl

#FireBase Scanner
echo -e "${RED} install fireBase Scanner${REST}"

cd /root/android-tools/FireBaseScanner
git clone https://github.com/shivsahni/FireBaseScanner.git > /dev/null 2>&1


#nculi install  
echo -e "${RED} install nucli${REST}"
cd /root/android-tools/nucli
git clone https://github.com/projectdiscovery/nuclei.git > /dev/null 2>&1
cd nuclei/v2/cmd/nuclei/
go build . > /dev/null 2>&1
echo -e "${RED} build nucli bin file${REST}"
mv nuclei /usr/local/bin/

echo -e "${RED}Download/Update templates${REST}"
nuclei -ut 

}

#@> CONNECT TO ADB WITH IP ADRESS
CONNECT_ADB(){

ADB_PATH=$(which adb)
$ADB_PATH kill-server
$ADB_PATH start-server  > /dev/null 2>&1
$ADB_PATH connect $ip_device  

CHECK_ADB
}


#@>  check if android device connected
CHECK_ADB(){

$ADB_PATH connect $ip_device  > /dev/null 2>&1
ADB_OUT=`$ADB_PATH devices | awk 'NR>1 {print $1}'`
if test -n "$ADB_OUT"
        then
                echo "device connected is $ADB_OUT"
        else
                echo "device is not connected, please check and restart the script"
                exit $?
        fi
}

FRIDA(){
cd /root/android-tools/firda/
echo -e "${RED} ${BOLD} install frida & frida-tools ${REST} ${RESET}"
pip3 install frida > /dev/null 2>&1
pip3 install frida-tools > /dev/null 2>&1

echo -e "${RED} ${BOLD}setup frida server & push it to android emulator${REST} ${RESET}"
wget "https://github.com/frida/frida/releases/download/$(frida --version)/frida-server-$(frida --version)-android-x86_64.xz" -O frida-server.xz > /dev/null 2>&1
unxz frida-server.xz > /dev/null 2>&1


if test -n "$ADB_OUT"
        then  
               echo -e "push frida-server to device "
               adb push frida-server /data/local/tmp 
               adb shell "chmod 755 /data/local/tmp/frida-server"   
        else
               echo "skip to bush frida-server to device"
        fi

}

#@> install Drozer and client apk
DROZER(){
echo -e "${RED} install Requirement for drozer ${REST}"
pip2.7 install twisted > /dev/null 2>&1
pip2.7 install pyOpenSSL > /dev/null 2>&1
pip2.7 install protobuf > /dev/null 2>&1

cd /root/android-tools/dorzer
echo -e "${RED} install Drozer ${REST}"
wget https://github.com/FSecureLABS/drozer/releases/download/2.4.4/drozer-2.4.4-py2-none-any.whl > /dev/null 2>&1
pip2.7 install drozer-2.4.4-py2-none-any.whl > /dev/null 2>&1

echo -e "${RED}Get  Agent${REST}"
#check for connection about adb 
wget https://github.com/mwrlabs/drozer/releases/download/2.3.4/drozer-agent-2.3.4.apk > /dev/null 2>&1

if test -n "$ADB_OUT"
        then  
               echo -e "${RED} Install Agent in device ${REST}"
 #              $ADB_PATH install drozer-agent-2.3.4.apk > /dev/null 2>&1
               $ADB_PATH forward tcp:31415 tcp:31415   
        else
               
               echo -e "${RED}Check for connection adb device for now will skip install ${REST}"
        fi

}
#@> BURP
#Setting up Burp Suite with Android Emulated Device

#Navigate to Burp -> Proxy -> Options -> Export CA certificate -> Certificate in DER format.
#@> BURP
BURP(){

openssl x509 -inform DER -in $FILE -out /root/android-tools/burp/cacert.pem
openssl x509 -inform PEM -subject_hash_old -in /root/android-tools/burp/cacert.pem | head -1 
mv /root/android-tools/burp/cacert.pem  /root/android-tools/burp/9a5ba575.0


if test -n "$ADB_OUT"
        then  
              echo -e "${RED} Install Cert in Android Device ${REST}"
              cd /root/android-tools/burp
              $ADB_PATH remount
              $ADB_PATH push /root/android-tools/burp/9a5ba575.0 /system/etc/security/cacerts/
              $ADB_PATH shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
              $ADB_PATH shell reboot
        else
               
               echo -e "${RED}Check for connection adb device for now will skip install ${REST}"
        fi
} 


#@> BANNER
BANNER(){

echo -e ""
echo -e "${BLUE}
 \ \ / /                (_)                
  \ V /    ___   _ __    _    ___    _ __  
   > <    / _ \ | '_ \  | |  / _ \  | '_ \ 
  / . \  |  __/ | | | | | | | (_) | | | | |
 /_/ \_\  \___| |_| |_| |_|  \___/  |_| |_|
 ${RESET}
[${YELLOW}Xenion${RESET}] == INSTALLER TOOLS FOR ANDROID PENTEST (${GREEN} @Xenion_${RESET})

"
CONNECT_ADB $ip_device

# check extention of burp 
if test -f "$FILE"; then
    ext="${FILE##*.}"
    if [[ $ext == der ]]; then
    echo ""
    else
    echo "not der file"
    fi
else
   echo "$FILE file is not exists"
   exit $?
        fi   
}



#@ > Main Fuctions
BANNER

MAKDR

LANGUAGES

TOOLS

CONNECT_ADB

FRIDA

DROZER

BURP
