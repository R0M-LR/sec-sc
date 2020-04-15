#!/bin/bash
# S&C v1.0

if [ -z "$1" ]; then
	read -p "Your target : " TARGET
else
	TARGET="$1"
fi


PORT_TO_SCAN=0
USER_FILE="common_usernames.txt"
PASS_FILE="/usr/share/wordlists/metasploit/burnett_top_1024.txt"
MIN_PASS="common_pass.txt"
DIRB_DIR="/usr/share/dirbuster/wordlists/directory-list-1.0.txt"
SNMP_STRINGS="/usr/share/seclists/Miscellaneous/wordlist-common-snmp-community-strings.txt"
COLOR_RED='\033[91m'
COLOR_GREEN='\033[92m'
COLOR_ORANGE='\033[93m'
RESET='\e[0m'

echo -e "$COLOR_GREEN Ready for scan !.$RESET"

echo -e "													"
echo -e "													"
echo -e "	                                |     |			"
echo -e "	  I'm just going to check      \/\_V_/\/		"
echo -e "	  a few things...               \/=|=\/			"
echo -e "	                                 [=v=]			"
echo -e "	                               __\___/_____		"
echo -e "	                              /..[  _____  ]	"
echo -e "	                             /_  [ [  M /] ]	"
echo -e "	                            /../.[ [ M /@] ]	"
echo -e "	                           <-->[_[ [M /@/] ]	"
echo -e "	                          /../ [.[ [ /@/ ] ]	"
echo -e "	     _________________]\ /__/  [_[ [/@/ C] ]	"
echo -e "	    <_________________>>0---]  [=\ \@/ C / /	"
echo -e "	       ___      ___   ]/000o   /__\ \ C / /		"
echo -e "	          \    /              /....\ \_/ /		"
echo -e "	       ....\||/....           [___/=\___/		"
echo -e "	      .    .  .    .          [...] [...]		"	
echo -e "	     .      ..      .         [___/ \___]		"
echo -e "	     .    0 .. 0    .         <---> <--->		"
echo -e "	  /\/\.    .  .    ./\/\      [..]   [..]		"
echo -e "	 / / / .../|  |\... \ \ \    _[__]   [__]_		"
echo -e "	/ / /       \/       \ \ \  [____>   <____]		"	
echo -e "													"


# Prerequisite
# -----------------------------------------------------------
# apt update && apt-get install python-pip git seclists -yy
# gem install winrm winrm-fs colorize stringio
# gem install evil-winrm
# git clone https://github.com/SecureAuthCorp/impacket.git
# pip install --upgrade pip
# pip install pycrypto cryptography pyasn1 pyOpenSSL ldapdomaindump jinja2 tox
# cd impacket
# python setup.py install

read -p "Press [Enter] key to start the scan..."

nmap -sS -T5 -sV -A --open -p- $TARGET -oX $TARGET.xml
port_21=`grep 'portid="21"' $TARGET.xml | grep open`
port_22=`grep 'portid="22"' $TARGET.xml | grep open`
port_25=`grep 'portid="25"' $TARGET.xml | grep open`
port_80=`grep 'portid="80"' $TARGET.xml | grep open`
port_110=`grep 'portid="110"' $TARGET.xml | grep open`
port_111=`grep 'portid="111"' $TARGET.xml | grep open`
port_135=`grep 'portid="135"' $TARGET.xml | grep open`
port_139=`grep 'portid="139"' $TARGET.xml | grep open`
port_161=`grep 'portid="161"' $TARGET.xml | grep open`
port_162=`grep 'portid="162"' $TARGET.xml | grep open`
port_443=`grep 'portid="443"' $TARGET.xml | grep open`
port_445=`grep 'portid="445"' $TARGET.xml | grep open`
port_2121=`grep 'portid="2121"' $TARGET.xml | grep open`
port_3306=`grep 'portid="3306"' $TARGET.xml | grep open`
port_3389=`grep 'portid="3389"' $TARGET.xml | grep open`
port_8080=`grep 'portid="8080"' $TARGET.xml | grep open`


function nmap_web_scan (){
	nmap -p$PORT_TO_SCAN --script=http-adobe-coldfusion-apsa1301 \
		--script=http-affiliate-id \
		--script=http-apache-negotiation \
		--script=http-apache-server-status \
		--script=http-aspnet-debug \
		--script=http-auth-finder \
		--script=http-auth \
		--script=http-backup-finder \
		--script=http-brute \
		--script=http-coldfusion-subzero  \
		--script=http-config-backup \
		--script=http-cookie-flags \
		--script=http-cors \
		--script=http-csrf \
		--script=http-cross-domain-policy \
		--script=http-default-accounts \
		--script=http-enum \
		--script=http-errors \
		--script=http-frontpage-login \
		--script=http-iis-short-name-brute \
		--script=http-iis-webdav-vuln \
		--script=http-methods \
		--script=http-method-tamper \
		--script=http-passwd \
		--script=http-phpmyadmin-dir-traversal \
		--script=http-phpself-xss \
		--script=http-shellshock \
		--script=http-php-version \
		--script=http-put \
		--script=http-robots.txt \
		--script=http-server-header \
		--script=http-shellshock \
		--script=http-title \
		--script=http-userdir-enum \
		--script=http-vuln-cve2006-3392 \
		--script=http-vuln-cve2009-3960 \
		--script=http-vuln-cve2010-0738 \
		--script=http-vuln-cve2010-2861 \
		--script=http-vuln-cve2011-3192 \
		--script=http-vuln-cve2011-3368 \
		--script=http-vuln-cve2012-1823 \
		--script=http-vuln-cve2013-0156 \
		--script=http-vuln-cve2013-6786 \
		--script=http-vuln-cve2013-7091 \
		--script=http-vuln-cve2014-2126 \
		--script=http-vuln-cve2014-2127 \
		--script=http-vuln-cve2014-2128 \
		--script=http-vuln-cve2014-2129 \
		--script=http-vuln-cve2014-3704 \
		--script=http-vuln-cve2014-8877 \
		--script=http-vuln-cve2015-1427 \
		--script=http-vuln-cve2015-1635 \
		--script=http-vuln-cve2017-1001000 \
		--script=http-vuln-cve2017-5638 \
		--script=http-vuln-cve2017-5689 \
		--script=http-vuln-cve2017-8917 $TARGET
}


####################### Web enumeration ##############################

if [ -z "$port_80" ];
	
	then
		echo -e "$COLOR_RED + -- --=[Port 80 closed... skipping.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 80 opened... running tests...$RESET"
		
		PORT_TO_SCAN=80

		nikto -Save -output nikto_80.txt -Display 123 -nointeractive -nossl -host $TARGET
		davtest -url http://$TARGET/

		# Nmap web scan custom version
		nmap_web_scan


fi


if [ -z "$port_443" ];
	
	then
		echo -e "$COLOR_RED + -- --=[Port 443 closed... skipping.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 443 opened... running tests...$RESET"
		
		PORT_TO_SCAN=443
		
		# Nmap web scan custom version
		nmap_web_scan

		nikto -Save -output nikto_443.txt -Display 123  -nointeractive -host $TARGET --port 443
		davtest -url https://$TARGET/
		nmap  -p443 -script=ssl-heartbleed $TARGET	
fi


# Range of ports -> 8080-8099 to test cam
# http-axis2-dir-traversal

if [ -z "$port_8080" ];
	
	then
		echo -e "$COLOR_RED + -- --=[Port 8080 closed... skipping.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 8080 opened... running tests...$RESET"

		PORT_TO_SCAN=8080
		# Nmap web scan custom version
		nmap_web_scan

		nikto -Save -output nikto_8080.txt -Display 123 -nointeractive -host $TARGET --port 8080
		davtest -url http://$TARGET:8080/
fi


####################### End Web enumeration ##########################

read -p "Press [Enter] key to start Dirb..."

####################### Dirb start ? #################################

if [ -z "$port_80" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 80 closed... skipping extensive directory browsing.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 80 opened... running extensive directory browsing...$RESET"
		dirb http://$TARGET/ $DIRB_DIR -w -r
	fi


if [ -z "$port_443" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 443 closed... skipping extensive directory browsing.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 443 opened... running extensive directory browsing...$RESET"
		dirb https://$TARGET:443/ $DIRB_DIR -w -r
	fi

if [ -z "$port_8080" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 8080 closed... skipping extensive directory browsing.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 8080 opened... running extensive directory browsing...$RESET"
		dirb http://$TARGET:8080/ $DIRB_DIR -w -r
	fi


####################### End of Dirb #################################


if [ -z "$port_21" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 21 closed... skipping.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 21 opened... running tests...$RESET"
		nmap -A -sV -sC -T5 -p21 --script="ftp-*" $TARGET
	fi

if [ -z "$port_25" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 25 closed... skipping.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 25 opened... running tests...$RESET"
		nmap -A -sV -sC -T5 -p25 --script="smtp-vuln-*" $TARGET
		smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET 
		smtp-user-enum -M EXPN -U $USER_FILE -t $TARGET 
		smtp-user-enum -M RCPT -U $USER_FILE -t $TARGET 
	fi


if [ -z "$port_161" ];
then
	echo -e "$COLOR_RED + -- --=[Port 161 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 161 opened... running tests...$RESET"
	for a in `cat $SNMP_STRINGS`; do snmp-check -t $TARGET -c $a; done;
	nmap -sU -p 161 --script="snmp*" $TARGET
fi

if [ -z "$port_162" ];
then
	echo -e "$COLOR_RED + -- --=[Port 162 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 162 opened... running tests...$RESET"
	for a in `cat $SNMP_STRINGS`; do snmp-check -t $TARGET -c $a; done;
	nmap -A -p 162 --script="snmp*" $TARGET
fi

if [ -z "$port_110" ];
then
	echo -e "$COLOR_RED + -- --=[Port 110 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 110 opened... running tests...$RESET"
	nmap -A -sV -T5 --script="pop3--capabilities" --script="pop3-ntlm-info" -p 110 $TARGET
fi

if [ -z "$port_111" ];
then
	echo -e "$COLOR_RED + -- --=[Port 111 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 111 opened... running tests...$RESET"
	showmount -a $TARGET
	showmount -d $TARGET
	showmount -e $TARGET
fi

if [ -z "$port_135" ];
then
	echo -e "$COLOR_RED + -- --=[Port 135 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 135 opened... running tests...$RESET"
	rpcinfo -p $TARGET
	nmap -A -p 135 -T5 --script="rpc*" $TARGET
fi


if [ -z "$port_445" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 445 closed... skipping.$RESET"
			if [ -z "$port_139" ];
				then
			echo -e "$COLOR_RED + -- --=[Port 139 closed... skipping.$RESET"
				else
			echo -e "$COLOR_ORANGE + -- --=[Port 139 opened... running tests...$RESET"
			enum4linux -a $TARGET
			nmap -p139 $TARGET --script="smb-vuln*"	
			fi
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 445 opened... running tests...$RESET"
		enum4linux -a $TARGET
		nmap -p445 $TARGET --script="smb-vuln*"	
	fi

if [ -z "$port_2121" ];
then
	echo -e "$COLOR_RED + -- --=[Port 2121 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 2121 opened... running tests...$RESET"
	nmap -A -sV -T5 --script="ftp-*" -p2121 $TARGET
	fi

if [ -z "$port_3306" ];
then
	echo -e "$COLOR_RED + -- --=[Port 3306 closed... skipping.$RESET"
else
	echo -e "$COLOR_ORANGE + -- --=[Port 3306 opened... running tests...$RESET"
	nmap -A -sV --script="mysql*" -p 3306 $TARGET
	mysql -u root -h $TARGET -e 'SHOW DATABASES; SELECT Host,User,Password FROM mysql.user;'
fi





read -p "Press [Enter] key to start brute force..."



if [ -z "$port_21" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 21 closed... skipping brute force.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 21  start brute force......$RESET"
		medusa -h $TARGET -U $USER_FILE -P $MIN_PASS -e ns -M ftp -v 1	
	fi

if [ -z "$port_22" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 22 closed... skipping brute force.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 22 opened...  start brute force...$RESET"
		medusa -h $TARGET -U $USER_FILE -P $MIN_PASS -e ns -M ssh -v 1
	fi


if [ -z "$port_445" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 445 closed... skipping brute force.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 445 opened...  start brute force...$RESET"
		medusa -h $TARGET -U $USER_FILE -P $MIN_PASS -e ns -M SMBNT -v 1
		echo -e "$COLOR_RED + -- -- If anon login allowed use the nmap brute force below...$RESET"
		#nmap -p445 --script=smb-brute --script-args smblockout=true,userdb=$USER_FILE,passdb=$MIN_PASS $TARGET
	fi

if [ -z "$port_3389" ];
	then
		echo -e "$COLOR_RED + -- --=[Port 3389 closed... skipping brute force.$RESET"
	else
		echo -e "$COLOR_ORANGE + -- --=[Port 3389 opened...  start brute force...$RESET"
		rdesktop $TARGET &
		medusa -h $TARGET -U $USER_FILE -P $MIN_PASS -e ns -M RDP -v 1
	fi
