#!/bin/bash
#@alexandrevvo

#falta tratar um recon nas portas udp. como está agora o recon pode acontecer antes do scan udp.

checkOS(){
if [ "$1" == 256 ] || [ "$1" == 255 ] || [ "$1" == 254 ]; then
        echo "OpenBSD/Cisco/Oracle"
elif [ "$1" == 128 ] || [ "$1" == 127 ]; then
        echo "Windows"
elif [ "$1" == 64 ] || [ "$1" == 63 ]; then
        echo "Linux"
else
        echo "Unknown OS!"
fi
}

recon(){

reconRecommend "$1" "$2" | tee "$2"/nmap/Recon_"$1".nmap

availableRecon=$(cat "$2"/nmap/Recon_"$1".nmap | grep "$1" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)

secs=30
count=0

reconCommand=""

runRecon "$1" "$2"

}

reconRecommend(){
echo -e "${GREEN}---------------------Recon Recommendations----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [ -f "$2"/nmap/Full_"$1".nmap ] && [ -f "$2"/nmap/Basic_"$1".nmap ]; then
	ports=$(echo "${allPorts}")
	file=$(cat "$2"/nmap/Basic_"$1".nmap "$2"/nmap/Full_"$1".nmap | grep -w "open")
elif [ -f "$2"/nmap/Full_"$1".nmap ]; then
	ports=$(echo "${allPorts}")
	file=$(cat "$2"/nmap/Quick_"$1".nmap "$2"/nmap/Full_"$1".nmap | grep -w "open")
elif [ -f "$2"/nmap/Basic_"$1".nmap ]; then
	ports=$(echo "${basicPorts}")
	file=$(cat "$2"/nmap/Basic_"$1".nmap | grep -w "open")
else
	ports=$(echo "${basicPorts}")
	file=$(cat "$2"/nmap/Quick_"$1".nmap | grep -w "open")

fi

if [[ ! -z $(echo "${file}" | grep -i http) ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Web Servers Recon:"
	echo -e "${NC}"
fi

for line in $file; do
	if [[ ! -z $(echo "${line}" | grep -i http) ]]; then
		port=$(echo "${line}" | cut -d "/" -f 1)
		if [[ ! -z $(echo "${line}" | grep -w "IIS") ]]; then
			pages=".html,.asp,.aspx,.php"
		else
			pages=".html,.php"
		fi
		if [[ ! -z $(echo "${line}" | grep ssl/http) ]]; then
			#echo "sslyze --regular $1 | tee recon/sslyze_$1_$port.txt"
			echo "sslscan _target_ | tee recon/sslscan_$1_$port.txt"
			echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x $pages -u https://_target_:$port -o recon/gobuster_$1_$port.txt"
			#echo "nikto -host https://$1:$port -ssl | tee recon/nikto_$1_$port.txt"
		else
			echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x $pages -u http://_target_:$port -o recon/gobuster_$1_$port.txt"
			#echo "nikto -host $1:$port | tee recon/nikto_$1_$port.txt"
		fi
		echo ""
	fi
done

if [ -f "$2"/nmap/Basic_"$1".nmap ]; then
	cms=$(cat "$2"/nmap/Basic_"$1".nmap | grep http-generator | cut -d " " -f 2)
	if [ ! -z $(echo "${cms}") ]; then
		for line in $cms; do
			port=$(cat "$2"/nmap/Basic_"$1".nmap | grep "$line" -B1 | grep -w "open" | cut -d "/" -f 1)
			if [[ "$cms" =~ ^(Joomla|WordPress|Drupal)$ ]]; then
				echo -e "${NC}"
				echo -e "${YELLOW}CMS Recon:"
				echo -e "${NC}"
			fi
			case "$cms" in
				Joomla!) echo "joomscan --url _target_:$port | tee recon/joomscan_$1_$port.txt";;
				WordPress) echo "wpscan --url _target_:$port --enumerate p | tee recon/wpscan_$1_$port.txt";;
				Drupal) echo "droopescan scan drupal -u _target_:$port | tee recon/droopescan_$1_$port.txt";;
			esac
		done
	fi
fi

if [[ ! -z $(echo "${file}" | grep -w "445/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}SMB Recon:"
	echo -e "${NC}"
	echo "smbmap -H _target_ | tee recon/smbmap_$1.txt"
	echo "smbclient -L \"//_target_/\" -U \"guest\"% | tee recon/smbclient_$1.txt"
	if [[ $osType == "Windows" ]]; then
		echo "nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_$1.txt _target_"
	fi
	if [[ $osType == "Linux" ]]; then
		echo "enum4linux -a _target_ | tee recon/enum4linux_$1.txt"
	fi
	echo ""
elif [[ ! -z $(echo "${file}" | grep -w "139/tcp") ]] && [[ $osType == "Linux" ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}SMB Recon:"
	echo -e "${NC}"
	echo "enum4linux -a _target_ | tee recon/enum4linux_$1.txt"
	echo ""
fi


if [ -f "$2"/nmap/UDP_"$1".nmap ] && [[ ! -z $(cat "$2"/nmap/UDP_"$1".nmap | grep open | grep -w "161/udp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}SNMP Recon:"
	echo -e "${NC}"
	echo "snmp-check _target_ -c public | tee recon/snmpcheck_$1.txt"
	echo "snmpwalk -Os -c public -v1 _target_ | tee recon/snmpwalk_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "53/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}DNS Recon:"
	echo -e "${NC}"
	echo "host -l _target_ _target_ | tee recon/hostname_$1.txt"
	echo "dnsrecon -r $subnet/24 -n _target_ | tee recon/dnsrecon_$1.txt"
	echo "dnsrecon -r 127.0.0.0/24 -n _target_ | tee recon/dnsrecon-local_$1.txt"
	echo "dig -x $1 @_target_ | tee recon/dig_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "389/tcp") ]]; then
        echo -e "${NC}"
        echo -e "${YELLOW}ldap Recon:"
        echo -e "${NC}"
        echo "ldapsearch -x -h _target_ -s base | tee recon/ldapsearch_$1.txt"
        echo "ldapsearch -x -h _target_ -b \$(cat recon/ldapsearch_$1.txt | grep rootDomainNamingContext | cut -d ' ' -f2) | tee recon/ldapsearch_DC_$1.txt"
        echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(cat recon/ldapsearch_$1.txt | grep rootDomainNamingContext | cut -d \\" \\" -f2)\"' _target_ -oN recon/nmap_ldap_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "1521/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Oracle Recon \"Exc. from Default\":"
	echo -e "${NC}"
	echo "cd /opt/odat/;#_target_;"
	echo "./odat.py sidguesser -s _target_ -p 1521"
	echo "./odat.py passwordguesser -s _target_ -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
	echo "cd -;#_target_;"
	echo ""
fi

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

runRecon(){
echo -e ""
echo -e ""
echo -e ""
echo -e "${GREEN}---------------------Running Recon Commands----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [[ ! -d recon/ ]]; then
        mkdir recon/
fi

cat "$2"/nmap/Recon_"$1".nmap | grep "$1" | grep -v odat > recon/recon_cmd_$1.txt

interlace -t "$1" -cL recon/recon_cmd_$1.txt -threads 20

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}


checkPing(){
pingTest=$(ping -c 1 -W 3 "$1" | grep ttl)
if [[ -z $pingTest ]]; then
	echo "nmap -Pn"
else
	echo "nmap"
	ttl=$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)
	echo "${ttl}"
fi
}

assignPorts(){
if [ -f "$2"/nmap/Quick_"$1".nmap ]; then
	basicPorts=$(cat "$2"/nmap/Quick_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
fi

if [ -f "$2"/nmap/Full_"$1".nmap ]; then
	if [ -f "$2"/nmap/Quick_"$1".nmap ]; then
		allPorts=$(cat "$2"/nmap/Quick_"$1".nmap "$2"/nmap/Full_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-1)
	else
		allPorts=$(cat "$2"/nmap/Full_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1)
	fi
fi
}

main(){
checkPing=$(checkPing "$1")
#nmapType="nmap -Pn"

nmapType=`echo "${checkPing}" | head -n 1`

if [ "$nmapType" != "nmap" ]; then 
	echo -e "${NC}"
	echo -e "${YELLOW}No ping detected.. Running with -Pn option!"
	echo -e "${NC}"
fi


ttl=$(echo "${checkPing}" | tail -n 1)
if [[  $(echo "${ttl}") != "nmap -Pn" ]]; then
	osType="$(checkOS "$ttl")"	
	echo -e "${NC}"
	echo -e "${GREEN}Host is likely running $osType"
	echo -e "${NC}"
fi

echo -e ""
echo -e ""
}

main "$1" "$2"
assignPorts "$1" "$2"
recon "$1" "$2"