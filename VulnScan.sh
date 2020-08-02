#!/bin/bash
#@alexandrevvo

vulnsScan(){
echo -e "${GREEN}---------------------Starting Nmap Vulns Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${allPorts}") ]; then
	portType="basic"
	ports=$(echo "${basicPorts}")
else
	portType="all"
	ports=$(echo "${allPorts}")
fi


if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
	echo -e "${RED}Please install 'vulners.nse' nmap script:"
	echo -e "${RED}https://github.com/vulnersCom/nmap-vulners"
        echo -e "${RED}"
        echo -e "${RED}Skipping CVE scan!"
	echo -e "${NC}"
else    
	echo -e "${YELLOW}Running CVE scan on $portType ports"
	echo -e "${NC}"
	$nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN "$2"/nmap/CVEs_"$1".nmap "$1"
	echo ""
fi

echo ""
echo -e "${YELLOW}Running Vuln scan on $portType ports"
echo -e "${NC}"
$nmapType -sV --script vuln -p$(echo "${ports}") -oN "$2"/nmap/Vulns_"$1".nmap "$1"
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

main "$1"
assignPorts "$1"
vulnsScan "$1"
