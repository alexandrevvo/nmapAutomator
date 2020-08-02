#!/bin/bash
#@alexandrevvo

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

UDPScan(){
echo -e "${GREEN}----------------------Starting Nmap UDP Scan----------------------"
echo -e "${NC}"

$nmapType -sU --max-retries 1 --open -oN "$2"/nmap/UDP_"$1".nmap "$1"

#assigning ports
if [ -f "$2"/nmap/UDP_"$1".nmap ]; then
	udpPorts=$(cat "$2"/nmap/UDP_"$1".nmap | grep -w "open " | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
	if [[ "$udpPorts" == "Al" ]]; then
		udpPorts=""
	fi
fi

if [ ! -z $(echo "${udpPorts}") ]; then
        echo ""
        echo ""
        echo -e "${YELLOW}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')"
        echo -e "${NC}"
	if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
        	$nmapType -sCVU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN "$2"/nmap/UDP_"$1".nmap "$1"
	else
        	$nmapType -sCVU -p$(echo "${udpPorts}") -oN "$2"/nmap/UDP_"$1".nmap "$1"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
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
UDPScan "$1" "$2"