#!/bin/bash
#@alexandrevvo
echo "***********************  $2   *******************"
directory=$(dirname $0)
bash "$directory"/Recon.sh "$1" "$2"
bash "$directory"/VulnScan.sh "$1" "$2"
bash "$directory"/UdpScan.sh "$1" "$2"




