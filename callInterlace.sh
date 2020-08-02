#!/bin/bash
#@alexandrevvo

directory=$(dirname $0)
"$directory"/Recon.sh "$1" "$2"
"$directory"/VulnScan.sh "$1" "$2"
"$directory"/UdpScan.sh "$1" "$2"

#### falta enviar para os scripts o diretório original de onde o nmap foi chamado.. para assim as pastas serem criadas
# no lugar certo;3,



