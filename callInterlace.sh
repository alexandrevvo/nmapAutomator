directory=$(dirname $0)
"$directory"/Recon.sh _target_
"$directory"/VulnScan.sh _target_
"$directory"/UdpScan.sh _target_

#### falta enviar para os scripts o diretório original de onde o nmap foi chamado.. para assim as pastas serem criadas
# no lugar certo;3,



