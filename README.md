chmod +x origin-ip-finder-advanced.sh
./origin-ip-finder-advanced.sh -d sempra.com -o "Sempra Energy" -b -D -t 50
naabu -list sempra_com_ips.txt -top-ports 1000 -silent
