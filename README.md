chmod +x origin-ip-finder-advanced.sh
./origin-ip-finder-advanced.sh -d sempra.com -o "Sempra Energy" -b -D -t 50
naabu -list sempra_com_ips.txt -top-ports 1000 -silent

./origin-ip-finder-pro.sh -d t-mobile.com -o "T-Mobile" -b -D \
    -k $vzmRD4EYDp9ndtZ6qNMcsCbfHxuA8CBF  -s oOrFLSCMTO9NA0UUVB3dgdXVFByefyLn -v 25184f231edcbecb04e568b038657b2c54b4fa49

chmod +x origin-ip-finder-pro.sh
./origin-ip-finder-pro.sh -d example.com -o "Example Inc" -b -D -k $SHODAN_KEY
naabu -list example_com_ips.txt -top-ports 1000 -silent


chmod +x origin-ip-finder-pro.sh

# Basic
./origin-ip-finder-pro.sh -d example.com -o "Example Inc"

# Full power (brute + deep permutations + all API keys)
export FULLHUNT_KEY=your_fullhunt_key      # optional
./origin-ip-finder-pro.sh -d example.com -o "Example Inc" -b -D \
    -k $SHODAN_KEY -c $CENSYS_ID:$CENSYS_SECRET -s $SECURITYTRAILS_KEY -v $VIEWDNS_KEY

# Then scan the confirmed IPs
naabu -list example_com_ips.txt -top-ports 1000 -silent


chmod +x origin-ip-finder-pro.sh

# Basic
./origin-ip-finder-pro.sh -d example.com -o "Example Inc"

# Full power (brute + deep permutations + all API keys)
export FULLHUNT_KEY=your_fullhunt_key      # optional
./origin-ip-finder-pro.sh -d example.com -o "Example Inc" -b -D \
    -k $SHODAN_KEY -c $CENSYS_ID:$CENSYS_SECRET -s $SECURITYTRAILS_KEY -v $VIEWDNS_KEY

# Then scan the confirmed IPs
naabu -list example_com_ips.txt -top-ports 1000 -silent

chmod +x origin-ip-finder-pro.sh

# Basic
./origin-ip-finder-pro.sh -d example.com -o "Example Inc"

# Full power (brute + deep permutations + all API keys)
export FULLHUNT_KEY=your_fullhunt_key      # optional
./origin-ip-finder-pro.sh -d example.com -o "Example Inc" -b -D \
    -k $SHODAN_KEY -c $CENSYS_ID:$CENSYS_SECRET -s $SECURITYTRAILS_KEY -v $VIEWDNS_KEY

# Then scan the confirmed IPs
naabu -list example_com_ips.txt -top-ports 1000 -silent
