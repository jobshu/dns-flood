# dns-flood-tool

Original codes found on code.google.com & Github  

Use raw sockets to generate DNS flood attack.  

Original Here: https://code.google.com/p/dns-flood/  
               and  
               https://github.com/nickwinn/dns-flood/  

Changes:  
	1. Change to use /dev/urandom as the random seed;  
	2. Add feature to generate random QNAME;  
	3. Support all DNS Query Type;  
	4. Make the Query comply with RFC 1035;  
	5. Add feature to specific target domain and with random QNAME;  
	6. Change default ephemeral port range comply with RFC 6056;  
	7. Add feature to select ephemeral port range between 0~65535 or 1024~65535;  
	8. Add feature to specific source port number, include port 0;  

## How to install

1. Clone Repo
2. Run Make
3. Enjoy Kittens
 
## How to run

Usage: ./dnsflood <query_name> <destination_ip> [options]  
	<query_name>		input "random" to enable random query name  
	Options:  
	-t, --type		query type  
	-T, --target		target domain name  
	-s, --source-ip		source ip  
	-p, --dest-port		destination port  
	-P, --src-port		source port, default comply with RFC6056, '-1' - range 0~65535  
	-i, --interval		interval (in millisecond) between two packets  
	-n, --number		number of DNS requests to send  
	-r, --random		fake random source IP  
	-D, --daemon		run as daemon  
	-h, --help
