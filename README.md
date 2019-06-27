# VASC

Vulnerability Analysis for Secure Connections(VASC) is a Python3 program for analysing Cipher Suite configurations in establishing SSL/TLS connections for weakness and vulnerabilities.

System requirements:
	Linux environment (Tested on Manjaro 18.0.4 running on Linux 4.19.49-1 kernel version)
	Python3
	Python packages:
		pandas
		argparse
		socket
		python-nmap
		subprocess
		lxml
	nmap
	nmap script:
		ssl-enum-ciphers.nse


How to run:
	Open terminal in the parent directory for the project
	Run the program using "Python3 main.py %filename %flag"
	Use flag -h for more help information
