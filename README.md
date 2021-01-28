# recursive-virustotal
Recursively calculates the hash of all files in a given path and checks them against the Virustotal threat database.
This script can be used in many different scenarios, my specific use case is in combination with NetworkMiner.
NetworkMiner can extract files from pcap traffic files. It is possible to manually calculate the hash of individual files and copy/paste it into VirusTotal.
To get a quick overview on suspicious files it is of course much faster to automate this process, which is why I decided to write this small script.
