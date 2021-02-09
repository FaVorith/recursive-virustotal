# coding: utf-8
 
__author__ = 'Fabian Voith'
__email__ = 'admin@fabian-voith.de'
#########################
# When first running the script, a default config.yaml will be created.
# Adjust config.yaml before using the script a second time.
# Especially the following two values need to be adjusted:
# api_key: *your VT API Key, see: https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key *
# file_path: *top folder from where you want to start your scan, e.g. /opt/NetworkMiner_2-6 *
#########################

import yaml
import sys
import json
import hashlib
import glob
import os
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi
#import argparse

class simpleFile:
    # simple file object, automatically calculates hash of itself

    def calculate_hash(self, file_name):
        sha256_hash = hashlib.sha256()
        with open(file_name,'rb') as f:
            # Read and update hash string value in blocks of 4K to avoid buffer overflow
            for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)

        return(sha256_hash.hexdigest())
    
    def __init__(self, file_name):
        self.file_name = file_name
        self.hash = self.calculate_hash(file_name)

    def get_hash(self):
        return(self.hash)

    def get_file_name(self):
        return(self.file_name)

class observedEntity:
    # Contains one hash and all file names that share this hash
    # It also holds the raw VirusTotal result and provides distilled threat intel information
    def __init__(self, file, alerting_level):
        self.files = []
        self.files.append(file.get_file_name())
        self.hash = file.get_hash()
        self.isMalicious = False
        self.vt_result = ''
        self.positives = 0
        self.total_scanners = 1 # to avoid division by zero error
        self.ALERTING_LEVEL = alerting_level

    def add_file_name(self, file_name):
        # if a file has the identical hash like another observed entity, we just add the file name
        # so that we will poll the VirusTotal result only once.
        self.files.append(file_name)

    def get_file_names(self):
        # returns the array of file names that share the hash and therefore the VirusTotal results.
        return(self.files)

    def get_hash(self):
        # returns the hash of the observed entity, also used for checking against VirusTotal
        return(self.hash)

    def add_virustotal_result(self, result):
        self.vt_result = result

         # Convert json to dictionary:
        json_data = json.loads(json.dumps(result))
        try:
            if json_data['results']['response_code'] == 1:
                # we got a valid response
                self.total_scanners = json_data['results']['total']
                self.positives = json_data['results']['positives']
                self.scan_date = json_data['results']['scan_date']
        except KeyError:
            print("Received unexpected response from VirusTotal:")
            print(result)
            sys.exit(f"\nReceived invalid response from VirusTotal. Did you enter a valid VT API Key in the config file?")


    def get_virustotal_result(self):
        return(self.vt_result)

    def is_malicious(self):
        # the definition of "malicious" is not fixed.
        # What we say here is that if a certain number of engines discover the file to be malicious,
        # then we deem it potentially malicious.
        # We use a ratio here, for example 0.1=10%:
        return(self.count_alerting_scanners() / self.count_total_scanners() >= self.ALERTING_LEVEL)

    def count_total_scanners(self):
        # number of AV scanners that were used to check this file
        return(self.total_scanners)

    def count_alerting_scanners(self):
        # number of AV scanners that reported the file as malicious
        return(self.positives)

    

class entityHandler:
    # manages observed entities, i.e. adds new entities if they were not observed before
    # or otherwise updates information on previously observed entities

    def __init__(self):
        self.hash_dict = {}

    def add_file(self, file, alerting_level):
        # check if other files with same hash were already processed (duplicates)
        new_file = simpleFile(file)
        existing_duplicates = self.hash_dict.get(new_file.get_hash())
        if existing_duplicates is not None:
            # Other files with an identical hash are already present, we just add the file name:
            existing_duplicates.add_file_name(new_file.get_file_name())
        else:
            # We see this hash for the first time and add it to the list:
            self.hash_dict.update({new_file.get_hash():observedEntity(new_file, alerting_level)})

    def get_entities(self):
        # returns an iterable of all observed entities so that they can be checked
        return(self.hash_dict.items())

    def count_entities(self):
        # number of entities (i.e. files with unique hash) in scope
        return(len(self.hash_dict))

    def retrieve_virustotal_results(self):
        # Starts the polling of VirusTotal results for all observed entities
        # VT rate limit is 4 requests per minute. If we have <= 4 unique hashes,
        # we can query them without waiting:
        if entity_handler.count_entities() <= 4:
            waiting_time = 0
        else:
            waiting_time = 15

        i = 0
        for hash, observed_entity in self.get_entities():
            i+=1
            print(f'Processing {i} out of {self.count_entities()}...')
            observed_entity.add_virustotal_result(vt.get_file_report(hash))
            # The free VirusTotal API is rate-limited to 4 requests per minute.
            # If you have a premium key without rate limiting, you can remove the following line:
            time.sleep(waiting_time)

    
# Initialize program / load config
CONFIG_FILE = 'config.yaml'
try:
    with open(CONFIG_FILE, 'r') as config_file:
        config = yaml.safe_load(config_file)
except FileNotFoundError:
    print(f"There was no valid {CONFIG_FILE} file in the directory of this script.")
    print("The file will be created for you, but you still need to enter your valid VirusTotal API key.")
    default_yaml = """
virustotal:
  api_key: enter your API key
  alerting_level: 0.1
file_path: /opt/NetworkMiner_2-6
recursive: True
"""
    with open(CONFIG_FILE, 'w') as config_file:
        yaml.dump(yaml.safe_load(default_yaml), config_file, default_flow_style=False)  

    sys.exit(f"\nNo valid API key in {CONFIG_FILE} file found.")
    
VT_KEY = config['virustotal']['api_key']
ALERTING_LEVEL = config['virustotal']['alerting_level']
IS_RECURSIVE = config['recursive']

# if a path was provided as command line parameter, it will override the config.yaml path:

# create parser
#parser = argparse.ArgumentParser()
 
# add arguments to the parser
#parser.add_argument("alertlv")
#parser.add_argument("path")
 
# parse the arguments
#args = parser.parse_args()

#print("Alert Level:"+args.alertlv)
#print("Path:"+args.path)

if len(sys.argv) > 1:
    FILE_PATH = sys.argv[1]
    print(f'Using {FILE_PATH} as parameter to search.')
else: 
    FILE_PATH = config['file_path']

vt = VirusTotalPublicApi(VT_KEY)

entity_handler = entityHandler()

# recursively read all files from the given directory
for file in glob.iglob(FILE_PATH+'/**/*', recursive=IS_RECURSIVE):
    # only calculate the hash of a file, not of folders:
    if os.path.isfile(file):
        # we add the alerting threshold to each individual entity.
        # This allows us to work with different alerting levels per file (type).
        # For now we keep it simple and assign the same level (default: 0.1) to all of them.
        entity_handler.add_file(file, ALERTING_LEVEL)
       

# VirusTotal polling
entity_handler.retrieve_virustotal_results()

# return relevant results
findings_counter = 0
for hash, observed_entity in entity_handler.get_entities():
    if observed_entity.is_malicious():
        findings_counter+=1
        print(f'====== {hash} ======')
        print('Potentially malicious hash for the following (identical) files:')

        i = 0
        for f in observed_entity.get_file_names():
            i+=1
            print(f'{i}: {f}')

        print(f'\n{observed_entity.count_alerting_scanners()} out of {observed_entity.count_total_scanners()} scanners identified this file as malicious.')
        print('--------------------------------------------------------\n\n\n')
        #print(f'VT Result is: {observed_entity.get_virustotal_result()}')

print(f'Finished processing {entity_handler.count_entities()} files. {findings_counter} findings were reported.')
        