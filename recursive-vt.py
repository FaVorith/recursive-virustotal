import yaml
import json
import hashlib
import glob
import os
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi

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
    # contains one hash and all file names that share this hash
    def __init__(self, file):
        self.files = []
        self.files.append(file.get_file_name())
        self.hash = file.get_hash()
        isMalicious = False
        vt_result = ''

    def add_file_name(self, file_name):
        self.files.append(file_name)

    def get_file_names(self):
        return(self.files)

    def get_hash(self):
        return(self.hash)

class entityHandler:
    # manages observed entities, i.e. adds new entities if they were not observed before
    # or otherwise updates information on previously observed entities

    def __init__(self):
        self.hash_dict = {}

    def add_file(self, file):
        # check if other files with same hash were already processed (duplicates)
        new_file = simpleFile(file)
        existing_duplicates = self.hash_dict.get(new_file.get_hash())
        if existing_duplicates is not None:
            # Other files with an identical hash are already present, we just add the file name:
            existing_duplicates.add_file_name(new_file.get_file_name())
        else:
            # We see this hash for the first time and add it to the list:
            self.hash_dict.update({new_file.get_hash():observedEntity(new_file)})

    def get_entities(self):
        return(self.hash_dict.items())

    def count_entities(self):
        return(len(self.hash_dict))

    
CONFIG_FILE = 'config.yaml'

with open(CONFIG_FILE, 'r') as config_file:
    config = yaml.load(config_file)
    
VT_KEY = config['virustotal']['api_key']
FILE_PATH = config['file_path']

vt = VirusTotalPublicApi(VT_KEY)

entity_handler = entityHandler()

for file in glob.iglob(FILE_PATH+'/**/*', recursive=True):
    # only calculate the hash of a file, not of folders:
    if os.path.isfile(file):   
        entity_handler.add_file(file)
       

# VT rate limit is 4 requests per minute. If we have <= 4 unique hashes,
# we can query them without waiting:
if entity_handler.count_entities() <= 4:
    waiting_time = 0
else:
    waiting_time = 15

for hash, observed_entity in entity_handler.get_entities():
    #response = vt.get_file_report(hash)
    #print(response)
    #time.sleep(waiting_time)
    print(f'Hash {hash} for the following files: {observed_entity.get_file_names()}')

#print(hash_dict)