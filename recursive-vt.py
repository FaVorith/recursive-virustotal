import yaml
import json
import hashlib
import glob
import os
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi

class observedEntity:
    

CONFIG_FILE = 'config.yaml'

with open(CONFIG_FILE, 'r') as config_file:
    config = yaml.load(config_file)
    
VT_KEY = config['virustotal']['api_key']
MINER_PATH = config['networkminer']['file_path']

vt = VirusTotalPublicApi(VT_KEY)

hash_dict = {}

sha256_hash = hashlib.sha256()
for file in glob.iglob(MINER_PATH+'/**/*', recursive=True):
    # only calculate the hash of a file, not of folders:
    if os.path.isfile(file):
        with open(file,'rb') as f:
            # Read and update hash string value in blocks of 4K to avoid buffer overflow
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        print(file + " has hash: "+file_hash)

        # check if key exists in dictionary by checking if get() returned None
        files_with_same_hash = hash_dict.get(file_hash)
        if files_with_same_hash is not None:
            # Other files with an identical hash are already present, we just add the file name:
            files_with_same_hash.append(file)
        else:
            # We see this hash for the first time and add it to the list:
            hash_dict.update({file_hash:[file]})
            

# VT rate limit is 4 requests per minute. If we have <= 4 unique hashes,
# we can query them without waiting:
if len(files_with_same_hash) <= 4:
    waiting_time = 0
else:
    waiting_time = 15

for hash in hash_dict.items():
    response = vt.get_file_report(hash)
    print(response)
    time.sleep(waiting_time)

#print(hash_dict)