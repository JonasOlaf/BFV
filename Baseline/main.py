from Client import Client
from Database import Database
from AS import AuthenticationServer
from Transforms import get_size, format_size
from os import remove
from os.path import getsize
import numpy as np
import pickle

import time

def print_result():
    splitter = '+---------------+'

    persons = len(db)
    ciphers = len(database.encrypted_templates)

    print(splitter)
    print('Operation timings')
    rots = database.timings['rot']
    decs = AS.timings['dec']
    ariths = database.timings['arith']
    total = rots + decs + ariths

    print(f'Enc ID:\t\t{round(total,3)}s')
    print(f' Rotations:\t{round(rots,3)}s  //  {round(rots/total,3)*100}%')
    print(f' Airths:\t{round(ariths,3)}s  //  {round(ariths/total,3)*100}%')
    print(f' Decrypts:\t{round(decs,3)}s  //  {round(decs/total,3)*100}%')


    print(splitter)
    print(f'Features:\t{n}')
    print(f'Slot count:\t{AS.slot_count}')
    print(f'Identities:\t{persons}')
    print(f'Ciphers:\t{ciphers}')
    print(f'Persons/cipher:\t{round(persons/ciphers,2)}')
    print(f'Rotations:\t{ciphers*(n-1)}')
    print(splitter)
    print('Timings:')
    print(f'Identities:\t{len(db)}')
    print(f'Initialisation:\t{round(t1-t0,2)}s')
    print(f'DB Encryption:\t{round(t3-t2, 2)}s')
    print(f' per person: \t{round(1000*(t3-t2)/persons,2)}ms')
    print(f' per cipher: \t{round(1000*(t3-t2)/ciphers,2)}ms')
    print(f'Identification:\t{round(t4-t3,2)}s')
    print(f' per person: \t{round(1000*(t4-t3)/persons,2)}ms')
    print(f' per cipher: \t{round(1000*(t4-t3)/ciphers,2)}ms')
    print(splitter)
    print('Sizes')
    keys = get_size(AS.public_key, format=1) + get_size(AS.secret_key, format=1) + get_size(AS.gal_keys, format=1) + get_size(AS.eval_keys, format=1)
    print(f'Keys\t\t{format_size(keys)}')
    print(f' Galois Key:\t{get_size(AS.gal_keys)}')
    print(f'Encrypted DB:\t{get_size(database.encrypted_templates)}')
    print(f' per person:\t{format_size(get_size(database.encrypted_templates, format=1)/persons)}')
    print(f' per person:\t{format_size(get_size(database.encrypted_templates, format=1)/ciphers)}')
    print(splitter)


if __name__ == '__main__':
    # Initialise
    n = 512
    s = 4096  # 1024, 2048, 4096
    print(f'\nn: {n}\ts: {s}\tBASELINE')

    t0 = time.time()
    AS = AuthenticationServer(features=512, slots=s)
    database = Database(AS.setup_database())  # remember to load DB
    client = Client(AS.setup_client())
    t1 = time.time()

    # Load db, reduce features, convert to integers
    db = []
    path = f'/Users/jonasolafsson/Documents/speciale/biometrics.nosync/small/feretint{n}/'

    for i in range(512):
        db.append(np.loadtxt(f'{path}{i}.txt').astype(int))
    probe = np.loadtxt(f'{path}999.txt').astype(int)
    AS.templates = 512

    # Load reference templates into database
    t2 = time.time()
    database.set_encrypted_templates(client.enroll_db(db))
    t3 = time.time()


    # Identificatioin x1
    enc_probe = client.encrypt_probe(probe)
    enc_dists = database.identify(enc_probe)
    result = AS.decrypt(enc_dists)
    t4 = time.time()
    plaindist = np.sum(np.square(np.array(db[418]) - np.array(probe)))
    print(f'Identification:\t{int((t4-t3)*1000)} ms')
    #print(f'Real identity: \t418\n ptxt distance:\t{plaindist}\nIdentified:\t{result[0]}\n enc distance:\t{result[1]}')

    #print_result()
