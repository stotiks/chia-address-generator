import progressbar
import json
import sys
import multiprocessing

from multiprocessing import Process, Lock

from typing import List, Optional, Tuple
from base.util.byte_types import hexstr_to_bytes
from base.consensus.coinbase import create_puzzlehash_for_pk
from base.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from words.mnemonic import generate_mnemonic, mnemonic_to_seed, bip39_word_list
from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL

def create_address_by_pk(pk: str) -> str:
    return encode_puzzle_hash(
        create_puzzlehash_for_pk(
            G1Element.from_bytes(hexstr_to_bytes(pk))
        ),
        address_prefix
    )

def pk2_puzzle_hash(pk: str) -> str:
    return create_puzzlehash_for_pk(
        G1Element.from_bytes(hexstr_to_bytes(pk))
    ).hex()

def puzzle_hash_2address(puzzle_hash: str) -> str:
    return encode_puzzle_hash(
        hexstr_to_bytes(puzzle_hash),
        address_prefix
    )

def address2_puzzle_hash(xch_address: str) -> str:
    return decode_puzzle_hash(xch_address).hex()


def _derive_path(sk: PrivateKey, path: List[int]) -> PrivateKey:
    for index in path:
        sk = AugSchemeMPL.derive_child_sk(sk, index)
    return sk

def master_sk_to_farmer_sk(master: PrivateKey) -> PrivateKey:
    return _derive_path(master, [12381, port, 0, 0])


def master_sk_to_pool_sk(master: PrivateKey) -> PrivateKey:
    return _derive_path(master, [12381, port, 1, 0])


def master_sk_to_wallet_sk(master: PrivateKey, index: int) -> PrivateKey:
    return _derive_path(master, [12381, port, 2, index])


def master_sk_to_local_sk(master: PrivateKey) -> PrivateKey:
    return _derive_path(master, [12381, port, 3, 0])


def master_sk_to_backup_sk(master: PrivateKey) -> PrivateKey:
    return _derive_path(master, [12381, port, 4, 0])


def get_public_key(private_key, index: int) -> G1Element:
    return master_sk_to_wallet_sk(private_key, index).get_g1()

def get_address(sk, index: int = 0):
    address = encode_puzzle_hash(create_puzzlehash_for_pk(master_sk_to_wallet_sk(sk, int(index)).get_g1()), prefix)
    return address

def print_header(sk):
    print("\n")
    #print(key)
    print("Fingerprint:", sk.get_g1().get_fingerprint())
    print("Master public key (m):", sk.get_g1())
    print(
        "Farmer public key (m/12381/port/0/0):",
        master_sk_to_farmer_sk(sk).get_g1(),
    )
    print("Pool public key (m/12381/port/1/0):", master_sk_to_pool_sk(sk).get_g1())
    print(
        "First wallet address:",
        encode_puzzle_hash(create_puzzlehash_for_pk(master_sk_to_wallet_sk(sk, int(0)).get_g1()), prefix),
    )
    print("\n")

config_f = open('config.json',)
params = json.load(config_f)


prefix = params["prefix"]
mnemonic = params["mnemonic"]
s_address = params["address"]
max_i = params["max_i"]


if prefix == 'xcc':
    port = 9699
elif prefix == 'xch':
    port = 8444
else:
    print("Uncorrect prefix")
    quit()


def check_address(address):
    for word in words:
        if address.endswith(word):
            return True
    return False

def find_address(lock):
    while True:
        mnemonic = generate_mnemonic()
        seed = mnemonic_to_seed(mnemonic, "")
        key = AugSchemeMPL.key_gen(seed)
        #print_header(key)

        for i in range(max_i):
            address = get_address(key,i)
            #print(address)
            if check_address(address):
                lock.acquire()
                try:
                    result = """-------------------------
Fingerprint: {3}                    
Mnemonic: {0}
Address [{2}]: {1}
""".format(mnemonic, address, i, key.get_g1().get_fingerprint() )

                    print(result)
                    
                    f = open("results.txt", "a")
                    f.write(result)
                    f.close()

                finally:
                    lock.release()            


if __name__ == "__main__":

    #mnemonic = generate_mnemonic();    
    #print(mnemonic)

    seed = mnemonic_to_seed(mnemonic, "")
    key = AugSchemeMPL.key_gen(seed)
    print_header(key)


    userMnemonic = mnemonic
    keyWordList=bip39_word_list().splitlines()
    for index in range(len(keyWordList)):
        testWord=keyWordList[index]
        print(str(index)+"/"+str(len(keyWordList))+" "+testWord)

        testMne = userMnemonic.replace("?",testWord)
        seed=mnemonic_to_seed(testMne,"")
        key=AugSchemeMPL.key_gen(seed)

        for i in range(max_i):
            address = get_address(key,i)
            if(address == s_address):
                print(print("the result is:"+testWord))
                quit()
            
