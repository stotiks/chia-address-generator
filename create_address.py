import progressbar
import json
import sys
import re
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
       

if __name__ == "__main__":

    keyWordList=bip39_word_list().splitlines()

    mnemonic_words = mnemonic.strip().split()

    posible_words = [0 for i in range(len(mnemonic_words))] 

    for index in range(len(mnemonic_words)):
        word = mnemonic_words[index]

        posible_words[index] = []

        r = re.compile(word)
        newlist = list(filter(r.match, keyWordList))
        posible_words[index] = newlist

        print("{} {}".format(index+1, posible_words[index]))

    posible_mnemonics_count = 1;
    for words in posible_words:
        #print(words)
        posible_mnemonics_count *= len(words)

    print("Posible Mnemonics: " + str(posible_mnemonics_count))

    bar = progressbar.ProgressBar(max_value=posible_mnemonics_count, redirect_stdout=True)

    for i in range(posible_mnemonics_count):
        bar.update(i)
        test_mnemonic_arr = []
        for index in range(len(mnemonic_words)):
            c = i % len(posible_words[index])        
            i = (i - c) // len(posible_words[index])
            test_mnemonic_arr.append(posible_words[index][c])
            #print(c)

        test_mnemonic = " ".join(test_mnemonic_arr)
        #print(test_mnemonic)

        seed=mnemonic_to_seed(test_mnemonic,"")
        key=AugSchemeMPL.key_gen(seed)

        for ii in range(max_i):
            address = get_address(key,ii)
            if(address == s_address):
                print("---------------------------------")
                print(test_mnemonic)
                print("---------------------------------")
                sys.exit()

    print("Not found :(")
