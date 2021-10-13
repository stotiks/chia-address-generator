import progressbar
import itertools
import time

from multiprocessing import Process, Lock
from multiprocessing.sharedctypes import Value, Array

from typing import List, Optional, Tuple
from base.util.byte_types import hexstr_to_bytes
from base.consensus.coinbase import create_puzzlehash_for_pk
from base.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from words.mnemonic import generate_mnemonic, mnemonic_to_seed
from blspy import G1Element, PrivateKey, G2Element, AugSchemeMPL

prefix = 'xcc'

if prefix == 'xcc':
    port = 9699
else:
    port = 8444

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


words = {"777","222","333","444","555","666","888","999","000"}
def check_address(address):
    for word in words:
        if address.endswith(word):
            return True
    return False

def find_address(lock):
    max_i = 100
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
                    print("-------------------------")
                    print(mnemonic)
                    print(address)
                    print(i)
                finally:
                    lock.release()            


if __name__ == "__main__":

    process_count = 8

    lock = Lock()

    pool = [Process(target=find_address,  args=(lock,)) for _ in range(process_count)]

    for p in pool:
        p.start()