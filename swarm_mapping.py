import random
import math
import struct
import binascii

import ed25519
from scipy.spatial import distance as scipy_distance
from scipy.stats import norm
import matplotlib.pyplot as plt
import numpy as np

UINT64_MAX = 2**64 - 1
NUM_SWARMS = 35
MERSENNE_TWISTER_BITS = 64
NUM_PUBKEYS = 10000

#  Python uses the Mersenne Twister as the core generator.
#  It produces 53-bit precision floats and has a period of 2**19937-1.
def mersenne_twister():
    return random.getrandbits(MERSENNE_TWISTER_BITS)

def uniform_distribution_portable(mt, n):
    mersenne_twister_max = 2**MERSENNE_TWISTER_BITS - 1
    secureMax = mersenne_twister_max - mersenne_twister_max % n
    while True:
        x = mt()
        if x < secureMax:
            break
    return  x / (secureMax / n)

def get_new_swarm_id(mt, ids):
    new_id = -1
    while new_id == -1 or new_id in ids:
        new_id = uniform_distribution_portable(mt, UINT64_MAX)
    return long(new_id)

def generate_swarm_ids(n):
    swarm_ids = []
    for _ in range(n):
        new_swarm_id = get_new_swarm_id(mersenne_twister, swarm_ids)
        swarm_ids.append(new_swarm_id)
    return swarm_ids

def generate_messenger_pubkeys(n):
    pubkeys = []
    for _ in range(n):
        _, verifying_key = ed25519.create_keypair()
        pubkeys.append(verifying_key)
    return pubkeys

def get_distance(pubkey, swarm_id):
    pubkey_hex_string = pubkey.to_ascii(encoding="hex")
    pubkey_binary_string = bin(int(pubkey_hex_string, 16))[2:].zfill(32 * 8)
    swarm_binary_string = "{0:0{1}b}".format(swarm_id, 64) * 4 # 64 bits, repeated 4 times
    assert(len(swarm_binary_string) == 8 * 32)
    assert(len(pubkey_binary_string) == 8 * 32)
    pubkey_array_binary = list(pubkey_binary_string)
    swarm_array_binary = list(swarm_binary_string)
    distance = scipy_distance.hamming(pubkey_array_binary, swarm_array_binary)
    return distance

def get_swarm_id_for_pubkey(pubkey, swarm_ids):
    best = (1024, -1)
    for swarm_id in swarm_ids:
        distance = get_distance(pubkey, swarm_id)
        best = min(best, (distance, swarm_id))
    return best[1]

def main():
    swarm_ids = generate_swarm_ids(NUM_SWARMS)
    pubkeys = generate_messenger_pubkeys(NUM_PUBKEYS)
    assigned_swarm_indexes = [0] * NUM_PUBKEYS
    swarms_buckets = [0] * NUM_SWARMS
    for (idx, pubkey) in enumerate(pubkeys):
        swarm_id = get_swarm_id_for_pubkey(pubkey, swarm_ids)
        swarm_index = swarm_ids.index(swarm_id)
        assigned_swarm_indexes[idx] = (swarm_index)
        swarms_buckets[swarm_index] += 1

    ax1 = plt.subplot(2, 1, 1)
    total = len(np.trim_zeros(assigned_swarm_indexes))
    print('total assigned: %s' % total)
    ax1.hist(assigned_swarm_indexes, bins=NUM_SWARMS, histtype='bar', alpha=0.2)
    # fit
    ax2 = plt.subplot(2, 1, 2)
    h = sorted(swarms_buckets)
    r = max(h) - min(h)
    ax2.hist(h, density=True, bins=r)
    mu, std = norm.fit(h)
    xmin, xmax = plt.xlim()
    x = np.linspace(xmin, xmax, 100)
    p = norm.pdf(x, mu, std)
    ax2.plot(x, p, 'k', linewidth=2)
    print(np.unique(h, return_counts=True))
    plt.show()
main()