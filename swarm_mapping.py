import math
import struct
import binascii

import ed25519
from scipy.spatial import distance as scipy_distance
from scipy.stats import norm
import matplotlib.pyplot as plt
import numpy as np

from swarms import generate_swarm_ids

NUM_SWARMS = 35
NUM_PUBKEYS = 10000
EUCLIDIAN_DISTANCE_REDUCE_PUBKEY_TO_8BYTES = True

def generate_messenger_pubkeys(n):
    pubkeys = []
    for _ in range(n):
        _, verifying_key = ed25519.create_keypair()
        pubkeys.append(verifying_key.to_ascii(encoding="hex"))
    return pubkeys

def hamming_distance(pubkey, swarm_id):
    # pub key hex string (32 bytes => 64 chars)
    pubkey_hex_string = pubkey
    # pubkey as a long int
    pubkey_long = long(pubkey_hex_string, 16)
    # pubkey as a string of 1 and 0's
    pubkey_binary_string = bin(pubkey_long)[2:].zfill(32 * 8)
    # swarm id as a string of 1 and 0's (duplicate 4 times for a total length of 256 chars)
    swarm_binary_string = "{0:0{1}b}".format(swarm_id, 64) * 4
    assert(len(swarm_binary_string) == 8 * 32)
    assert(len(pubkey_binary_string) == 8 * 32)
    # string of 1 and 0's to array of '1' and '0'
    pubkey_array_binary = list(pubkey_binary_string)
    swarm_array_binary = list(swarm_binary_string)
    distance = scipy_distance.hamming(pubkey_array_binary, swarm_array_binary)
    return distance

def euclidian_distance(pubkey, swarm_id):
    pubkey_hex_string = pubkey
    if (EUCLIDIAN_DISTANCE_REDUCE_PUBKEY_TO_8BYTES):
        pubkey_hex_array = list(pubkey_hex_string)
        pubkey_8bytes_string = []
        for i in range(4):
            pubkey_8bytes_string.append(''.join(pubkey_hex_array[i*16:i*16+16]))
        pubkey_8bytes_long = [long(x, 16) for x in pubkey_8bytes_string]
        pubkey_xor = reduce(lambda x, y: x ^ y, pubkey_8bytes_long, 0)
        return abs(pubkey_xor - swarm_id)
    else:
        # pubkey_long is 256 bits (32 bytes)
        pubkey_long = long(pubkey_hex_string, 16)
        swarm_32bytes = swarm_id
        swarm_32bytes += swarm_id << 64
        swarm_32bytes += swarm_id << 128
        swarm_32bytes += swarm_id << 192
        return abs(pubkey_long - swarm_32bytes)

def get_swarm_id_for_pubkey(pubkey, swarm_ids, distance_functions):
    num_outputs = len(distance_functions)
    # tuple (distance, id)
    closest_swarm = [(float("inf"), -1) for _ in range(num_outputs)]
    for swarm_id in swarm_ids:
        for (idx, distance_function) in enumerate(distance_functions):
            distance = distance_function(pubkey, swarm_id)
            closest_swarm[idx] = min(closest_swarm[idx], (distance, swarm_id))
    return [x[1] for x in closest_swarm]

def assign_pubkey_to_swarm(pubkey, pubkey_index, swarm_ids, distance_functions, out_assignd_swarm_indexes, out_swarm_buckets):
    assigned_swarms = get_swarm_id_for_pubkey(pubkey, swarm_ids, distance_functions)
    for (idx, swarm_id) in enumerate(assigned_swarms):
        swarm_index = swarm_ids.index(swarm_id)
        out_assignd_swarm_indexes[idx][pubkey_index] = swarm_index
        out_swarm_buckets[idx][swarm_index].append(pubkey)

def plot(assigned_swarm_indexes, swarms_buckets):
    titles = ['hamming', '1d euclidian']
    for i in range(2):
        ax1 = plt.subplot(2, 2, i*2 + 1)
        total = len(np.trim_zeros(assigned_swarm_indexes[i]))
        print('total assigned: %s' % total)
        ax1.hist(assigned_swarm_indexes[i], bins=NUM_SWARMS, histtype='bar', alpha=0.2)
        ax2 = plt.subplot(2, 2, i*2+2)
        swarm_bucket_sizes = map(lambda pubkeys_array: len(pubkeys_array), swarms_buckets[i])
        h = sorted(swarm_bucket_sizes)
        bins = max(h) - min(h)
        ax2.hist(h, density=True, bins=bins)
        # fit normal distribution
        mu, std = norm.fit(h)
        xmin, xmax = plt.xlim()
        x = np.linspace(xmin, xmax, 100)
        p = norm.pdf(x, mu, std)
        ax2.plot(x, p, 'k', linewidth=2)
        print(np.unique(h, return_counts=True))
    plt.show()

def main():
    swarm_ids = generate_swarm_ids(NUM_SWARMS)
    pubkeys = generate_messenger_pubkeys(NUM_PUBKEYS)
    distance_functions = [hamming_distance, euclidian_distance]
    output_dimensions = len(distance_functions)
    assigned_swarm_indexes = [[0] * NUM_PUBKEYS for _ in range(output_dimensions)]
    swarms_buckets = [[[] for _ in range(NUM_SWARMS)] for _ in range(output_dimensions)]
    for (idx, pubkey) in enumerate(pubkeys):
        assign_pubkey_to_swarm(pubkey, idx, swarm_ids, distance_functions, assigned_swarm_indexes, swarms_buckets)

    plot(assigned_swarm_indexes, swarms_buckets)

main()