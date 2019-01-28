import sys
import os
import math
import struct
import hashlib

import ed25519
from scipy.spatial import distance as scipy_distance
from scipy.stats import norm
import matplotlib.pyplot as plt
import numpy as np

from swarms import generate_swarm_ids

# python3 compat
if sys.version_info > (3,):
    long = int


NUM_SWARMS = 31
NUM_PUBKEYS = 10000
EUCLIDIAN_DISTANCE_REDUCE_PUBKEY_TO_SWARM_ID = True
pubkeys_filename = 'pubkeys.txt'

def generate_messenger_pubkeys(n):
    pubkeys = []
    for i in range(n):
        pct = math.ceil(i * 100 / n)
        sys.stdout.write("\rGenerating pubkey: %i%% " % pct)
        sys.stdout.flush()
        _, verifying_key = ed25519.create_keypair()
        pubkeys.append(verifying_key.to_ascii(encoding="hex").decode('ascii'))
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

def hamming_distance_hash256(pubkey, swarm_id):
    # pub key hex string (32 bytes => 64 chars)
    pubkey_hex_string = hashlib.sha256(pubkey).hexdigest()
    # pubkey as a long int
    pubkey_long = long(pubkey_hex_string, 16)
    # pubkey as a string of 1 and 0's
    pubkey_binary_string = bin(pubkey_long)[2:].zfill(32 * 8)
    # swarm id as a string of 1 and 0's (duplicate 4 times for a total length of 256 chars)
    hash_hex = hashlib.sha256(bytes(swarm_id)).hexdigest()
    hash_long = long(hash_hex, 16)
    swarm_binary_string = "{0:0{1}b}".format(hash_long, 256)
    assert(len(swarm_binary_string) == 8 * 32)
    assert(len(pubkey_binary_string) == 8 * 32)
    # string of 1 and 0's to array of '1' and '0'
    pubkey_array_binary = list(pubkey_binary_string)
    swarm_array_binary = list(swarm_binary_string)
    distance = scipy_distance.hamming(pubkey_array_binary, swarm_array_binary)
    return distance

def hamming_distance_hash256_nopubkeyhash(pubkey, swarm_id):
    # pub key hex string (32 bytes => 64 chars)
    pubkey_hex_string = pubkey
    # pubkey as a long int
    pubkey_long = long(pubkey_hex_string, 16)
    # pubkey as a string of 1 and 0's
    pubkey_binary_string = bin(pubkey_long)[2:].zfill(32 * 8)
    # swarm id as a string of 1 and 0's (duplicate 4 times for a total length of 256 chars)
    hash_hex = hashlib.sha256(bytes(swarm_id)).hexdigest()
    hash_long = long(hash_hex, 16)
    swarm_binary_string = "{0:0{1}b}".format(hash_long, 256)
    assert(len(swarm_binary_string) == 8 * 32)
    assert(len(pubkey_binary_string) == 8 * 32)
    # string of 1 and 0's to array of '1' and '0'
    pubkey_array_binary = list(pubkey_binary_string)
    swarm_array_binary = list(swarm_binary_string)
    distance = scipy_distance.hamming(pubkey_array_binary, swarm_array_binary)
    return distance

def hamming_distance16(pubkey, swarm_id):
    pubkey_hex = hashlib.sha256(pubkey).hexdigest()[:4]
    pubkey_long = long(pubkey_hex, 16)
    # pubkey as a string of 1 and 0's
    pubkey_binary_string = bin(pubkey_long)[2:].zfill(16)
    # swarm id as a string of 1 and 0's
    #swarm_binary_string = "{0:0{1}b}".format(swarm_id, 16)
    swarm_id_hex = hashlib.sha256(bytes(swarm_id)).hexdigest()[:4]
    swarm_id_long = long(swarm_id_hex, 16)
    # pubkey as a string of 1 and 0's
    swarm_binary_string = bin(swarm_id_long)[2:].zfill(16)
    assert(len(swarm_binary_string) == 16)
    assert(len(pubkey_binary_string) == 16)
    # string of 1 and 0's to array of '1' and '0'
    pubkey_array_binary = list(pubkey_binary_string)
    swarm_array_binary = list(swarm_binary_string)
    distance = scipy_distance.hamming(pubkey_array_binary, swarm_array_binary)
    return distance

def euclidian_distance(pubkey, swarm_id):
    pubkey_hex_string = pubkey
    if (EUCLIDIAN_DISTANCE_REDUCE_PUBKEY_TO_SWARM_ID):
        # pubkey_hex_array = list(pubkey_hex_string)
        # pubkey_8bytes_string = []
        # for i in range(4):
        #     pubkey_8bytes_string.append(''.join(pubkey_hex_array[i*16:i*16+16]))
        # pubkey_8bytes_long = [long(x, 16) for x in pubkey_8bytes_string]
        # pubkey_xor = reduce(lambda x, y: x ^ y, pubkey_8bytes_long, 0)
        pk = long(pubkey_hex_string[-4:], 16)
        return abs(pk - swarm_id)
    else:
        # pubkey_long is 256 bits (32 bytes)
        pubkey_hex_string = hashlib.sha256(pubkey).hexdigest()
        pubkey_long = long(pubkey_hex_string, 16)
        swarm_id_hex = hashlib.sha256(bytes(swarm_id)).hexdigest()
        swarm_id_long = long(swarm_id_hex, 16)
        return abs(pubkey_long - swarm_id_long)

def euclidian_distance_uniformswarm(pubkey, swarm_id):
    return euclidian_distance(pubkey, swarm_id)

def get_swarm_id_for_pubkey(pubkey, swarm_ids, distance_functions):
    num_outputs = len(distance_functions)
    # tuple (distance, id)
    closest_swarm = [(float("inf"), -1) for _ in range(num_outputs)]
    for swarm_id in swarm_ids:
        for (idx, distance_function) in enumerate(distance_functions):
            distance = distance_function(pubkey, swarm_id)
            if distance == closest_swarm[idx][0]:
                pubkey_long = long(pubkey, 16)
                swarm_id_long = long(hashlib.sha256(bytes(swarm_id)).hexdigest(), 16)
                swarm_id2_long = long(hashlib.sha256(bytes(closest_swarm[idx][1])).hexdigest(), 16)
                result = ((pubkey_long ^ swarm_id_long ^ swarm_id2_long) % 2) == 0
                if result:
                    closest_swarm[idx] = min(closest_swarm[idx], (distance, swarm_id))
                else:
                    closest_swarm[idx] = max(closest_swarm[idx], (distance, swarm_id))
            else:
                closest_swarm[idx] = min(closest_swarm[idx], (distance, swarm_id))
    return [x[1] for x in closest_swarm]

def assign_pubkey_to_swarm(pubkey, pubkey_index, swarm_ids, distance_functions, out_assignd_swarm_indexes, out_swarm_buckets):
    assigned_swarms = get_swarm_id_for_pubkey(pubkey, swarm_ids, distance_functions)
    for (idx, swarm_id) in enumerate(assigned_swarms):
        swarm_index = swarm_ids.index(swarm_id)
        out_assignd_swarm_indexes[idx][pubkey_index] = swarm_index
        out_swarm_buckets[idx][swarm_index].append(pubkey)

def assign_pubkeys_to_swarm(pubkeys, swarm_ids, distance_functions):
    output_dimensions = len(distance_functions)
    assigned_swarm_indexes = [[0] * len(pubkeys) for _ in range(output_dimensions)]
    swarms_buckets = [[[] for _ in range(len(swarm_ids))] for _ in range(output_dimensions)]
    n = len(pubkeys)
    for (idx, pubkey) in enumerate(pubkeys):
        pct = math.ceil(idx * 100 / n)
        sys.stdout.write("\rAssigning pubkeys: %i%% " % pct)
        sys.stdout.flush()
        assign_pubkey_to_swarm(pubkey, idx, swarm_ids, distance_functions, assigned_swarm_indexes, swarms_buckets)
    return (swarms_buckets, assigned_swarm_indexes)

def print_buckets(title, bucket_sizes):
    unique_with_counts = np.unique(bucket_sizes, return_counts=True)
    mu, std = norm.fit(bucket_sizes)
    print('##### %s #####' % title)
    print('# mu: %s' % mu)
    print('# std: %s' % std)
    print('# min: %s' % min(unique_with_counts[0]))
    print('# max: %s' % max(unique_with_counts[0]))
    # print(' # ------------')
    # print(' # Swarm usage')
    # print('#\tindex\tcount\tx\t[fill]\t(%)')
    # for i in range(len(unique_with_counts[0])):
    #     num_pubkeys = unique_with_counts[0][i]
    #     print ('#\t%s: \t%s\tx\t[%s]\t(%s)' % (i, unique_with_counts[1][i], num_pubkeys, num_pubkeys * 100 / NUM_PUBKEYS))

def plot(assigned_swarm_indexes, swarms_buckets, distance_functions):
    titles = [x.__name__ for x in distance_functions]
    max_x = 0
    min_x = 10000
    ax = []
    n = len(distance_functions)
    for i in range(n):
        ax1 = plt.subplot(2, n, i * n + 1)
        total = len(np.trim_zeros(assigned_swarm_indexes[i]))
        ax1.hist(assigned_swarm_indexes[i], bins=NUM_SWARMS, histtype='bar', alpha=0.2)
        ax1.set_title('%s - histogram' % titles[i])
        ax2 = plt.subplot(2, n, i * n + 2)
        swarm_bucket_sizes = map(lambda pubkeys_array: len(pubkeys_array), swarms_buckets[i])
        h = sorted(swarm_bucket_sizes)
        bins = max(h) - min(h)
        ax2.hist(h, density=True, bins=10)
        ax2.set_title('%s - distribution' % titles[i])
        x0, x1 = ax2.get_xlim()
        max_x = max(max_x, x1)
        min_x = min(min_x, x0)
        # fit normal distribution
        mu, std = norm.fit(h)
        xmin, xmax = plt.xlim()
        x = np.linspace(xmin, xmax, 100)
        p = norm.pdf(x, mu, std)
        ax2.plot(x, p, 'k', linewidth=2)
        print_buckets(titles[i], h)
        ax.append([ax1, ax2])
    for i in range(n):
        ax[i][1].set_xlim((min_x, max_x))
    plt.show()

def load_pubkeys(pubkeys_filename):
    with open(pubkeys_filename, 'r') as f:
        pubkeys = f.read().splitlines()
    return pubkeys

def save_pubkeys(pubkeys_filename, pubkeys):
    with open(pubkeys_filename, 'w') as f:
        f.writelines('\n'.join(pubkeys))

def main():
    distance_functions = [euclidian_distance, hamming_distance_hash256]
    # generate initial swarm ids and pubkeys
    swarm_ids = generate_swarm_ids(NUM_SWARMS, swarm_ids=[], num_bits=64, method='mersenne-twister')
    if os.path.isfile(pubkeys_filename):
        pubkeys = load_pubkeys(pubkeys_filename)
    else:
        pubkeys = generate_messenger_pubkeys(NUM_PUBKEYS)
        save_pubkeys(pubkeys_filename, pubkeys)
    # assign pubkeys
    (swarms_buckets_before, assigned_swarm_indexes_before) = assign_pubkeys_to_swarm(pubkeys, swarm_ids, distance_functions)
    plot(assigned_swarm_indexes_before, swarms_buckets_before, distance_functions)
    # return
    # add one swarm id
    swarm_ids = generate_swarm_ids(1, swarm_ids, num_bits=64, method='mersenne-twister')
    # reassign
    (swarms_buckets_after, assigned_swarm_indexes_after) = assign_pubkeys_to_swarm(pubkeys, swarm_ids, distance_functions)
    for i in range(len(distance_functions)):
        diff = []
        swarm_losing = []
        swarm_winning = []
        for j in range(len(assigned_swarm_indexes_before[i])):
            if not assigned_swarm_indexes_before[i][j] == assigned_swarm_indexes_after[i][j]:
                diff.append(j)
                swarm_losing.append(assigned_swarm_indexes_before[i][j])
                swarm_winning.append(assigned_swarm_indexes_after[i][j])
        print('# Adding 1 swarm for %s' % distance_functions[i].__name__)
        print('# new swarm got %s pubkeys assigned' % len(swarms_buckets_after[i][-1]))
        print('# %s pubkeys assigned to a different swarm' % len(diff))
        print('# %s swarms lost pubkeys' % len(set(swarm_losing)))
        print('# %s swarms won pubkeys' % len(set(swarm_winning)))

def main2():
    # generate initial swarm ids and pubkeys
    if os.path.isfile(pubkeys_filename):
        pubkeys = load_pubkeys(pubkeys_filename)[:NUM_PUBKEYS]
    else:
        pubkeys = generate_messenger_pubkeys(NUM_PUBKEYS)
        save_pubkeys(pubkeys_filename, pubkeys)
    # assign pubkeys
    functions = [euclidian_distance, euclidian_distance_uniformswarm]
    swarm_ids1 = generate_swarm_ids(NUM_SWARMS, swarm_ids=[], num_bits=16, method='mersenne-twister', sort=True)
    (a0, a1) = assign_pubkeys_to_swarm(pubkeys, swarm_ids1, [functions[0]])
    swarm_ids2 = generate_swarm_ids(NUM_SWARMS, swarm_ids=[], num_bits=16, method='uniform', sort=False)
    (b0, b1) = assign_pubkeys_to_swarm(pubkeys, swarm_ids2, [functions[1]])
    plot([a1[0], b1[0]], [a0[0], b0[0]], functions)
    # add one swarm id
    # swarm_ids = generate_swarm_ids(1, swarm_ids)
    # # reassign
    # (swarms_buckets_after, assigned_swarm_indexes_after) = assign_pubkeys_to_swarm(pubkeys, swarm_ids, distance_functions)
    # for i in range(len(distance_functions)):
    #     diff = []
    #     swarm_losing = []
    #     swarm_winning = []
    #     for j in range(len(assigned_swarm_indexes_before[i])):
    #         if not assigned_swarm_indexes_before[i][j] == assigned_swarm_indexes_after[i][j]:
    #             diff.append(j)
    #             swarm_losing.append(assigned_swarm_indexes_before[i][j])
    #             swarm_winning.append(assigned_swarm_indexes_after[i][j])
    #     print('# Adding 1 swarm for %s' % distance_functions[i].__name__)
    #     print('# new swarm got %s pubkeys assigned' % len(swarms_buckets_after[i][-1]))
    #     print('# %s pubkeys assigned to a different swarm' % len(diff))
    #     print('# %s swarms lost pubkeys' % len(set(swarm_losing)))
    #     print('# %s swarms won pubkeys' % len(set(swarm_winning)))
# n     =>index value   => array
# n     => i    x/y
# 1     => 0    1/2     => [1/2]
# 2     => 0    1/4     => [1/4, 2/4]
# 3     => 2    3/4     => [1/4, 2/4, 3/4]
# 4     => 0    1/8     => [1/8, 2/8, 4/8, 6/8]
# 5     => 2    3/8     => [1/8, 2/8, 3/8, 4/8, 6/8]
# 6     => 4    5/8     => [1/8, 2/8, 3/8, 4/8, 5/8, 6/8]
# 7     => 6    7/8     => [1/8, 2/8, 3/8, 4/8, 5/8, 6/8, 7/8]
# 8     => 0    1/16    => [1/16, 2/16, 4/16, 6/16, 8/16, 10/16, 12/16, 14/16]
# 9     => 2    3/16    => [1/16, 2/16, 3/16, 4/16, 6/16, 8/16, 10/16, 12/16, 14/16]
# 10    => 4    5/16    => [1/16, 2/16, 3/16, 4/16, 5/16, 6/16, 8/16, 10/16, 12/16, 14/16]
# 11    => 6    7/16    => [1/16, 2/16, 3/16, 4/16, 5/16, 6/16, 7/16, 8/16, 10/16, 12/16, 14/16]
# 12    => 8    9/16    => [1/16, 2/16, 3/16, 4/16, 5/16, 6/16, 7/16, 8/16, 9/16, 10/16, 12/16, 14/16]
# 13    => 10    11/16   => [1/16, 2/16, 3/16, 4/16, 5/16, 6/16, 7/16, 8/16, 9/16, 10/16, 11/16, 12/16, 14/16]
# 14    => 12    13/16   => [1/16, 2/16, 3/16, 4/16, 5/16, 6/16, 7/16, 8/16, 9/16, 10/16, 11/16, 12/16, 13/16, 14/16]

# y = 2**p where p is the number of bits to represent n
# i = 
# x = i + 1


def main3():
    swarm_ids = generate_swarm_ids(31, [], num_bits=16, method='uniform')
    distances = set()
    for i in range(1, len(swarm_ids)):
        distances.add(swarm_ids[i] - swarm_ids[i - 1])
    print(distances)
    m = max(swarm_ids)
    print(2**16 -1 -m)


main2()
