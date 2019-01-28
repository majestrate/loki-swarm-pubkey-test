import random

import sys

# python3 compat
if sys.version_info > (3,):
    long = int



UINT64_MAX = 2**64 - 1
MERSENNE_TWISTER_64_BITS = 64
#  Python uses the Mersenne Twister as the core generator.
#  It produces 53-bit precision floats and has a period of 2**19937-1.
def mersenne_twister(num_bits=MERSENNE_TWISTER_64_BITS):
    return random.getrandbits(num_bits)

def uniform_distribution_portable(mt, n, num_bits):
    mersenne_twister_max = 2**MERSENNE_TWISTER_64_BITS - 1
    secureMax = mersenne_twister_max - mersenne_twister_max % n
    while True:
        x = mt(num_bits)
        if x < secureMax:
            break
    return  x / (secureMax / n)

def get_new_swarm_id(mt, existing_swarm_ids, num_bits=MERSENNE_TWISTER_64_BITS):
    new_id = -1
    while new_id == -1 or new_id in existing_swarm_ids:
        new_id = uniform_distribution_portable(mt, UINT64_MAX, num_bits)
    return long(new_id)

def num_bits_for_integer(i):
    num_bits = 1
    while i > (2**num_bits - 1):
        num_bits += 1
    return num_bits


def generate_equi_swarm_id(swarm_ids, num_bits):
    value_max = 2**num_bits - 1
    new_swarm_length = len(swarm_ids) + 1
    equi_distance = float(value_max) / (2**num_bits_for_integer(new_swarm_length))
    prev_id = 0
    index = 0
    for i in range(len(swarm_ids)):
        id = swarm_ids[i]
        distance = id - prev_id
        if (distance > (equi_distance + 1)):
            index = i
            break
        if i == (len(swarm_ids) - 1):
            index = i + 1
            break
        prev_id = id
    new_id = (index + 1) * equi_distance
    new_swarm_ids = swarm_ids[:]
    new_swarm_ids.insert(index, int(new_id))
    return new_swarm_ids

def generate_swarm_ids(n, swarm_ids, num_bits, method, sort=False):

    for _ in range(n):
        if method == 'mersenne-twister':
            new_swarm_id = get_new_swarm_id(mersenne_twister, swarm_ids, num_bits)
            swarm_ids.append(new_swarm_id)
        elif method == 'uniform':
            swarm_ids = generate_equi_swarm_id(swarm_ids, num_bits)
    if sort:
        swarm_ids = sorted(swarm_ids)
    return swarm_ids
