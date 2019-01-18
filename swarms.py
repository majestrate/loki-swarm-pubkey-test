import random

UINT64_MAX = 2**64 - 1
MERSENNE_TWISTER_BITS = 64
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