import hashlib
import os

def PRFmsg(seed, opt_rand, message):
    m = hashlib.sha256()
    m.update(seed)
    m.update(opt_rand)
    m.update(message)
    return m.digest()

def Hmsg(R, PK_seed, PK_root, M):
    m = hashlib.sha256()
    m.update(R)
    m.update(PK_seed)
    m.update(PK_root)
    m.update(M)
    return m.digest()

def FORS_sign(digest, SK_seed, ADRS):
    # Simplified FORS signature function
    m = hashlib.sha256()
    m.update(SK_seed)
    m.update(ADRS)
    m.update(digest)
    return m.digest()

def get_FORS_PK(SIGFORS, PK_seed, ADRS):
    # Simplified function for obtaining FORS public key
    m = hashlib.sha256()
    m.update(PK_seed)
    m.update(ADRS)
    m.update(SIGFORS)
    return m.digest()

def HT_sign(FORS_PK, SK_seed, ADRS):
    # Simplified hypertree signature function
    m = hashlib.sha256()
    m.update(SK_seed)
    m.update(ADRS)
    m.update(FORS_PK)
    return m.digest()

def slh_sign(M, SK):
    SK_seed, SK_prf, PK_seed, PK_root = SK
    ADRS = os.urandom(32)  # Randomly generated address
    opt_rand = PK_seed  # Set opt_rand to PK.seed

    # Generate randomizer
    R = PRFmsg(SK_prf, opt_rand, M)
    SIG = [R]

    # Compute message digest
    digest = Hmsg(R, PK_seed, PK_root, M)

    # Compute FORS signature
    SIGFORS = FORS_sign(digest, SK_seed, ADRS)
    SIG.append(SIGFORS)

    # Obtain corresponding FORS public key
    FORS_PK = get_FORS_PK(SIGFORS, PK_seed, ADRS)

    # Sign the FORS public key
    SIGHT = HT_sign(FORS_PK, SK_seed, ADRS)
    SIG.append(SIGHT)

    return SIG

# Example usage
SK_seed = os.urandom(32)
SK_prf = os.urandom(32)
PK_seed = os.urandom(32)
PK_root = os.urandom(32)
SK = (SK_seed, SK_prf, PK_seed, PK_root)
M = b"Olavo Borges"

# Generate SLH-DSA signature
signature = slh_sign(M, SK)
print("Message: ", M)
print("SK_seed: ", SK_seed)
print("SK_prf: ", SK_prf)
print("PK_seed: ", PK_seed)
print("PK_root: ", PK_root)
print("SK: ", SK)
print("SLH-DSA Signature: ", signature)

