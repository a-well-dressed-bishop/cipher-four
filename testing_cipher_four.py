from basic_spn import cipher_four


def get_vec_keys(rounds=5):
    return [vector(GF(2), ZZ(0x1).digits(2)) for i in range(rounds + 1)]


def correctness(enc, dec, P, K):

    res = dec(enc(P, K), K)

    # for ease of evaluation, I suppose
    if not isinstance(res, (int, Integer)):
        res = ZZ(list(res), 2)

    if not isinstance(P, (int, Integer)):
        P = ZZ(list(P), 2)

    return P == res


# ---------------------------------- Default --------------------------------- #
enc = cipher_four().encrypt
dec = cipher_four().decrypt

# ---------------------------- Change # of rounds ---------------------------- #
enc_r6 = cipher_four(rounds=6).encrypt
dec_r6 = cipher_four(rounds=6).decrypt

# ------------------------------- Vector output ------------------------------ #
enc_vec = cipher_four(vector_output=True).encrypt
dec_vec = cipher_four(vector_output=True).decrypt

# ------------------------------- Integer input ------------------------------ #
P = 0xffff
K_5 = [0x1 for _ in range(6)]
K_6 = [0x1 for _ in range(7)]

# ------------------------------- Vector input ------------------------------- #
P_vec = vector(GF(2), ZZ(0xffff).digits(2))
K_vec_5 = get_vec_keys()
K_vec_6 = get_vec_keys(6)

# ------------------------------ Sequence input ------------------------------ #
K_seq = Sequence(range(6), use_sage_types=True)


# ================================== TESTS =================================== #

# ------------------------------ Defaults ------------------------------------ #
c1 = correctness(enc, dec, P, K_5)
c2 = correctness(enc, dec, P_vec, K_5)
c3 = correctness(enc, dec, P, K_vec_5)
c4 = correctness(enc, dec, P_vec, K_vec_5)
c5 = correctness(enc, dec, P, K_5)
c6 = correctness(enc, dec, P, K_seq)

checks = [eval(f"c{i}") for i in range(1, 7)]
print(checks)

# ----------------------------- Increasing rounds ---------------------------- #
c1 = correctness(enc_r6, dec_r6, P, K_6)
c2 = correctness(enc_r6, dec_r6, P_vec, K_6)
c3 = correctness(enc_r6, dec_r6, P, K_vec_6)
c4 = correctness(enc_r6, dec_r6, P_vec, K_vec_6)
c5 = correctness(enc_r6, dec_r6, P, K_6)

checks = [eval(f"c{i}") for i in range(1, 6)]
print(checks)

# ------------------------------- Vector output ------------------------------ #
c1 = correctness(enc_vec, dec_vec, P, K_5)
c2 = correctness(enc_vec, dec_vec, P_vec, K_5)
c3 = correctness(enc_vec, dec_vec, P, K_vec_5)
c4 = correctness(enc_vec, dec_vec, P_vec, K_vec_5)
c5 = correctness(enc_vec, dec_vec, P, K_5)
c6 = correctness(enc_vec, dec, P, K_5)
c7 = correctness(enc, dec_vec, P, K_5)

checks = [eval(f"c{i}") for i in range(1, 8)]
print(checks)