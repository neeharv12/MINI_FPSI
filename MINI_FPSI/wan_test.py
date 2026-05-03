#!/usr/bin/python3
import os
import time
import random

Ts = [8, 16]
ELLs = [16, 32]
Ks = [2, 4, 6]
SCHEMES = ["iknp", "softspoken", "silent"]
NUM_ELEMENTS_LIST = [128, 512, 1024, 4096]

ADDR_R = "127.0.0.1:1212"
ADDR_S = "127.0.0.1:1213"

A_FILE = "inputs/A.txt"
B_FILE = "inputs/B.txt"


def random_bitstring(length):
    return ''.join(random.choice('01') for _ in range(length))


def generate_inputs(n, l):
    os.makedirs("inputs", exist_ok=True)

    # completely random A and B (no forced overlap)
    A = [random_bitstring(l) for _ in range(n)]
    B = [random_bitstring(l) for _ in range(n)]

    with open(A_FILE, "w") as f:
        f.write("\n".join(A))

    with open(B_FILE, "w") as f:
        f.write("\n".join(B))


if __name__ == "__main__":
    os.makedirs("wan_output", exist_ok=True)

    for n in NUM_ELEMENTS_LIST:
        for l in ELLs:
            for t in Ts:
                for scheme in SCHEMES:
                    ks_to_try = Ks if scheme == "softspoken" else [None]
                    for k in ks_to_try:
                        if k is None:
                            label = f"{scheme}.{n}.{l}.{t}"
                            print(f"\nRunning scheme={scheme}, n={n}, l={l}, t={t}")
                        else:
                            label = f"{scheme}.{n}.{l}.{t}.k{k}"
                            print(f"\nRunning scheme={scheme}, n={n}, l={l}, t={t}, k={k}")
                        generate_inputs(n, l)
                        out_file = f"wan_output/{label}.txt"
                        k_arg = f"--k {k} " if k is not None else ""
                        recv_cmd = (
                            f"./build/Bob "
                            f"--addr {ADDR_R} "
                            f"--b {B_FILE} "
                            f"--ot {scheme} "
                            f"--l {l} --t {t} "
                            f"{k_arg}"
                            f"--threads {16} "
                            f"> {out_file} 2>&1 &"
                        )

                        send_cmd = (
                            f"./build/Alice "
                            f"--addr {ADDR_S} "
                            f"--a {A_FILE} "
                            f"--ot {scheme} "
                            f"--l {l} --t {t} "
                            f"{k_arg}"
                            f"--threads {16} "
                            f">> {out_file} 2>&1"
                        )
                        os.system(recv_cmd)
                        time.sleep(0.5)
                        os.system(send_cmd)
                        time.sleep(1) 