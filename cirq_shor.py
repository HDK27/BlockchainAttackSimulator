# shor_ecdlp_fixed.py

import cirq
import numpy as np
from collections import Counter, defaultdict
from math import ceil, log2
import time

# =========================
# --- ECC PARAMETERS ---
# =========================
P = 37  # prime field
A = 2
B = 3
EC_G = (15, 2)  # base point
ORDER = 29     # order of G
O = None       # point at infinity

# --- ECC FUNCTIONS ---
def is_on_curve(Pt):
    if Pt is None:
        return True
    x, y = Pt
    return (y*y - (x**3 + A*x + B)) % P == 0

def inv_mod(k, p):
    """Modular inverse via pow (Fermat's little theorem)."""
    return pow(k, -1, p)

def point_add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    (x1, y1) = Pt
    (x2, y2) = Qt
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if Pt == Qt:
        m = (3*x1*x1 + A) * inv_mod(2*y1, P) % P
    else:
        m = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (m*m - x1 - x2) % P
    y3 = (m*(x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, Pt):
    R = None
    addend = Pt
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

# Check generator
assert is_on_curve(EC_G)

# =========================
# --- Parse Public Key ---
# =========================
hex_pubkey = "031f"  # (x,y) = (3,31)
pub_bytes = bytes.fromhex(hex_pubkey)
pub_point = (pub_bytes[0], pub_bytes[1])
print("Public key point:", pub_point)
assert is_on_curve(pub_point)

# Compute Q_IDX = discrete log classically (for validation)
def dlog_index(point, G, order):
    for k in range(order):
        if scalar_mult(k, G) == point:
            return k
    return None

Q_IDX = dlog_index(pub_point, EC_G, ORDER)
print("Q_IDX =", Q_IDX, "ORDER =", ORDER)

# =========================
# --- Shor Circuit Setup ---
# =========================
N_Q = max(1, ceil(log2(ORDER)))
D = 2**N_Q
print(f"N_Q = {N_Q}, D = {D}")

a = cirq.LineQubit.range(0, N_Q)
b = cirq.LineQubit.range(N_Q, 2*N_Q)
p = cirq.LineQubit.range(2*N_Q, 3*N_Q)

def qft_no_swaps(qubits):
    circ = cirq.Circuit()
    n = len(qubits)
    for i in range(n):
        circ.append(cirq.H(qubits[i]))
        for j in range(i+1, n):
            circ.append(cirq.CZ(qubits[j], qubits[i]) ** (1 / (2 ** (j - i))))
    return circ

def add_const_embedded_gate(cst):
    mat = np.zeros((D, D), dtype=complex)
    cst %= ORDER
    for x in range(D):
        if x < ORDER:
            y = (x + cst) % ORDER
            mat[y, x] = 1
        else:
            mat[x, x] = 1
    return cirq.MatrixGate(mat)

def controlled_add(circuit, ctrl, target_qubits, c):
    gate = add_const_embedded_gate(c)
    circuit.append(cirq.ControlledOperation([ctrl], gate.on(*target_qubits)))

def ecdlp_oracle(circuit, a_reg, b_reg, p_reg, P_idx, Q_idx):
    for i in range(N_Q):
        const_a = (P_idx * (1 << i)) % ORDER
        if const_a != 0:
            controlled_add(circuit, a_reg[i], p_reg, const_a)
    for i in range(N_Q):
        const_b = (Q_idx * (1 << i)) % ORDER
        if const_b != 0:
            controlled_add(circuit, b_reg[i], p_reg, const_b)

def shor_ecdlp_circuit(P_idx, Q_idx):
    circ = cirq.Circuit()
    circ.append(cirq.H.on_each(*a))
    circ.append(cirq.H.on_each(*b))
    ecdlp_oracle(circ, a, b, p, P_idx, Q_idx)
    circ += qft_no_swaps(a)
    circ += qft_no_swaps(b)
    circ.append(cirq.measure(*a, key='a'))
    circ.append(cirq.measure(*b, key='b'))
    return circ

# =========================
# --- Run Simulation ---
# =========================
qc = shor_ecdlp_circuit(1, Q_IDX)
sim = cirq.Simulator()
res = sim.run(qc, repetitions=5000)

def bits_to_int_le(bits): 
    return int("".join(str(int(x)) for x in bits[::-1]), 2)

A_list = [bits_to_int_le(row) for row in res.measurements['a']]
B_list = [bits_to_int_le(row) for row in res.measurements['b']]

ab_counter = Counter(zip(A_list, B_list))

print("Top (A,B) measurement pairs:")
for k,v in ab_counter.most_common(10):
    print(k,v)

# =========================
# --- Post-processing ---
# =========================
def safe_inv(x, mod):
    try:
        return pow(int(x)%mod, -1, mod)
    except ValueError:
        return None

def k_candidates_from_pair(A,B):
    cands = []
    invB = safe_inv(B, ORDER)
    invA = safe_inv(A, ORDER)
    if invB is not None:
        cands.append(( (A*invB)%ORDER, "A*inv(B)"))
        cands.append(( (-A*invB)%ORDER, "-A*inv(B)"))
    if invA is not None:
        cands.append(( (B*invA)%ORDER, "B*inv(A)"))
        cands.append(( (-B*invA)%ORDER, "-B*inv(A)"))
    return cands

k_votes = defaultdict(int)
for (A,B),count in ab_counter.items():
    for k,_ in k_candidates_from_pair(A,B):
        k_votes[k] += count

k_sorted = sorted(k_votes.items(), key=lambda kv: kv[1], reverse=True)
print("\nRecovered discrete log candidates:")
for k,v in k_sorted[:10]:
    print(f"k={k}, count={v}")

print("\nGround truth Q_IDX =", Q_IDX)
