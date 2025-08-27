#%%
import hashlib
import random

# --- ECC Parameters ---
P = 37         # prime field
A = 2
B = 3
G = (15, 2)    # base point on curve
N = 32         # order of G (prime or near-prime)
O = None       # point at infinity

# --- Helper Functions ---
def inv_mod(k, p):
    """Modular inverse using Extended Euclidean Algorithm."""
    if k == 0:
        raise ZeroDivisionError('division by zero')
    s, old_s = 0, 1
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    return old_s % p

def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        m = (3*x1*x1 + A) * inv_mod(2*y1, P) % P
    else:
        m = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (m*m - x1 - x2) % P
    y3 = (m*(x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

# --- Key Classes ---
class SigningKey:
    def __init__(self, private_key: int):
        if not (1 <= private_key < N):
            raise ValueError("Private key must be integer in [1, N-1]")
        self.privkey = private_key

    @staticmethod
    def generate():
        while True:
            priv = random.randint(1, N-1)
            pub = scalar_mult(priv, G)
            if pub is not None and is_on_curve(pub):
                return SigningKey(priv)

    def get_verifying_key(self):
        pub_point = scalar_mult(self.privkey, G)
        if pub_point is None or not is_on_curve(pub_point):
            raise ValueError("Invalid public key generated")
        return VerifyingKey(pub_point)

    def sign(self, message: bytes) -> bytes:
        z = int(hashlib.sha256(message).hexdigest(), 16) % N
        while True:
            k = random.randint(1, N-1)
            R = scalar_mult(k, G)
            if R is None:
                continue
            r = R[0] % N
            if r == 0:
                continue
            k_inv = inv_mod(k, N)
            s = (k_inv * (z + r*self.privkey)) % N
            if s == 0:
                continue
            break
        return r.to_bytes(1, 'big') + s.to_bytes(1, 'big')

    @staticmethod
    def from_string(data: bytes):
        if len(data) != 1:
            raise ValueError("Invalid private key length")
        return SigningKey(int.from_bytes(data, 'big'))

class VerifyingKey:
    def __init__(self, pub_point):
        if pub_point is None or not is_on_curve(pub_point):
            raise ValueError("Invalid public key point")
        self.pub_point = pub_point

    def to_string(self) -> bytes:
        x, y = self.pub_point
        return x.to_bytes(1, 'big') + y.to_bytes(1, 'big')

    def verify(self, signature: bytes, message: bytes) -> bool:
        if len(signature) != 2:
            return False
        r, s = signature[0], signature[1]
        if r == 0 or s == 0 or r >= N or s >= N:
            return False
        z = int(hashlib.sha256(message).hexdigest(), 16) % N
        s_inv = inv_mod(s, N)
        u1 = (z * s_inv) % N
        u2 = (r * s_inv) % N
        point = point_add(scalar_mult(u1, G), scalar_mult(u2, self.pub_point))
        if point is None:
            return False
        x, y = point
        return (r % N) == (x % N)

    @staticmethod
    def from_string(data: bytes):
        if len(data) != 2:
            raise ValueError("Invalid public key length")
        return VerifyingKey((data[0], data[1]))

#%%
# --- Test Example ---
if __name__ == "__main__":
    fixed_priv_keys = [1,2,3,4,9]
    message = b"Test"
    for priv in fixed_priv_keys:
        sk = SigningKey(priv)
        vk = sk.get_verifying_key()
        sig = sk.sign(message)
        valid = vk.verify(sig, message)
        print(f"Private key: {priv}, Public key: {vk.to_string().hex()}, Signature: {sig.hex()}, Valid: {valid}")

# %%
