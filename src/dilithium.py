"""
Dilithium: Post-Quantum Digital Signature Scheme
Implementation of the Dilithium algorithm (CRYSTALS-Dilithium)
Based on NIST PQC standardization specification

Author: Aland Mulia Pratama - 13522124
Institution: Institut Teknologi Bandung
Major: Informatics Engineering
"""

import hashlib
import secrets
from typing import Tuple, List
import numpy as np


class DilithiumParams:
    """Parameter sets for Dilithium security levels"""
    
    # Dilithium2 (NIST Security Level 2)
    DILITHIUM2 = {
        'name': 'Dilithium2',
        'q': 8380417,           # Prime modulus
        'n': 256,               # Polynomial degree
        'k': 4,                 # Rows in matrix A
        'l': 4,                 # Columns in matrix A
        'd': 13,                # Dropped bits from t
        'tau': 39,              # Hamming weight of c
        'gamma1': 2**17,        # Challenge norm bound
        'gamma2': (8380417 - 1) // 88,  # Low-order rounding range
        'beta': 78,             # Rejection bound
        'omega': 80,            # Maximum coefficient weight
        'security_level': 2
    }
    
    # Dilithium3 (NIST Security Level 3)
    DILITHIUM3 = {
        'name': 'Dilithium3',
        'q': 8380417,
        'n': 256,
        'k': 6,
        'l': 5,
        'd': 13,
        'tau': 49,
        'gamma1': 2**19,
        'gamma2': (8380417 - 1) // 32,
        'beta': 196,
        'omega': 55,
        'security_level': 3
    }
    
    # Dilithium5 (NIST Security Level 5)
    DILITHIUM5 = {
        'name': 'Dilithium5',
        'q': 8380417,
        'n': 256,
        'k': 8,
        'l': 7,
        'd': 13,
        'tau': 60,
        'gamma1': 2**19,
        'gamma2': (8380417 - 1) // 32,
        'beta': 120,
        'omega': 75,
        'security_level': 5
    }


class Polynomial:
    """Represents a polynomial in Z_q[X]/(X^n + 1)"""
    def __init__(self, coeffs: np.ndarray, q: int, n: int):
        self.coeffs = np.array(coeffs) % q
        self.q = q
        self.n = n

    def __add__(self, other):
        return Polynomial((self.coeffs + other.coeffs) % self.q, self.q, self.n)

    def __sub__(self, other):
        return Polynomial((self.coeffs - other.coeffs) % self.q, self.q, self.n)

    def __mul__(self, other):
        """Polynomial multiplication in ring Z_q[X]/(X^n + 1)"""
        # Simple schoolbook multiplication with modular reduction
        result = np.zeros(2 * self.n, dtype=np.int64)
        for i in range(self.n):
            for j in range(self.n):
                result[i + j] += int(self.coeffs[i]) * int(other.coeffs[j])

        # Reduce modulo (X^n + 1)
        final = np.zeros(self.n, dtype=np.int64)
        for i in range(self.n):
            final[i] = result[i] - result[i + self.n]

        return Polynomial(final % self.q, self.q, self.n)

    def norm(self) -> int:
        """Compute infinity norm of polynomial"""
        centered = self.coeffs.copy()
        centered[centered > self.q // 2] -= self.q
        return int(np.max(np.abs(centered)))


class DilithiumSignature:
    """Main Dilithium signature scheme implementation"""
    
    def __init__(self, params: dict):
        self.params = params
        self.q = params['q']
        self.n = params['n']
        self.k = params['k']
        self.l = params['l']
        self.d = params['d']
        self.tau = params['tau']
        self.gamma1 = params['gamma1']
        self.gamma2 = params['gamma2']
        self.beta = params['beta']
        self.omega = params['omega']
    
    def _hash_function(self, data: bytes) -> bytes:
        """SHAKE256 hash function"""
        return hashlib.shake_256(data).digest(64)
    
    def _sample_polynomial(self, seed: bytes, nonce: int) -> Polynomial:
        """Sample a polynomial using SHAKE256"""
        data = seed + nonce.to_bytes(2, 'little')
        hash_output = hashlib.shake_256(data).digest(self.n * 3)
        coeffs = np.zeros(self.n, dtype=np.int32)
        
        j = 0
        for i in range(0, len(hash_output), 3):
            if j >= self.n:
                break
            val = int.from_bytes(hash_output[i:i+3], 'little')
            if val < self.q:
                coeffs[j] = val % self.q
                j += 1
        
        return Polynomial(coeffs, self.q, self.n)
    
    def _sample_small_polynomial(self, seed: bytes, nonce: int, eta: int) -> Polynomial:
        """Sample a small polynomial with coefficients in [-eta, eta]"""
        data = seed + nonce.to_bytes(2, 'little')
        hash_output = hashlib.shake_256(data).digest(self.n)
        coeffs = np.zeros(self.n, dtype=np.int32)
        
        for i in range(self.n):
            byte_val = hash_output[i]
            # Map to [-eta, eta]
            coeffs[i] = (byte_val % (2 * eta + 1)) - eta
        
        return Polynomial(coeffs % self.q, self.q, self.n)
    
    def _power2round(self, r: int) -> Tuple[int, int]:
        """Decompose r into (r1, r0) where r = r1*2^d + r0"""
        r = r % self.q
        r0 = r % (2 ** self.d)
        if r0 > 2 ** (self.d - 1):
            r0 -= 2 ** self.d
        r1 = (r - r0) // (2 ** self.d)
        return r1, r0
    
    def _decompose(self, r: int) -> Tuple[int, int]:
        """Decompose r for signature generation"""
        r = r % self.q
        r0 = r % (2 * self.gamma2)
        if r0 > self.gamma2:
            r0 -= 2 * self.gamma2
        
        if r - r0 == self.q - 1:
            r1 = 0
            r0 = r0 - 1
        else:
            r1 = (r - r0) // (2 * self.gamma2)
        
        return r1, r0
    
    def _make_hint(self, z: int, r: int) -> int:
        """Generate hint bit for signature compression"""
        r1, r0 = self._decompose(r)
        v1, v0 = self._decompose(r + z)
        return 1 if r1 != v1 else 0
    def _use_hint(self, h: int, r: int) -> int:
        """Use hint bit during verification"""
        m = (self.q - 1) // (2 * self.gamma2)
        r1, r0 = self._decompose(r)
        
        if h == 1:
            if r0 > 0:
                return (r1 + 1) % m
            else:
                return (r1 - 1) % m
        
        return r1
    
    def _sample_challenge(self, seed: bytes) -> Polynomial:
        """Sample challenge polynomial with hamming weight tau"""
        hash_output = hashlib.shake_256(seed).digest(self.n)
        coeffs = np.zeros(self.n, dtype=np.int32)
        
        # Set tau random positions to ±1
        positions = set()
        idx = 0
        while len(positions) < self.tau and idx < len(hash_output):
            pos = hash_output[idx] % self.n
            if pos not in positions:
                positions.add(pos)
                coeffs[pos] = 1 if hash_output[idx] % 2 == 0 else -1
            idx += 1
                
        return Polynomial(coeffs, self.q, self.n)
    
    def keygen(self) -> Tuple[dict, dict]:
        """
        Generate public and private key pair
        
        Returns:
            (public_key, secret_key): Tuple of key dictionaries
        """
        # Generate random seed
        seed = secrets.token_bytes(32)
        rho = hashlib.shake_256(seed + b'rho').digest(32)
        key = hashlib.shake_256(seed + b'key').digest(32)
        
        # Sample matrix A
        A = [[self._sample_polynomial(rho, i * self.l + j) 
              for j in range(self.l)] for i in range(self.k)]
        
        # Sample secret vectors s1, s2 with small coefficients
        eta = 2 if self.params['security_level'] == 2 else 4
        s1 = [self._sample_small_polynomial(key, i, eta) for i in range(self.l)]
        s2 = [self._sample_small_polynomial(key, self.l + i, eta) for i in range(self.k)]
        
        # Compute t = A*s1 + s2
        t = []
        for i in range(self.k):
            ti = Polynomial(np.zeros(self.n, dtype=np.int32), self.q, self.n)
            for j in range(self.l):
                ti = ti + (A[i][j] * s1[j])
            t.append(ti)
        
        # Power2Round to get t1, t0
        t1 = []
        t0 = []
        for ti in t:
            t1i = np.zeros(self.n, dtype=np.int32)
            t0i = np.zeros(self.n, dtype=np.int32)
            for j in range(self.n):
                t1i[j], t0i[j] = self._power2round(ti.coeffs[j])
            t1.append(Polynomial(t1i, self.q, self.n))
            t0.append(Polynomial(t0i, self.q, self.n))
        
        # Public key
        public_key = {
            'rho': rho,
            't1': t1,
            'params': self.params['name']
        }
        
        # Secret key
        secret_key = {
            'rho': rho,
            'key': key,
            's1': s1,
            's2': s2,
            't0': t0,
            'params': self.params['name']
        }
        
        return public_key, secret_key
    
    def sign(self, message: bytes, secret_key: dict) -> dict:
        """
        Generate a signature for a message
        
        Args:
            message: Message to sign
            secret_key: Secret key from keygen
            
        Returns:
            signature: Dictionary containing signature components
        """
        rho = secret_key['rho']
        key = secret_key['key']
        s1 = secret_key['s1']
        s2 = secret_key['s2']
        t0 = secret_key['t0']
        
        # Reconstruct matrix A
        A = [[self._sample_polynomial(rho, i * self.l + j) 
              for j in range(self.l)] for i in range(self.k)]
        
        # Hash message
        mu = self._hash_function(message)
        
        # Rejection sampling loop
        kappa = 0
        max_attempts = 1000
        eta = 2 if self.params['security_level'] == 2 else 4
        while kappa < max_attempts:
            # Sample random vector y
            y = [self._sample_small_polynomial(
                mu + kappa.to_bytes(2, 'little'), i, eta
            ) for i in range(self.l)]
            # Compute w = A*y
            w = []
            for i in range(self.k):
                wi = Polynomial(np.zeros(self.n), self.q, self.n)
                for j in range(self.l):
                    wi = wi + (A[i][j] * y[j])
                w.append(wi)
            # Decompose w
            w1 = []
            for wi in w:
                w1i = np.zeros(self.n, dtype=np.int32)
                for j in range(self.n):
                    w1i[j], _ = self._decompose(wi.coeffs[j])
                w1.append(Polynomial(w1i, self.q, self.n))
            # Generate challenge
            c_seed = mu + b''.join([w1i.coeffs.tobytes() for w1i in w1])
            c = self._sample_challenge(c_seed)
            # Compute z = y + c*s1
            z = []
            z_reject = False
            for i in range(self.l):
                zi = y[i] + (c * s1[i])
                if zi.norm() >= self.gamma1 - self.beta:
                    # print(f"[DEBUG] Rejection at z norm (i={i}, norm={zi.norm()}, bound={self.gamma1 - self.beta}, kappa={kappa})")
                    kappa += 1
                    z_reject = True
                    break
                z.append(zi)
            if z_reject or len(z) != self.l:
                continue
            # Compute r0 = w - c*s2
            r0 = []
            r0_reject = False
            for i in range(self.k):
                r0i_poly = w[i] - (c * s2[i])
                # Decompose each coefficient and check the norm of the r0 (low bits)
                r0i_coeffs = np.zeros(self.n, dtype=np.int32)
                for j in range(self.n):
                    _, r0_coeff = self._decompose(r0i_poly.coeffs[j])
                    r0i_coeffs[j] = r0_coeff
                r0i_norm = int(np.max(np.abs(r0i_coeffs)))
                if r0i_norm >= self.gamma2 - self.beta:
                    # print(f"[DEBUG] Rejection at r0 norm (i={i}, norm={r0i_norm}, bound={self.gamma2 - self.beta}, kappa={kappa})")
                    kappa += 1
                    r0_reject = True
                    break
                r0.append(Polynomial(r0i_coeffs, self.q, self.n))
            if r0_reject or len(r0) != self.k:
                continue
            # Compute hints
            ct0 = [c * t0i for t0i in t0]
            hints = []
            hint_count = 0
            hint_reject = False
            for i in range(self.k):
                hi = np.zeros(self.n, dtype=np.int32)
                for j in range(self.n):
                    hint = self._make_hint(ct0[i].coeffs[j], w[i].coeffs[j] - ct0[i].coeffs[j])
                    hi[j] = hint
                    hint_count += hint
                if hint_count > self.omega:
                    # print(f"[DEBUG] Rejection at hint count (i={i}, hint_count={hint_count}, omega={self.omega}, kappa={kappa})")
                    kappa += 1
                    hint_reject = True
                    break
                hints.append(hi)
            if hint_reject or len(hints) != self.k:
                continue
            # Valid signature found
            return {
                'c': c_seed,
                'z': z,
                'h': hints
            }
            kappa += 1
        raise ValueError("Failed to generate signature after maximum attempts")
    
    def verify(self, message: bytes, signature: dict, public_key: dict) -> bool:
        """
        Verify a signature
        
        Args:
            message: Original message
            signature: Signature from sign()
            public_key: Public key from keygen
        
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            rho = public_key['rho']
            t1 = public_key['t1']
            c_seed = signature['c']
            z = signature['z']
            h = signature['h']
            # Check z norm
            for zi in z:
                if zi.norm() >= self.gamma1 - self.beta:
                    return False
            # Check hint weight
            hint_weight = sum(np.sum(hi) for hi in h)
            if hint_weight > self.omega:
                return False
            # Reconstruct matrix A
            A = [[self._sample_polynomial(rho, i * self.l + j)
                  for j in range(self.l)] for i in range(self.k)]
            # Hash message
            mu = self._hash_function(message)
            # Reconstruct challenge
            c = self._sample_challenge(c_seed)
            # Compute w' = A*z - c*t1*2^d
            w_prime = []
            for i in range(self.k):
                wi = Polynomial(np.zeros(self.n), self.q, self.n)
                for j in range(self.l):
                    wi = wi + (A[i][j] * z[j])
                # Subtract c*t1[i]*2^d
                t1_scaled = Polynomial(t1[i].coeffs * (2 ** self.d), self.q, self.n)
                wi = wi - (c * t1_scaled)
                w_prime.append(wi)
            # Use hints to recover w1
            w1_prime = []
            for i in range(self.k):
                w1i = np.zeros(self.n, dtype=np.int32)
                for j in range(self.n):
                    w1i[j] = self._use_hint(h[i][j], w_prime[i].coeffs[j])
                w1_prime.append(Polynomial(w1i, self.q, self.n))
            # Recompute challenge
            c_prime_seed = mu + b''.join([w1i.coeffs.tobytes() for w1i in w1_prime])
            return c_seed == c_prime_seed
        except Exception as e:
            print(f"Verification error: {e}")
            return False

def get_dilithium_instance(security_level: int) -> DilithiumSignature:
    """
    Factory to get DilithiumSignature instance for a given security level.
    Args:
        security_level: 2, 3, or 5
    Returns:
        DilithiumSignature instance
    """
    if security_level == 2:
        return DilithiumSignature(DilithiumParams.DILITHIUM2)
    elif security_level == 3:
        return DilithiumSignature(DilithiumParams.DILITHIUM3)
    elif security_level == 5:
        return DilithiumSignature(DilithiumParams.DILITHIUM5)
    else:
        raise ValueError("Security level must be 2, 3, or 5")


if __name__ == "__main__":
    print("Dilithium Post-Quantum Digital Signature Demo")
    print("=" * 50)
    
    # Initialize Dilithium with security level 2
    dilithium = get_dilithium_instance(2)
    
    # Generate keys
    print("\n[1] Generating key pair...")
    public_key, secret_key = dilithium.keygen()
    print(f"✓ Keys generated successfully")
    print(f"  - Parameter set: {dilithium.params['name']}")
    print(f"  - Security level: NIST Level {dilithium.params['security_level']}")
    
    # Sign a message
    message = b"Hello, Post-Quantum World!"
    print(f"\n[2] Signing message: '{message.decode()}'")
    signature = dilithium.sign(message, secret_key)
    print(f"✓ Signature generated successfully")
    
    # Verify signature
    print(f"\n[3] Verifying signature...")
    is_valid = dilithium.verify(message, signature, public_key)
    print(f"✓ Signature verification: {'VALID' if is_valid else 'INVALID'}")
    
    # Test with tampered message
    print(f"\n[4] Testing with tampered message...")
    tampered_message = b"Hello, Post-Quantum World?"
    is_valid_tampered = dilithium.verify(tampered_message, signature, public_key)
    print(f"✓ Tampered message verification: {'VALID' if is_valid_tampered else 'INVALID (as expected)'}")
