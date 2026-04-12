import random
from py_ecc.optimized_bn128 import G1, G2, multiply, add, curve_order, pairing, eq, neg, Z1, Z2

Order = curve_order

def mod_inverse(a, m):
    if a == 0:
        raise ZeroDivisionError("division by zero")
    return pow(a, m - 2, m)

def lagrange_interpolate(x_values, y_values):
    assert len(x_values) == len(y_values)
    n = len(x_values)
    poly = [0] * n
    for i in range(n):
        num = [1]
        den = 1
        for j in range(n):
            if i != j:
                new_num = [0] * (len(num) + 1)
                for k in range(len(num)):
                    new_num[k+1] = (new_num[k+1] + num[k]) % Order
                    new_num[k] = (new_num[k] - x_values[j] * num[k]) % Order
                num = new_num
                den = (den * (x_values[i] - x_values[j])) % Order
        inv_den = mod_inverse(den, Order)
        factor = (y_values[i] * inv_den) % Order
        for k in range(len(num)):
            poly[k] = (poly[k] + num[k] * factor) % Order
    return poly

import hashlib

def poly_add(p1, p2):
    max_len = max(len(p1), len(p2))
    res = [0] * max_len
    for i in range(len(p1)): res[i] = (res[i] + p1[i]) % Order
    for i in range(len(p2)): res[i] = (res[i] + p2[i]) % Order
    return res

def poly_mul_scalar(p, scalar):
    return [(coeff * scalar) % Order for coeff in p]

def poly_div_exact(P, z, y):
    """ Divides (P(x) - y) / (x - z). Assumes remainder is 0. """
    num = list(P)
    num[0] = (num[0] - y) % Order
    quotient = [0] * (len(num) - 1)
    for i in range(len(num) - 1, 0, -1):
        quotient[i-1] = num[i]
        num[i-1] = (num[i-1] + quotient[i-1] * z) % Order
    return quotient

def evaluate_poly(P, x):
    result = 0
    power = 1
    for coeff in P:
        result = (result + coeff * power) % Order
        power = (power * x) % Order
    return result

def hash_to_scalar(*args):
    """ Mirrors abi.encode() hashing in Solidity """
    data = b""
    for arg in args:
        if isinstance(arg, int): 
            data += arg.to_bytes(32, 'big')
        elif isinstance(arg, tuple): 
            val0 = int(arg[0])
            val1 = int(arg[1])
            data += val0.to_bytes(32, 'big') + val1.to_bytes(32, 'big')
    return int.from_bytes(hashlib.sha256(data).digest(), 'big') % Order

from py_ecc.optimized_bn128 import normalize

def generate_multiproof(kzg, polynomials, C, z, y):
    depth = len(polynomials)
    
    # 1. Challenge r
    r = hash_to_scalar(*C, *z, *y)
    
    # 2. Compute h(x) = SUM [ r^i * (f_i(x) - y_i) / (x - z_i) ]
    h_coeffs = []
    r_power = 1
    for i in range(depth):
        Q_i = poly_div_exact(polynomials[i], z[i], y[i])
        term = poly_mul_scalar(Q_i, r_power)
        h_coeffs = poly_add(h_coeffs, term)
        r_power = (r_power * r) % Order
        
    C_h = kzg.commit(h_coeffs)
    
    # 3. Challenge t
    t = hash_to_scalar(r, C_h)
    
    # 4. Prover evaluations at t
    v = [evaluate_poly(polynomials[i], t) for i in range(depth)]
    v_h = evaluate_poly(h_coeffs, t)
    
    # 5. Challenge rho
    rho = hash_to_scalar(t, *v, v_h)
    
    # 6. Compute P_agg(x) and V_agg
    P_agg = []
    V_agg = 0
    rho_power = 1
    for i in range(depth):
        P_agg = poly_add(P_agg, poly_mul_scalar(polynomials[i], rho_power))
        V_agg = (V_agg + v[i] * rho_power) % Order
        rho_power = (rho_power * rho) % Order
        
    P_agg = poly_add(P_agg, poly_mul_scalar(h_coeffs, rho_power))
    V_agg = (V_agg + v_h * rho_power) % Order
    
    # 7. Compute final quotient Q(x) = (P_agg(x) - V_agg) / (x - t)
    Q_final = poly_div_exact(P_agg, t, V_agg)
    pi = kzg.commit(Q_final)
    
    return {
        "C": [(int(c[0]), int(c[1])) for c in C],
        "z": z,
        "y": y,
        "v": v,
        "v_h": v_h,
        "C_h": (int(C_h[0]), int(C_h[1])),
        "pi": (int(pi[0]), int(pi[1]))
    }

class KZG:
    def __init__(self, secret=None, degree=16):
        """Generates Trusted Setup (SRS)"""
        if secret is None:
            self.s = random.randint(1, Order - 1)
        else:
            self.s = secret
        
        self.degree = degree
        self.SRS_1 = []
        self.SRS_2 = []

        print("Generating Trusted Setup (SRS)...")
        curr_s = 1
        for i in range(degree + 1):
            self.SRS_1.append(multiply(G1, curr_s))
            self.SRS_2.append(multiply(G2, curr_s))
            curr_s = (curr_s * self.s) % Order
        print("Trusted Setup Complete.")

    def commit(self, coeffs):
        """Commits to a polynomial P(x)"""
        commitment = Z1
        for i, coeff in enumerate(coeffs):
            if i >= len(self.SRS_1):
                break
            term = multiply(self.SRS_1[i], coeff)
            commitment = add(commitment, term)
        
        if commitment == Z1:
            return None
            
        from py_ecc.optimized_bn128 import normalize
        return normalize(commitment)

    def evaluate(self, coeffs, x):
        """Evaluates polynomial P(x) at scalar x"""
        result = 0
        power_of_x = 1
        for coeff in coeffs:
            result = (result + coeff * power_of_x) % Order
            power_of_x = (power_of_x * x) % Order
        return result

    def generate_proof(self, coeffs, z):
        """Generates proof for P(z) = y"""
        y = self.evaluate(coeffs, z)
        
        numerator_coeffs = list(coeffs)
        numerator_coeffs[0] = (numerator_coeffs[0] - y) % Order
        
        quotient_coeffs = [0] * (len(numerator_coeffs) - 1)
        
        for i in range(len(numerator_coeffs) - 1, 0, -1):
           quotient_coeffs[i-1] = numerator_coeffs[i]
           numerator_coeffs[i-1] = (numerator_coeffs[i-1] + quotient_coeffs[i-1] * z) % Order
           
        if numerator_coeffs[0] != 0:
            print("Error: Division remainder is not zero!", numerator_coeffs[0])
            
        proof = self.commit(quotient_coeffs)
        return proof, y

    def verify(self, commitment, proof, z, y):
        """Verifies the proof equation using bilinear pairing"""
        if commitment and len(commitment) == 2:
            commitment = (commitment[0], commitment[1], G1[2])
        if proof and len(proof) == 2:
            proof = (proof[0], proof[1], G1[2])

        s_2 = self.SRS_2[1]
        z_g2 = multiply(G2, z)
        term_2 = add(s_2, neg(z_g2))
        
        lhs = pairing(term_2, proof)
        
        y_g1 = multiply(G1, y)
        comm_minus_y = add(commitment, neg(y_g1))
        rhs = pairing(G2, comm_minus_y)
        
        return lhs == rhs

def main():
    print("=== KZG Polynomial Commitment Demo ===")
    kzg = KZG(degree=4)
    
    coeffs = [1, 2, 3] 
    print(f"Polynomial P(x): {coeffs}")
    
    print("Committing to polynomial...")
    commitment = kzg.commit(coeffs)
    print(f"Commitment: {commitment}")
    
    z = 10
    print(f"Generating proof for P({z})...")
    proof, y = kzg.generate_proof(coeffs, z)
    print(f"Value y: {y}")
    print(f"Proof pi: {proof}")
    
    assert y == 321
    print("Local evaluation check passed.")
    
    print("Verifying proof...")
    valid = kzg.verify(commitment, proof, z, y)
    
    if valid:
        print("SUCCESS: Proof Verified!")
    else:
        print("FAILURE: Proof Invalid.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRITICAL ERROR: {e}")
