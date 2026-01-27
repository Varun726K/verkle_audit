import random
from py_ecc.optimized_bn128 import G1, G2, multiply, add, curve_order, pairing, eq, neg, Z1, Z2

# BN128 curve order (scalar field size)
Order = curve_order

class KZG:
    def __init__(self, secret=None, degree=16):
        """
        Trusted Setup: In a real scenario, this is done via MPC.
        Here we generate it locally for testing.
        s: Secret trapdoor
        n: Max degree of polynomial supported
        """
        if secret is None:
            self.s = random.randint(1, Order - 1)
        else:
            self.s = secret
        
        self.degree = degree
        self.SRS_1 = [] # G1 powers: g1^s^0, g1^s^1, ...
        self.SRS_2 = [] # G2 powers: g2^s^0, g2^s^1, ...

        print("Generating Trusted Setup (SRS)...")
        # Generate SRS [s^i * G1] and [s^i * G2]
        curr_s = 1
        for i in range(degree + 1):
            self.SRS_1.append(multiply(G1, curr_s))
            self.SRS_2.append(multiply(G2, curr_s))
            curr_s = (curr_s * self.s) % Order
        print("Trusted Setup Complete.")

    def commit(self, coeffs):
        """
        Commit to a polynomial P(x) = sum(coeffs[i] * x^i)
        Commitment C = sum(coeffs[i] * SRS_1[i])
        """
        commitment = Z1 # Point at infinity (Identity)
        for i, coeff in enumerate(coeffs):
            if i >= len(self.SRS_1):
                break
            term = multiply(self.SRS_1[i], coeff)
            commitment = add(commitment, term)
        
        # Normalize to (x, y) if not infinity
        if commitment == Z1:
            return None
        # py_ecc points are usually (x, y, z) in Jacobian or (x, y) in affine.
        # optimized_bn128 usually returns (x, y, z).
        # We need to ensure we return Affine coordinates for consistency.
        from py_ecc.optimized_bn128 import normalize
        return normalize(commitment)

    def evaluate(self, coeffs, x):
        """
        Evaluate polynomial P(x) at scalar x
        """
        result = 0
        power_of_x = 1
        for coeff in coeffs:
            result = (result + coeff * power_of_x) % Order
            power_of_x = (power_of_x * x) % Order
        return result

    def generate_proof(self, coeffs, z):
        """
        Generate proof for P(z) = y
        Proof pi = g1 ^ (P(s) - y) / (s - z)
        This is essentially committing to the quotient polynomial Q(x)
        Q(x) = (P(x) - y) / (x - z)
        pi = Commit(Q(x))
        """
        y = self.evaluate(coeffs, z)
        
        # Polynomial Division to find Q(x)
        # We need (P(x) - y) / (x - z)
        # Since we are working with coefficients, we can do synthetic division
        
        # 1. Shift P(x) by subtracting y from the constant term (index 0)
        numerator_coeffs = list(coeffs)
        numerator_coeffs[0] = (numerator_coeffs[0] - y) % Order
        
        # 2. Divide by (x - z)
        # Q(x) will have degree len(coeffs) - 2
        # Let P(x) = a_n*x^n + ... + a_0
        # We want Q(x) such that Q(x) * (x - z) = P(x) - y
        
        # Synthetic division algorithm
        quotient_coeffs = [0] * (len(numerator_coeffs) - 1)
        remainder = 0 # Should be 0 since z is a root of (P(x) - y)
        
        # Work from highest degree down
        # (x - z) means we are dividing by x - z
        # The coefficient of x in divisor is 1.
        
        current_val = 0
        for i in range(len(numerator_coeffs) - 1, 0, -1):
            # The coeff of x^i in P(x) comes from coeff of x^{i-1} in Q(x) * x
            # So Q_{i-1} = P_i
            # But we also have to account for the -z * Q_i term from previous step?
            # Wait, standard synthetic division:
            # Dividing by (x - c). Here c = z.
            # Coeffs: [a_n, a_{n-1}, ..., a_0] (highest to lowest? No, my coeffs are lowest to highest)
            pass

        # Let's do it properly with lowest-to-highest index
        # coeffs: [a0, a1, a2] -> a0 + a1*x + a2*x^2
        # Divisor: (x - z) = -z + 1*x
        
        # Logic:
        # Highest term of Q must match Highest term of P divided by x
        # Q_{n-1} = P_n
        # Then we subtract Q_{n-1} * (x-z) from P
        
        quotient_coeffs = [0] * (len(numerator_coeffs) - 1)
        carry = 0
        
        for i in range(len(numerator_coeffs) - 1, 0, -1):
           quotient_coeffs[i-1] = numerator_coeffs[i]
           numerator_coeffs[i-1] = (numerator_coeffs[i-1] + quotient_coeffs[i-1] * z) % Order
           
        # Verification: numerator_coeffs[0] should be 0 now (remainder)
        if numerator_coeffs[0] != 0:
            print("Error: Division remainder is not zero!", numerator_coeffs[0])
            
        proof = self.commit(quotient_coeffs)
        return proof, y

    def verify(self, commitment, proof, z, y):
        """
        Verify the proof equation:
        e(proof, [s - z]_2) = e(C - [y]_1, [1]_2)
        
        Rearranged for simpler computation usually:
        e(proof, S_2 - z*G2) = e(C - y*G1, G2)
        """
        
        # LHS terms
        # [s]_2 is SRS_2[1]
        # [z]_2 is z * G2
        s_2 = self.SRS_2[1]
        z_g2 = multiply(G2, z)
        term_2 = add(s_2, neg(z_g2)) # (s - z) * G2
        
        lhs = pairing(term_2, proof)
        
        # RHS terms
        # C - [y]_1
        y_g1 = multiply(G1, y)
        comm_minus_y = add(commitment, neg(y_g1))
        
        # [1]_2 is G2 (generator)
        rhs = pairing(G2, comm_minus_y)
        
        return lhs == rhs

def main():
    print("=== KZG Polynomial Commitment Demo ===")
    kzg = KZG(degree=4)
    
    # 1. Create a polynomial P(x) = 1 + 2x + 3x^2
    # Coeffs: [1, 2, 3]
    coeffs = [1, 2, 3] 
    print(f"Polynomial P(x): {coeffs}")
    
    # 2. Commit to polynomial
    print("Committing to polynomial...")
    commitment = kzg.commit(coeffs)
    print(f"Commitment: {commitment}")
    
    # 3. Prove value at z = 10
    z = 10
    print(f"Generating proof for P({z})...")
    proof, y = kzg.generate_proof(coeffs, z)
    print(f"Value y: {y}")
    print(f"Proof pi: {proof}")
    
    # Manual check: P(10) = 1 + 2(10) + 3(100) = 1 + 20 + 300 = 321
    assert y == 321
    print("Local evaluation check passed.")
    
    # 4. Verify
    print("Verifying proof...")
    valid = kzg.verify(commitment, proof, z, y)
    
    if valid:
        print("✅ SUCCESS: Proof Verified!")
    else:
        print("❌ FAILURE: Proof Invalid.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRITICAL ERROR: {e}")

