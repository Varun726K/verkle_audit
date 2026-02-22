import random
from py_ecc.optimized_bn128 import G1, G2, multiply, add, curve_order, pairing, eq, neg, Z1, Z2

Order = curve_order

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
