from py_ecc.bn128 import G1, G2, multiply, add, pairing, neg, curve_order, Z1, Z2
import sys

print("Starting checks...")
try:
    print(f"G1: {G1}")
    print(f"G2: {G2}")
    
    # Check Multiply
    print("Testing multiply...")
    p1 = multiply(G1, 5)
    print(f"5*G1: {p1}")
    
    # Check Neg
    print("Testing neg...")
    n1 = neg(p1)
    print(f"-5*G1: {n1}")
    
    # Check Add
    print("Testing add...")
    sum_p = add(p1, n1) # Should be Z1 (Infinity)
    print(f"Sum (should be infinity): {sum_p}")
    print(f"Is Infinity? {sum_p == Z1}")
    if sum_p is None: print("Sum is None")
    
    # Check Pairing
    print("Testing pairing...")
    # e(G1, G2) ? No, usually e(G2, G1) in py_ecc types 
    # Let's try e(G2, G1)
    res = pairing(G2, G1)
    print(f"Pairing result: {res}")
    
    # Bilinearity check
    # e(2*G2, G1) == e(G2, 2*G1)
    lhs = pairing(multiply(G2, 2), G1)
    rhs = pairing(G2, multiply(G1, 2))
    print(f"Bilinearity check: {lhs == rhs}")
    
except Exception as e:
    print(f"Caught exception: {e}")
    import traceback
    traceback.print_exc()

print("Done.")
