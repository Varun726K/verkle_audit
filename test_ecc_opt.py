from py_ecc.optimized_bn128 import G1, G2, multiply, add, pairing, neg, curve_order, Z1, Z2
import sys

print("Starting checks (optimized)...")
try:
    print(f"G1 type: {type(G1)}")
    
    # Check Pairing
    print("Testing pairing(G2, G1)...")
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
