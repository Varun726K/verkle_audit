from py_ecc.optimized_bn128 import G1
x = G1[0]
print(f"Type: {type(x)}")
try:
    val = int(x)
    print(f"int(x) = {val}")
except Exception as e:
    print(f"int(x) failed: {e}")

try:
    val_n = x.n
    print(f"x.n = {val_n}")
except Exception as e:
    print(f"x.n failed: {e}")
