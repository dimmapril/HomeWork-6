#!/usr/bin/env python3
# task4_decrypt.py — извлечение plaintext из ct, когда e=3 и plaintext^3 < n.
ct = 183001753190025751114220069887230720857448492282044619321040127443487542179613757444809112210217896463899655491288132907560322811734646233820773

def iroot(k, n):
    lo = 0
    hi = 1 << ((n.bit_length() + k - 1) // k)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid
    return lo

root = iroot(3, ct)
pt_bytes = root.to_bytes((root.bit_length()+7)//8, 'big')
try:
    pt_text = pt_bytes.decode('utf-8')
except UnicodeDecodeError:
    pt_text = pt_bytes.hex()

print("Recovered integer plaintext:", root)
print("Plaintext bytes:", pt_bytes)
print("Plaintext:", pt_text)

# save flag
with open("task-4-flag.txt", "w", encoding="utf-8") as f:
    f.write(pt_text)
print("Flag written to task-4-flag.txt")
