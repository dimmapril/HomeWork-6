#!/usr/bin/env python3
# Разбор задачи 3: если e = 1, то ct == pt (mod n), поэтому plaintext = ct как число -> байты.
from pathlib import Path

n = 89130176363968657187562046515332781879906710777886742664996031757940362853930049819009596594982246571669482031940134479813793328701373238273415076270891142859666516439231904521557755729322490606876589914024096621194962329718893576886641536066926542462448229133783052051407061075447588804617825930836181625077
e = 1
ct = 9525146106593233668246438912833048755472216768584708733

# перевод числа в байты
blen = (ct.bit_length() + 7) // 8
pt_bytes = ct.to_bytes(blen, 'big')

# декодируем в текст (utf-8)
try:
    pt_text = pt_bytes.decode('utf-8')
except UnicodeDecodeError:
    pt_text = repr(pt_bytes)

print("Plain bytes:", pt_bytes)
print("Plain text :", pt_text)

# записать флаг в файл
Path("task-3-flag.txt").write_text(pt_text, encoding="utf-8")
print("Flag saved to task-3-flag.txt")
