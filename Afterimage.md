# CTF Challenge Writeup: Afterimage

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** Afterimage  

---

## Challenge Description
We were given `afterimage.png`, a night photograph of a fire and smoke over a city skyline, with this hint:

> "A photograph captured at the right moment can tell a story. Can you find what was left behind?"

---

## Step-by-Step Solution

### Step 1: Inspect the PNG chunks
We parsed the PNG chunk by chunk to look for metadata and data after `IEND`:

```python
import struct
d = open('afterimage.png', 'rb').read()
i = 8
while i < len(d):
    l, t = struct.unpack('>I4s', d[i:i+8])
    print(t, l, d[i+8:i+8+l][:80] if t != b'IDAT' else '')
    i += 12 + l
    if t == b'IEND':
        break
print('trailing bytes:', len(d) - i)
```

There was no trailing data, but there were several text chunks (`iTXt` / `tEXt`) with a description, author, copyright and a **Comment**:

```
QC annotation (encoded): UUMtMTc6IEJMVUUgTFNCLCByb3ctbWFqb3I7IHZlcmlmeSBhcmNoaXZlIHJlZmVyZW5jZSBBRi0xNy4=
```

---

### Step 2: Decode the QC annotation
```bash
echo "UUMtMTc6IEJMVUUgTFNCLCByb3ctbWFqb3I7IHZlcmlmeSBhcmNoaXZlIHJlZmVyZW5jZSBBRi0xNy4=" | base64 -d
```

```
QC-17: BLUE LSB, row-major; verify archive reference AF-17.
```

This tells us to read the **least significant bit of the blue channel**, in row-major order.

---

### Step 3: Extract the blue LSB (a decoy again)
```python
from PIL import Image
import numpy as np

im = np.array(Image.open('afterimage.png').convert('RGB'))
bits = (im[:, :, 2] & 1).flatten()
data = np.packbits(bits[:len(bits)//8*8].reshape(-1, 8), axis=1).flatten().tobytes()
print(data[:200].decode(errors='replace'))
```

Output:
```
ARCHIVE DECOY: no flag here.
AF-17 calibration record:
Horizontal drift: 1
Vertical drift: 3
Sampling cycle: 17
Residual target: 0
Active sensor: G
```

The blue channel is a decoy, but it leaves us a **calibration record** that describes where the real data is:

| Field | Value | Meaning |
|-------|-------|---------|
| Horizontal drift | 1 | x coefficient |
| Vertical drift | 3 | y coefficient |
| Sampling cycle | 17 | modulus |
| Residual target | 0 | remainder to match |
| Active sensor | G | use the **green** channel |

---

### Step 4: Sample the green channel using the calibration record
Only pixels where `(1*x + 3*y) mod 17 == 0` carry data. We took the green LSB at just those pixels, in row-major order:

```python
from PIL import Image
import numpy as np

im = np.array(Image.open('afterimage.png').convert('RGB'))
H, W, _ = im.shape
ys, xs = np.mgrid[0:H, 0:W]

mask = ((1 * xs + 3 * ys) % 17 == 0)
g = im[:, :, 1] & 1
sel = g[mask]

n = len(sel) // 8 * 8
data = np.packbits(sel[:n].reshape(-1, 8), axis=1).flatten().tobytes()
print(data[:60])
```

Output (the bytes after the flag are random padding):
```
b'AIMG\x00(VOID{afterimage_pixels_are_the_evidence} ...'
```

The payload starts with an `AIMG` header followed by the flag.

---

## Flag
```
VOID{afterimage_pixels_are_the_evidence}
```
