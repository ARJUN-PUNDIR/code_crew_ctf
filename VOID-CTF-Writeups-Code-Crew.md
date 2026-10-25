# VOID CTF – Writeups

**Team:** Code Crew  
**Author:** Arjun Singh Pundir  
**Categories:** Steganography, Reverse Engineering

---

# CTF Challenge Writeup: The Vault

**Challenge Name:** The Vault  
**Points:** <add points>

---

## Challenge Description
We were given a single image, `challenge.jpg`, with the following story:

> "Our operatives intercepted a suspicious photograph from a rogue operative's terminal. Headquarters suspects there's more to this picture than meets the eye. They claim they left some sensitive files behind, but looking at the pixels alone won't save us. Can you dig beneath the surface and crack open The Vault?"

Flag format: `VOID{...}`

The hint "looking at the pixels alone won't save us" suggests the data is hidden *around* the image, not inside its pixels.

---

## Step-by-Step Solution

### Step 1: Check the file and its metadata
```bash
file challenge.jpg
```

`file` reported a JPEG with a **comment** field:

```
comment: "Qmkxa00zR0VoaHdjVlZ1blUyTHJjeWNMeE1QVkVnaVM3VDMyODZTQ0VCYkZoNWdkZE1LQg=="
```

---

### Step 2: Decode the comment (a decoy)
The comment is Base64. Decoding it gives another string:

```bash
echo "Qmkxa00zR0VoaHdjVlZ1blUyTHJjeWNMeE1QVkVnaVM3VDMyODZTQ0VCYkZoNWdkZE1LQg==" | base64 -d
```

```
Bi1kM3GEhhwcVVunU2LrcycLxMPVEgiS7T3286SCEBbFh5gddMKB
```

This uses only Base58 characters, so we decoded it with Python:

```python
A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s = "Bi1kM3GEhhwcVVunU2LrcycLxMPVEgiS7T3286SCEBbFh5gddMKB"
n = 0
for c in s:
    n = n * 58 + A.index(c)
print(n.to_bytes((n.bit_length() + 7) // 8, 'big'))
```

Output:
```
b'Haha... nice try. But this is a decoy.'
```

So the comment was a trap, and the real data is somewhere else.

---

### Step 3: Look for data appended after the image
Running `strings` on the file showed file names near the end of it: `01_hidden.txt`, `02_hidden.txt`, `03_hidden.txt`. That means a **ZIP archive is appended after the JPEG data**. We located the ZIP signature (`PK\x03\x04`) and carved it out:

```python
d = open('challenge.jpg', 'rb').read()
i = d.find(b'PK\x03\x04')
open('emb.zip', 'wb').write(d[i:])
```

```bash
unzip emb.zip
```

The archive was not password protected and contained three files.

---

### Step 4: Identify the real file types
Although the files are named `.txt`, `file` showed they are images:

```bash
file 01_hidden.txt 02_hidden.txt 03_hidden.txt
```

| File | Real type | Content |
|------|-----------|---------|
| `01_hidden.txt` | JPEG | Desert dunes photo |
| `02_hidden.txt` | JPEG | Autumn waterfall photo |
| `03_hidden.txt` | PNG (1536x1024) | Wasteland scene with a power plant and a tattered flag |

We renamed `03_hidden.txt` to `03.png` and opened it. The text on the flag in the picture is the flag.

<!-- add screenshot: 03.png -->

---

## Flag
```
VOID{the_picture_was_inside_the_picture}
```

> Note: the text wraps over two lines on the banner (`VOID{the_picture_was` / `inside_the_picture}`). Join the lines with an underscore.

---
---

# CTF Challenge Writeup: Afterimage

**Challenge Name:** Afterimage  
**Points:** <add points>

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

---
---

# CTF Challenge Writeup: QR Fragments

**Challenge Name:** <add challenge name>  
**Category:** Steganography / Forensics  
**Points:** <add points>

---

## Challenge Description
We were given **12 image fragments** (`fragment_01` ... `fragment_12`). They are pieces of more than one picture, and not every signal in them is real.

---

## Step-by-Step Solution

### Step 1: Work out the layout
The 12 fragments assemble into **two separate 600x600 QR codes**. Each QR code is a **3x2 grid** (3 columns, 2 rows) of 200x300 fragments. Checking edge continuity and the padding around each tile shows which fragments belong together and in what order.

---

### Step 2: Reassemble Signal 1
Layout (row by row, left to right):

| | Col 1 | Col 2 | Col 3 |
|---|---|---|---|
| **Row 1** | fragment_03 | fragment_01 | fragment_09 |
| **Row 2** | fragment_02 | fragment_06 | fragment_11 |

Scanning the reassembled QR code gives:
```
VOID{s33_th3_wh0l3_p1ctur3}
```

---

### Step 3: Reassemble Signal 2
Layout:

| | Col 1 | Col 2 | Col 3 |
|---|---|---|---|
| **Row 1** | fragment_04 | fragment_07 | fragment_05 |
| **Row 2** | fragment_10 | fragment_12 | fragment_08 |

Scanning this QR code gives:
```
VOID{n0t_3v3ry_s1gn4l_1s_r34l}
```

---

### Step 4: Separate the real signal from the decoy
Signal 2 reads "not every signal is real", so it announces that it is the decoy transmission. Signal 1 reads "see the whole picture", which is what you get by putting all the fragments back together correctly. Signal 1 is the real flag.

---

## Flag
```
VOID{s33_th3_wh0l3_p1ctur3}
```

---
---

# CTF Challenge Writeup: chall (LoongArch Reverse Engineering)

**Challenge Name:** chall  
**Category:** Reverse Engineering  
**Points:** <add points>

---

## Challenge Description
We were given a 64-bit **LoongArch ELF binary**, `chall`, and the output it produces for the correct 30-character input:

```
-655162063 -838009797 232397087 -1738908707 -468405423 -143659455 1211474117 1874553211 -143659455 -489127571 288734813 1211474117 -921521839 2076262653 288734813 -607311 -582423 -686361 -280503 -274485 -717267 -607311 -672693 -301005 -301005 -197883 -197883 -197883 -197883 -826611
```

The goal is to recover the input, which is the flag.

---

## Step-by-Step Solution

### Step 1: Reverse the binary
Reversing the binary shows how an input of length 30 is transformed. `arr` below is the array of the input's character codes.

**`func_8bc` (left = 0, right = 29, len = 30)**
- Indices 0 to 3: `arr[i] = arr[i] - 299`
- Index 4: unchanged
- Indices 5 to 29: `arr[j] = arr[j] * 67`
- It then splits the array at `mid = 15`, calling `func_a80(arr, 0, 14)` on the first half and `func_c44(arr, 15, 29)` on the second half.

**First half, `func_a80` (indices 0 to 14)**
```
arr[k] = (arr[k] * 0x9e3779b1 + 123) mod 2^32
```

**Second half, `func_c44` (indices 15 to 29)**
```
arr[j] = 17 * ((arr[j] ^ 912) ^ 91) = 17 * (arr[j] ^ 971)
```

**Final step in `main` (for all i from 0 to 29)**
```
v2        = (6 * (arr[i] + 7)) mod 2^32
output[i] = (~v2) + 100000
```

---

### Step 2: Invert the output step
From `output` back to `arr`:

```
v2 = ~(output[i] - 100000)  (mod 2^32)
```

`v2` is even, so `v2 / 2 = 3 * (arr[i] + 7) (mod 2^31)`. We invert this modulo 2^31 (this leaves two candidates modulo 2^32).

---

### Step 3: Invert the first half (indices 0 to 14)
- Undo the affine step using the modular inverse `0x9e3779b1^-1 = 0x0e8b2f51 (mod 2^32)`.
- Add 299 back for indices 0 to 3.
- Divide by 67 for indices 5 to 14.

This gives:
```
VOID{1_l1k3_ic3
```

---

### Step 4: Invert the second half (indices 15 to 29)
- Divide by 17.
- XOR with 971.
- Divide by 67.

This gives:
```
_cr34m_t00!!!!}
```

---

### Step 5: Check the result
Running the forward algorithm on the recovered string reproduces all 30 output values exactly.

---

## Flag
```
VOID{1_l1k3_ic3_cr34m_t00!!!!}
```
