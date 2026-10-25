# CTF Challenge Writeup: A Sealed Record

**Team:** Code Crew  
**Author:** [Akshat](https://github.com/akshat-xcode)  
**Category:** Forensics  
**Points:** 300  
**Flag:** `VOID{crc_r3v34ls_th3_tru3_h31ght}`  

---

## Challenge Description

> "An evidence image came in from intake, but something's off — a few tools refuse to open it at all. The analyst who logged it left one note: 'the tag was rewritten after sealing. the seal still remembers the original. trust the seal, not the tag.' Recover the record."

We were provided with an archive: `Artifact-BC34.rar`.

Flag format: `VOID{...}`

---

## File Identification & Forensics

### Outer Archive (`Artifact-BC34.rar`)
* **Format:** RAR 5.0 Archive
* **Signature:** `52 61 72 21 1A 07 01 00` (`Rar!\x1a\x07\x01\x00`)
* **SHA-256:** `9267c6daad76ec2da7849c7d70ff0069e520df5ce260b039cb92c6591fa6fff5`
* **Contained File:** `Artifact-BC34.png`

### Evidence Image (`Artifact-BC34.png`)
* **Format:** Portable Network Graphics (PNG)
* **Signature:** `89 50 4E 47 0D 0A 1A 0A`
* **File Size:** 6,343,346 bytes
* **Tampered Dimensions:** $2464 \times 1607\text{ px}$
* **Original Dimensions:** $2464 \times 1728\text{ px}$

---

## Step-by-Step Solution

### Step 1: Analyzing the Analyst's Clue
The intake note says:
> *"the tag was rewritten after sealing. the seal still remembers the original. trust the seal, not the tag."*

In the PNG format:
- Each chunk has a **4-byte chunk type** (e.g. `IHDR`) and chunk data.
- Following the chunk data is a **4-byte CRC-32 checksum** ("the seal") calculated over chunk type + data.
- The `IHDR` chunk contains width (4 bytes), height (4 bytes), bit depth, color type, compression, filter, and interlace methods.

When strict image viewers or forensic parsers attempted to render `Artifact-BC34.png`, they threw a CRC mismatch error on the `IHDR` chunk because the height field had been modified without recalculating the CRC.

---

### Step 2: Comparing Stored CRC vs Calculated CRC
Examining the `IHDR` chunk in a hex editor:
- Width: `00 00 09 A0` ($2464\text{ px}$)
- Stored Height: `00 00 06 47` ($1607\text{ px}$)
- Other fields: `08 02 00 00 00` (8-bit Truecolor)
- Stored CRC-32 checksum: `0x14C4F49F`

Calculating the CRC-32 of `IHDR` with height $1607\text{ px}$ gives `0x1771D0FF`, which **does not match** `0x14C4F49F`.

---

### Step 3: Brute-Forcing the Original Height via CRC-32
Because "the seal still remembers the original", we brute-forced the height parameter against the valid stored CRC `0x14C4F49F`:

```python
import struct, zlib

width = 2464
stored_crc = 0x14C4F49F

for h in range(1, 10000):
    ihdr_payload = b'IHDR' + struct.pack('>IIBBBBB', width, h, 8, 2, 0, 0, 0)
    if zlib.crc32(ihdr_payload) == stored_crc:
        print(f"[+] True original height: {h} (0x{h:08X})")
        break
```

Output:
```text
[+] True original height: 1728 (0x000006C0)
```

The image height had been artificially truncated by **121 vertical pixels** ($1728 - 1607 = 121$).

---

### Step 4: Repairing the PNG & Revealing the Flag
We patched bytes `0x14 - 0x17` from `00 00 06 47` to `00 00 06 C0`.

Opening the restored image reveals the previously hidden 121 bottom rows displaying an intake evidence terminal banner:
```text
recovered record:
VOID{crc_r3v34ls_th3_tru3_h31ght}
```

---

## Reproducible Python Script

```python
import struct
import zlib

png_file = "Artifact-BC34.png"
repaired_file = "Artifact-BC34-repaired.png"

with open(png_file, "rb") as f:
    data = bytearray(f.read())

assert data[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG header"

# IHDR fields
width = struct.unpack(">I", data[16:20])[0]
tampered_h = struct.unpack(">I", data[20:24])[0]
stored_crc = struct.unpack(">I", data[29:33])[0]

print(f"[+] Current Dimensions: {width} x {tampered_h}")
print(f"[+] Stored CRC: {hex(stored_crc)}")

# Recover original height
true_h = None
for candidate_h in range(1, 10000):
    ihdr_payload = b'IHDR' + struct.pack(">IIBBBBB", width, candidate_h, 8, 2, 0, 0, 0)
    if zlib.crc32(ihdr_payload) == stored_crc:
        true_h = candidate_h
        break

if true_h:
    print(f"[+] Found True Height: {true_h}")
    # Patch height in binary data
    data[20:24] = struct.pack(">I", true_h)
    with open(repaired_file, "wb") as f:
        f.write(data)
    print(f"[+] Saved repaired image to {repaired_file}")
else:
    print("[-] Height recovery failed")
```
