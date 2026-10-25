# CTF Challenge Writeup: QR Fragments

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** <add challenge name>  
**Category:** Steganography / Forensics  

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
