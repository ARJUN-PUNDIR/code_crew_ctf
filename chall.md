# CTF Challenge Writeup: chall (LoongArch Reverse Engineering)

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** chall  
**Category:** Reverse Engineering  

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
