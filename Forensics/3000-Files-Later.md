# CTF Challenge Writeup: 3000 Files Later

**Team:** Code Crew  
**Author:** [Akshat](https://github.com/akshat-xcode)  
**Category:** Forensics  
**Points:** 500  
**Flag:** `VOID{y0u_ch3ck3d_3000_f1l3s_f0r_th1s_021959f6}`  

---

## Challenge Description

> "Someone poured their whole life into a zip file. Thousands of flags, every one of them convincing. They swear only one is real, and that they left a way to prove it. Note - Before you start grepping: they saw you coming."

We were provided with a ZIP archive: `3000_files_later.zip`.

Flag format: `VOID{...}`

---

## File Identification & Forensics

| Property | Value |
| :--- | :--- |
| **Filename** | `3000_files_later.zip` |
| **Archive Size** | 693,520 bytes |
| **Total Files** | 3,369 files (across 256 subdirectories) |
| **File Contents** | Base64-encoded strings matching `VOID{...}` |
| **SHA-256** | `6e9f1502d2253d1d4c6e7569dbfa89229f7b05ca04816e0cf6ebeb481fa760eb` |

---

## Step-by-Step Solution

### Step 1: Examining the Decoy Minefield
Extracting the archive reveals 3,369 text files, all containing Base64 strings. Decoding any file produces a convincing flag candidate, e.g.:
- `VOID{m3m0ry_l34k_f1x_d7a8e291}`
- `VOID{c4ch3_m1ss_3rr0r_5f2b8a1c}`

Grepping for `VOID{` yields over 3,000 matches. As the challenge author noted: *"they saw you coming."* There must be a mathematical or metadata verification mechanism that differentiates the authentic flag from the decoys.

---

### Step 2: The Archive Comment Clue
We inspected the ZIP archive header comments:

```python
import zipfile
zf = zipfile.ZipFile("3000_files_later.zip")
print(zf.comment.decode())
```

Output:
> `Ask the one that marks the beginning of an era how to sign. Trust the youngest who bears the mark.`

---

### Step 3: "The one that marks the beginning of an era"
In the MS-DOS/FAT timestamp format used by ZIP files, the earliest representable timestamp (the epoch) is:
```text
1980-01-01 00:00:00
```

Scanning all 3,369 entries for the minimum timestamp finds exactly one file:
- **Path:** `ae/4a/d9dc427dacb85135.txt`
- **Timestamp:** `1980-01-01 00:00:00`
- **Decoded Content:** `VOID{my_t41l_th3n_y0ur_b0dy_sha256_f1rst_8_1s_y0ur_t41l_1e7ea419}`

This file reveals the signing rule:
1. `my_t41l` = `1e7ea419`
2. Each candidate flag has structure: `VOID{<body_without_tail>_<tail>}`
3. The valid signature formula:
   $$\text{Expected Tail} = \operatorname{SHA256}(\mathtt{"1e7ea419"} \,\|\, \text{body})[0:8]$$

---

### Step 4: Filtering Candidate Flags
We evaluated all 3,369 files against this SHA-256 signature verification rule.
Exactly **8 files** in the entire archive "bear the mark" (valid signature):

| Modification Timestamp | File Path | Flag Content |
|:---:|:---|:---|
| 2004-03-07 21:51:16 | `5a/3b/b517d9196b0521aa.txt` | `VOID{0ld_sch00l_fl4g_s1gn_d2c88f11}` |
| 2006-11-12 14:20:02 | `1f/c2/a7e3d1c8b9a04f21.txt` | `VOID{b1t_sh1ft_m4st3r_c4b910e5}` |
| 2008-08-19 09:15:44 | `8c/41/d0298be5f123ac78.txt` | `VOID{st4ck_0v3rfl0w_c0ur13r_fa22d861}` |
| 2010-01-25 18:42:10 | `3d/7a/e9821bf40c1157d3.txt` | `VOID{k3rn3l_p4n1c_h4ndl3r_88e04b12}` |
| 2011-06-30 04:05:58 | `92/e5/f83726ab5c010a34.txt` | `VOID{crypt0_k3y_r0t4t10n_9cb72e04}` |
| 2013-09-14 22:11:30 | `d4/12/38e9b0cd47f128bc.txt` | `VOID{s3cur3_v4ult_pr0t0c0l_374fa90c}` |
| 2014-10-03 11:55:18 | `0e/88/47a29dc5e01f6542.txt` | `VOID{p4ck3t_dr0p_4n4lys1s_4a19cb7d}` |
| **2015-02-04 06:30:32** | `b1/ab/54b611bcdb191433.txt` | `VOID{y0u_ch3ck3d_3000_f1l3s_f0r_th1s_021959f6}` |

---

### Step 5: "Trust the youngest who bears the mark"
The youngest (most recently timestamped) file among the 8 signed candidates is:
- **Timestamp:** `2015-02-04 06:30:32`
- **File:** `b1/ab/54b611bcdb191433.txt`
- **Body:** `y0u_ch3ck3d_3000_f1l3s_f0r_th1s`
- **Verification:**
  $$\operatorname{SHA256}(\mathtt{"1e7ea419y0u\_ch3ck3d\_3000\_f1l3s\_f0r\_th1s"}) = \mathtt{\mathbf{021959f6}cebd...}$$
- **Tail:** `021959f6` (Exact match)

---

## Reproducible Python Script

```python
import zipfile
import base64
import hashlib
import datetime

ZIP_PATH = "3000_files_later.zip"

with zipfile.ZipFile(ZIP_PATH, 'r') as zf:
    # 1. Print comment
    print(f"[+] ZIP Comment: {zf.comment.decode('utf-8')}")

    # 2. Find beginning of era (DOS epoch 1980-01-01)
    epoch_entry = min(zf.infolist(), key=lambda x: datetime.datetime(*x.date_time))
    epoch_content = base64.b64decode(zf.read(epoch_entry.filename).strip()).decode('utf-8')
    print(f"[+] Epoch File: {epoch_entry.filename} ({datetime.datetime(*epoch_entry.date_time)})")
    print(f"[+] Rule Template: {epoch_content}")

    my_tail = epoch_content[5:-1].rsplit("_", 1)[1]

    # 3. Find all files bearing the mark
    signed_candidates = []
    for info in zf.infolist():
        try:
            content = base64.b64decode(zf.read(info.filename).strip()).decode('utf-8')
        except Exception:
            continue

        if content.startswith("VOID{") and content.endswith("}"):
            inner = content[5:-1]
            if "_" in inner:
                body, tail = inner.rsplit("_", 1)
                if len(tail) == 8:
                    expected_tail = hashlib.sha256((my_tail + body).encode()).hexdigest()[:8]
                    if expected_tail.lower() == tail.lower():
                        dt = datetime.datetime(*info.date_time)
                        signed_candidates.append((dt, info.filename, content))

    # 4. Sort by timestamp descending to get the youngest
    signed_candidates.sort(key=lambda x: x[0])
    youngest = signed_candidates[-1]

    print("\n[+] All 8 Signed Files:")
    for dt, fn, flg in signed_candidates:
        print(f"  [{dt}] {fn} -> {flg}")

    print(f"\n[+] Authentic Flag (Youngest): {youngest[2]}")
```

Output:
```text
[+] Authentic Flag (Youngest): VOID{y0u_ch3ck3d_3000_f1l3s_f0r_th1s_021959f6}
```
