# CTF Challenge Writeup: Volatile Mira

**Team:** Code Crew  
**Author:** [Akshat](https://github.com/akshat-xcode)  
**Category:** Forensics  
**Points:** 300  
**Flag:** `VOID{f0r3n51c5_15_4n_4r7}`  

---

## Challenge Description

> "Mira never writes secrets to disk. 'Disk is evidence,' she wrote in her diary. 'RAM forgets.' Her notes daemon keeps everything encrypted in memory, and she swears the key never sits next to the vault. When her laptop went dark, our responder didn't pull the plug. She grabbed a full image of the machine's RAM first. Mira was wrong about one thing: RAM forgets only when the power goes. Find what she was hiding."

We were provided with a compressed memory dump archive: `mem.rar`.

Flag format: `VOID{...}`

---

## Memory Artifact Identification

| Property | Value |
| :--- | :--- |
| **Archive** | `mem.rar` (78,396,448 bytes) |
| **Extracted Image** | `mem.lime` (2,147,019,840 bytes / 2.0 GB) |
| **Acquisition Format** | **LiME (Linux Memory Extractor)** format v1 |
| **Magic Header** | `45 4d 69 4c` (`0x4C694D45` / `EMiL` little-endian) |
| **Target OS / Host** | Kali GNU/Linux (x86_64) |
| **SHA-256 (`mem.rar`)** | `ed1e486b35e2d0c0c6b85549e3c7962e5d6f4ffc5e2924dcee542e8ff881db89` |

---

## Step-by-Step Solution

### Step 1: Identifying the In-Memory Notes Daemon
We scanned the memory image for references to `mira`, `vault`, and python script buffers.
At physical offset `0x301E8FDB`, we recovered the Python source code of Mira's memory resident daemon (`/opt/mira/heartbeat.py`):

```python
# Mira's "encrypted notes sync" daemon. Holds the XOR-encrypted flag in memory.
# Only ciphertext lives here: the plaintext flag never exists in the VM.
import time
SEALED = bytes.fromhex("632c7f761e530146035b020402566804003c025c3a0143034d")
# The marker makes the blob findable in the process dump.
# Hard mode: remove the marker so solvers must XOR-scan the dump for "VOID{".
vault = bytearray(b"MIRA-VAULT::" + SEALED + b"::END")
while True:
    time.sleep(60)  # stay alive so the process is in pslist at capture time
```

Ciphertext recovered:
`SEALED = bytes.fromhex("632c7f761e530146035b020402566804003c025c3a0143034d")` (25 bytes)

---

### Step 2: Locating the Key ("The key never sits next to the vault")
The prompt noted:
> *"she swears the key never sits next to the vault."*

Since the key was not hardcoded in the script or in the vault array, it had to be supplied from outside at runtime.

We searched memory for process argument vectors (`mm_struct->arg_start`), bash command histories, and `/proc/[pid]/cmdline` allocations.
At offsets `0x13FFD4B6` and `0x15978CDD`, we discovered the exact execution command:

```bash
./launch.sh 5c62e5140575ac75
shred -u launch.sh
python3 /opt/mira/heartbeat.py --session-token 5c62e5140575ac75 --interval 60
```

The encryption key is the session token:
```text
Key: 5c62e5140575ac75 (16 ASCII bytes)
```

---

### Step 3: Decrypting the Sealed Vault
The encryption scheme is repeating-key XOR ($P_i = C_i \oplus K_{i \pmod{16}}$).

#### Byte-by-Byte Decryption Trace:
| Index $i$ | Cipher Byte $C_i$ | Key Byte $K_{i \pmod{16}}$ | Plaintext Char $P_i$ |
|:---:|:---:|:---:|:---:|
| 0 | `0x63` | `'5'` (`0x35`) | **V** |
| 1 | `0x2c` | `'c'` (`0x63`) | **O** |
| 2 | `0x7f` | `'6'` (`0x36`) | **I** |
| 3 | `0x76` | `'2'` (`0x32`) | **D** |
| 4 | `0x1e` | `'e'` (`0x65`) | **{** |
| 5 | `0x53` | `'5'` (`0x35`) | **f** |
| 6 | `0x01` | `'1'` (`0x31`) | **0** |
| 7 | `0x46` | `'4'` (`0x34`) | **r** |
| 8 | `0x03` | `'0'` (`0x30`) | **3** |
| 9 | `0x5b` | `'5'` (`0x35`) | **n** |
| 10 | `0x02` | `'7'` (`0x37`) | **5** |
| 11 | `0x04` | `'5'` (`0x35`) | **1** |
| 12 | `0x02` | `'a'` (`0x61`) | **c** |
| 13 | `0x56` | `'c'` (`0x63`) | **5** |
| 14 | `0x68` | `'7'` (`0x37`) | **_** |
| 15 | `0x04` | `'5'` (`0x35`) | **1** |
| 16 | `0x00` | `'5'` (`0x35`) | **5** |
| 17 | `0x3c` | `'c'` (`0x63`) | **_** |
| 18 | `0x02` | `'6'` (`0x36`) | **4** |
| 19 | `0x5c` | `'2'` (`0x32`) | **n** |
| 20 | `0x3a` | `'e'` (`0x65`) | **_** |
| 21 | `0x01` | `'5'` (`0x35`) | **4** |
| 22 | `0x43` | `'1'` (`0x31`) | **r** |
| 23 | `0x03` | `'4'` (`0x34`) | **7** |
| 24 | `0x4d` | `'0'` (`0x30`) | **}** |

---

## Reproducible Python Script

```python
SEALED = bytes.fromhex("632c7f761e530146035b020402566804003c025c3a0143034d")
KEY = b"5c62e5140575ac75"

flag = bytes([c ^ KEY[i % len(KEY)] for i, c in enumerate(SEALED)])
print(f"[+] Recovered Flag: {flag.decode('utf-8')}")
```

Output:
```text
[+] Recovered Flag: VOID{f0r3n51c5_15_4n_4r7}
```
