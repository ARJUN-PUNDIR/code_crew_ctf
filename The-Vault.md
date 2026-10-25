# CTF Challenge Writeup: The Vault

**Team:** Code Crew  
**Author:** Arjun Singh Pundir

**Challenge Name:** The Vault  

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
