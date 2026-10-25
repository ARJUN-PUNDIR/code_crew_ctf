# CTF Challenge Writeup: Left Behind

**Team:** Code Crew  
**Author:** [Akshat](https://github.com/akshat-xcode)  
**Category:** Forensics  
**Points:** 200  
**Flag:** `VOID{h1d_k3ystr0k3s}`  

---

## Challenge Description

> "Arlo Vance runs the server room at Halvorsen Logistics and trusts nothing that touches a network. His workstation is air-gapped, and his passwords live only in his head. During last night's audit, someone left a small device plugged in behind his desk. It sat there quietly until Arlo noticed it this morning and yanked it out. This file is all it left behind. Arlo insists there was nothing on it worth worrying about. Prove him wrong."

We were provided with a network capture file: `left_behind.pcapng`.

Flag format: `VOID{...}`

---

## File Identification & Forensics

| Property | Value |
| :--- | :--- |
| **Filename** | `left_behind.pcapng` |
| **File Size** | 110,524 bytes |
| **File Format** | PCAP Next Generation Capture File (`pcapng`) |
| **Link Layer Type** | `LINKTYPE_USB_LINUX_MMAPPED` (Linktype 220) |
| **Capture Origin** | Linux kernel `usbmon` subsystem |
| **Total Packets** | 1,100 Enhanced Packet Blocks (EPBs) |
| **SHA-256** | `e6ebca6440909a849acd6ed3889b22064b7ef7c3dc17682880bf38a654656e07` |

---

## Step-by-Step Solution

### Step 1: Identifying the Hardware Sniffer Traffic
Opening the capture file reveals it is not an Ethernet/IP capture, but a raw USB capture recorded using Linux's `usbmon` facility (Linktype 220).

Inspecting the USB descriptors in the initial setup/control transfers identified 4 active devices on the USB bus:
1. **Device 1:** Linux Foundation Root Hub (`VID 0x1d6b, PID 0x0002`)
2. **Device 2:** Intel Corp. Integrated Hub (`VID 0x8087, PID 0x0024`)
3. **Device 3:** Primax Electronics Optical Mouse (`VID 0x0461, PID 0x4d0f`) — 466 packets on EP `0x81`
4. **Device 4:** Logitech USB Keyboard (`VID 0x046d, PID 0xc31c`) — 72 interrupt packets on EP `0x81`

The small device plugged behind Arlo's desk was an inline hardware keylogger capturing USB traffic from **Device 4**.

---

### Step 2: Decoding USB HID Keyboard Reports
Device 4 sends standard 8-byte USB HID Keyboard Boot Protocol reports:
- **Byte 0:** Modifier bitmask (`0x02` = Left Shift, `0x20` = Right Shift, `0x04` = Left Alt)
- **Byte 1:** Reserved (`0x00`)
- **Bytes 2–7:** Up to 6 active key usage IDs (from the USB HID Usage Tables specification)

Keycodes of interest:
- `0x04` - `0x1d`: Letters `a` - `z` (or `A` - `Z` if Shift is held)
- `0x1e` - `0x27`: Numbers `1` - `0`
- `0x2a`: Backspace (`\b`)
- `0x2d`: `-` / `_`
- `0x2f`: `[` / `{`
- `0x30`: `]` / `}`

---

### Step 3: Handling Typo & Backspaces
Analyzing the raw keystroke sequence:
1. `VOID{h1d_` is typed.
2. The user types `wrong` (5 characters).
3. The user presses **Backspace 5 times** (`0x2a`), erasing `wrong`.
4. The user completes typing: `k3ystr0k3s}`.

Final reconstructed string:
```text
VOID{h1d_k3ystr0k3s}
```

---

## Reproducible Python Script

```python
import struct

PCAP_PATH = "left_behind.pcapng"

# Standard USB HID Keyboard Mapping
HID_MAP = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0a: ('g', 'G'), 0x0b: ('h', 'H'),
    0x0c: ('i', 'I'), 0x0d: ('j', 'J'), 0x0e: ('k', 'K'), 0x0f: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1a: ('w', 'W'), 0x1b: ('x', 'X'),
    0x1c: ('y', 'Y'), 0x1d: ('z', 'Z'), 0x1e: ('1', '!'), 0x1f: ('2', '@'),
    0x20: ('3', '#'), 0x21: ('4', '$'), 0x22: ('5', '%'), 0x23: ('6', '^'),
    0x24: ('7', '&'), 0x25: ('8', '*'), 0x26: ('9', '('), 0x27: ('0', ')'),
    0x2a: ('\b', '\b'), # Backspace
    0x2d: ('-', '_'),   0x2e: ('=', '+'), 0x2f: ('[', '{'), 0x30: (']', '}'),
    0x2b: ('\t', '\t'), 0x2c: (' ', ' ')
}

with open(PCAP_PATH, "rb") as f:
    raw = f.read()

offset = 0
prev_keys = set()
buffer = []

while offset < len(raw):
    bt, bl = struct.unpack("<II", raw[offset:offset+8])
    body = raw[offset+8 : offset+bl-4]
    
    # Enhanced Packet Block (EPB)
    if bt == 6:
        cap_len = struct.unpack("<I", body[12:16])[0]
        pkt = body[20:20+cap_len]
        
        # 64-byte Linux usbmon_packet header + payload
        if len(pkt) >= 72:
            urb_type = chr(pkt[8])
            epnum = pkt[10]
            devnum = pkt[11]
            payload = pkt[64:]
            
            # Device 4 = Keyboard, Endpoint 0x81 (IN interrupt transfer)
            if devnum == 4 and epnum == 0x81 and urb_type == 'C':
                mod = payload[0]
                shift = bool(mod & 0x22)
                curr_keys = set(k for k in payload[2:8] if k != 0)
                new_keys = curr_keys - prev_keys
                
                for k in new_keys:
                    if k in HID_MAP:
                        char = HID_MAP[k][1] if shift else HID_MAP[k][0]
                        if char == '\b':
                            if buffer:
                                buffer.pop()
                        elif not (mod & 0x44): # Ignore system Alt combos
                            buffer.append(char)
                prev_keys = curr_keys
                
    offset += bl

print(f"[+] Recovered Flag: {''.join(buffer)}")
```

Output:
```text
[+] Recovered Flag: VOID{h1d_k3ystr0k3s}
```
