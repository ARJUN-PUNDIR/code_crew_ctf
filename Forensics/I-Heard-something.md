# CTF Challenge Writeup: I Heard something

**Team:** Code Crew  
**Author:** [Akshat](https://github.com/akshat-xcode)  
**Category:** Forensics  
**Points:** 100  
**Flag:** `VOID{y0u_c4n7_h34r_m3}`  

---

## Challenge Description

> "Mira left a voice note on her desktop called 'whisper.' It's just a tune. Or is it? Some things are only meant for machines to hear."

We were provided with an audio file (`whisper.wav`).

Flag format: `VOID{...}`

---

## Technical Properties

| Property | Value |
| :--- | :--- |
| **File Format** | Microsoft WAV (RIFF `WAVE`, uncompressed PCM) |
| **File Size** | 1,058,444 bytes |
| **Audio Channels** | 1 (Mono) |
| **Bit Depth** | 16-bit signed PCM (`int16`, little-endian) |
| **Sampling Rate** | 44,100 Hz (Nyquist limit: 22,050 Hz) |
| **Duration** | 12.000 seconds (529,200 samples) |

---

## Step-by-Step Solution

### Step 1: Initial Container Inspection & Metadata Audit
We inspected the RIFF chunk headers and tested whether any extra data was appended after the `data` chunk:

```bash
file whisper.wav
exiftool whisper.wav
```

The RIFF container matched its declared file size exactly, and no suspicious metadata tags or appended payload strings were found in the header chunks.

### Step 2: Time-Domain & LSB Steganography Check
We inspected the raw PCM sample values for standard least-significant-bit (LSB) steganographic encoding. Extracting the LSBs across byte alignments showed typical uniform noise distribution and natural audio entropy, with no file signatures or text strings.

### Step 3: Frequency-Domain (Spectrogram) Analysis
The hint stated:
> *"Some things are only meant for machines to hear."*

Human hearing generally extends up to ~15–17 kHz for adults, while digital audio sampled at 44.1 kHz can represent frequencies up to the Nyquist limit of 22,050 Hz.

We performed a Short-Time Fourier Transform (STFT) across the entire spectrum (0 Hz to 22.05 kHz). While the audible acoustic tune was concentrated in the low-frequency region ($0 - 1.5\text{ kHz}$), a clear synthetic spectral drawing appeared in the **high-frequency ultrasonic band between 16.3 kHz and 19.3 kHz**:

- **Start ($t \approx 2.05\text{ s}$):** `VOID{`
- **Body ($t \approx 3.0\text{ s} - 9.0\text{ s}$):** Visual glyphs spelling `y0u_c4n7_h34r_m3` (with distinct horizontal bar strokes for underscores `_` at ~16.4 kHz)
- **End ($t \approx 9.9\text{ s}$):** `}`

---

## Reproducible Python Script

```python
import numpy as np
import scipy.io.wavfile as wavfile
import matplotlib.pyplot as plt

# 1. Load the challenge audio file
sr, data = wavfile.read("whisper.wav")

# 2. Generate high-frequency zoomed spectrogram
plt.figure(figsize=(14, 6))
Pxx, freqs, bins, im = plt.specgram(
    data,
    NFFT=2048,
    Fs=sr,
    noverlap=1024,
    cmap='viridis'
)

# Focus on the ultrasonic band
plt.ylim(15000, 21000)
plt.title("High-Frequency Spectrogram (15 kHz - 21 kHz)")
plt.xlabel("Time (seconds)")
plt.ylabel("Frequency (Hz)")
plt.colorbar(im, label="Intensity (dB)")
plt.tight_layout()
plt.savefig("flag_spectrogram.png", dpi=300)
plt.show()
```

Opening the resulting spectrogram clearly displays:
```text
VOID{y0u_c4n7_h34r_m3}
```
