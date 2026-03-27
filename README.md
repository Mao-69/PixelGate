# PIXELGATE + Illegal Prime Encoder
- Hide arbitrary files inside images using mathematically illegal primes.

<img width="1150" height="863" alt="Screenshot 2026-03-27 at 00-15-43 PIXELGATE" src="https://github.com/user-attachments/assets/5dba1585-1f1e-4e66-a9d3-7e8ea6bc435f" />

# Overview
- This repository contains two complementary tools that together let you encode any data as a prime number and hide that prime inside a pixelated image using steganography.

# iLLPrime
- (C program) — Encodes any file or text as a large prime number using Phil Carmody’s “illegal prime” technique.
- 
# PIXELGATE
- (single-file web app) — Pixelates an image and hides the prime inside it via LSB steganography. Also extracts and recovers the original file from the image.

Together they allow you to turn any file (source code, documents, images, etc.) into a mathematically interesting prime that can be secretly embedded in a seemingly innocent pixel-art image.



```
git clone https://github.com/Mao-69/PixelGate.git
```
```
cd PixelGate
```
```
gcc -O2 -o primer primer.c -lz -lssl -lcrypto -lpthread -lm
```
