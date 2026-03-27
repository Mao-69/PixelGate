# PIXELGATE + Illegal Prime Encoder
- Hide arbitrary files inside images using mathematically illegal primes.

<img width="1150" height="863" alt="Screenshot 2026-03-27 at 00-15-43 PIXELGATE" src="https://github.com/user-attachments/assets/5dba1585-1f1e-4e66-a9d3-7e8ea6bc435f" />

### Overview
- This repository contains two complementary tools that together let you encode any data as a prime number and hide that prime inside a pixelated image using steganography.

### iLLPrime
- (C program) — Encodes any file or text as a large prime number using Phil Carmody’s “illegal prime” technique.

### PIXELGATE
- (single-file web app) — Pixelates an image and hides the prime inside it via LSB steganography. Also extracts and recovers the original file from the image.

Together they allow you to turn any file (source code, documents, images, etc.) into a mathematically interesting prime that can be secretly embedded in a seemingly innocent pixel-art image.

# 2. PIXELGATE Web App
- Pixelates your image with configurable block size and gaps.
Embeds the large prime (from the C tool) into the red-channel LSBs of the pixelated image.
Extracts the prime from any steg-encoded PNG.
Automatically decompresses the Carmody prime and shows the recovered original content (with line numbers for text files) or offers a download for binary files.

No server required — everything runs in your browser.
<img width="1163" height="879" alt="Screenshot 2026-03-27 at 00-18-30 PIXELGATE" src="https://github.com/user-attachments/assets/c04f8159-9ae3-4b1e-9316-c81652343309" />

### Generate an Illegal Prime to encode
```
git clone https://github.com/Mao-69/PixelGate.git
```
```
cd PixelGate
```
```
gcc -O2 -o iLLPrime iLLPrime.c -lz -lssl -lcrypto -lpthread -lm
```
```
./iLLPrime -t "we are everywhere" -o test.prime -p full
```
- or you could generate a prime from a file, img, source code, etc ...
```
./iLLPrime -f file.c -o file.prime -p full
```
<img width="914" height="749" alt="everywhere" src="https://github.com/user-attachments/assets/e7128b51-7076-4aee-8c32-30588a2c9ce5" />

- Using iLLPrime to recover content from the prime 4015900675360164941251164573085381583763085502225938239902804756060548864700681100564889637
```
./iLLPrime -f test.prime | gunzip
```
```
We are everywhere
```

# Example using the Web App with source code

### Example using a Prime generated from Lockr.c source code

<img width="1156" height="884" alt="Screenshot 2026-03-27 at 00-51-52 PIXELGATE" src="https://github.com/user-attachments/assets/aff42513-0a84-4e96-93eb-3eac0960f8d4" />

- with this you can see the recovered source code for lockr.c
<img width="615" height="407" alt="source" src="https://github.com/user-attachments/assets/cc5c5699-c8cc-43b3-9bfd-2beb93cee051" />

