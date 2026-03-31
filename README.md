# CS333 Lab 4 – thread_hash

## Overview
`thread_hash` is a multithreaded password cracker written in C. It compares hashed passwords against a dictionary using `crypt_r()` and distributes the work across threads.

Supported algorithms:
DES, NT, MD5, SHA256, SHA512, YESCRYPT, GOST_YESCRYPT, BCRYPT

---

## Files
- `thread_hash.c` – main program
- `thread_hash.h` – constants and enums
- `Makefile` – build rules

---

## Build

```bash
make
```

---

## Usage
```bash
./thread_hash -i hashes.txt -d words.txt [options]
```

### Required
-i <file> : hashed passwords

-d <file> : dictionary words

### Optional
```
-o <file> : output file (default stdout)

-t <num> : threads (default 1, max 24)

-v : verbose mode

-n : apply nice value

-h : help
```
