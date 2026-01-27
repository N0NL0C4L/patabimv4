# PATABIM v4.0

Python3 bytecode packer with multi-layer cryptographic protection.

## Stack

* **Encryption:** AES-256-GCM
* **Key Derivation:** PBKDF2-HMAC-SHA256
* **Identity:** RSA-3072 Digital Signature (PKCS#1 v1.5).

## Quick Start

1. **Generate Keys:**
```bash
python patabimv4.py gen-keys --bits 3072

```

2. **Set Public Key:**
```bash
cp keys/public_key.pem __patabim__/_ptbm.pem

```

3. **Pack Script:**
```bash
python patabimv4.py pack-py input.py output_packed.py keys/private_key.pem

```
# OR
```bash
python patabimv4.py pack-bin input.py output_packed keys/private_key.pem

```

### Disclaimer
If you are here to decompile this, try it on. If you can, contact me via:

* **Discord:** `@n0nl0c4l`
* **ProtonMail:** `n0nl0c4l@protonmail.com`
* **Telegram:** `t.me/n0nl0c4l`


[![VirusTotal Scan](https://img.shields.io/badge/VirusTotal-Clean-brightgreen)](https://www.virustotal.com/gui/file/5dc96c1e6757553a76b959b64c73e2df2631525df7f08ba1df7f4c1d3d13d5a5/detection)
