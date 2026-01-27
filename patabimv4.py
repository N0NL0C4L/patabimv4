#!/usr/bin/env python3
# https://github.com/N0NL0C4L

import os
import platform
import struct
import argparse
import random
import base64
import getpass
import zlib
from distutils import dir_util
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as asym_hashes
from cryptography.hazmat.primitives.asymmetric import rsa

MAGIC = b'PTBMv4.0'  # must match loader
MAGIC2 = b'\x1c\x8f\xd2\xcf\x07\x89\xb7\xce'
KDF_ITERATIONS = 200000

def derive_key(password: bytes, salt: bytes, length=32, iterations=KDF_ITERATIONS):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password)

def gen_rsa_keys(private_path: str = "private_key.pem", public_path: str = "public_key.pem", bits: int = 3072):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if not os.path.isdir("resutls"):
        os.mkdir("keys")

    Path("keys/" + private_path).write_bytes(priv_pem)
    Path("keys/" + public_path).write_bytes(pub_pem)
    Path("keys/README.txt").write_text("The public key must copied into __patabim__/ folder as __patabim__/_ptbm.pem.", encoding="utf-8")

    print(f"Generated keys -> keys/{private_path}, keys/{public_path}")

def pack_file(input_path: str, out_path: str, privkey_path: str, password: bytes, salt: bytes = None, nonce: bytes = None):
    data = Path(input_path).read_bytes()

    if salt is None:
        salt = os.urandom(16)
    if nonce is None:
        nonce = os.urandom(12)

    aes_key = derive_key(password, salt)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # includes tag

    priv_pem = Path(privkey_path).read_bytes()
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    signature = private_key.sign(
        ciphertext,
        padding.PSS(mgf=padding.MGF1(asym_hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        asym_hashes.SHA256()
    )

    version = b'\x01'
    blob = b"".join([
        MAGIC,
        version,
        struct.pack("B", len(salt)),
        struct.pack("B", len(nonce)),
        struct.pack(">H", len(signature)),
        salt,
        nonce,
        ciphertext,
        signature
    ])
    
    if not os.path.isdir("results"):
        os.mkdir("results")
    
    b64 =  base64.b64encode(blob).replace(b"/", b"\x0c\x4b")[::-1]
    zlibed = MAGIC2 + zlib.compress(b64)[::-1].replace(b"x", b"\xe1\xb4\x98\xe1\xb4\x9b\xca\x99\xe1\xb4\x8d\xe1\xb4\xa0\xf0\x9d\x9f\xba\x2e\xf0\x9d\x9f\xb6")

    Path("results/" + out_path + ".bin").write_bytes(zlibed)
    stub = f"""#!/usr/bin/env python3+
# Packed by Patabimv4 — do NOT include private keys here.
# Packed on version {platform.python_version()} — if you got any errors try this version
import __patabim__

# Optional: set PTAB_PASSWORD env var to avoid interactive prompt
# __patabim__.env("YOUR_PASSWORD_HERE")

exec(__patabim__.extract("<{out_path + ".bin"}>"))
"""
    Path("results/" + out_path + ".py").write_text(stub, encoding='utf-8')
    try:
        os.chmod("results/" + out_path + ".py", 0o755)
    except Exception:
        pass

    dir_util.copy_tree("__patabim__", "results/__patabim__")

    print(f"Packed {input_path} -> results/{out_path}.bin & results/{out_path}.py (salt={len(salt)} nonce={len(nonce)} sig={len(signature)})")

def pack_to_py(input_path: str, out_py_path: str, privkey_path: str, password: bytes):
    data = Path(input_path).read_bytes()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes_key = derive_key(password, salt)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # sign
    priv_pem = Path(privkey_path).read_bytes()
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    signature = private_key.sign(
        ciphertext,
        padding.PSS(mgf=padding.MGF1(asym_hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        asym_hashes.SHA256()
    )

    version = b'\x01'
    blob = b"".join([
        MAGIC,
        version,
        struct.pack("B", len(salt)),
        struct.pack("B", len(nonce)),
        struct.pack(">H", len(signature)),
        salt,
        nonce,
        ciphertext,
        signature
    ])

    b64 =  base64.b64encode(blob).replace(b"/", b"\x0c\x4b")[::-1]
    zlibed = MAGIC2 + zlib.compress(b64)[::-1].replace(b"x", b"\xe1\xb4\x98\xe1\xb4\x9b\xca\x99\xe1\xb4\x8d\xe1\xb4\xa0\xf0\x9d\x9f\xba\x2e\xf0\x9d\x9f\xb6")

    stub = f"""#!/usr/bin/env python3+
# Packed by Patabimv4 — do NOT include private keys here.
# Packed on version {platform.python_version()} — if you got any errors try this version

import __patabim__

# Optional: set PTAB_PASSWORD env var to avoid interactive prompt
# __patabim__.env("YOUR_PASSWORD_HERE")

exec(__patabim__.extract(__patabim__.handle({zlibed})))
"""
    if not os.path.isdir("results"):
        os.mkdir("results")
    Path("results/" + out_py_path).write_text(stub, encoding='utf-8')
    try:
        os.chmod("results/" + out_py_path, 0o755)
    except Exception:
        pass

    dir_util.copy_tree("__patabim__", "results/__patabim__")
    
    print(f"Packed {input_path} -> runnable python stub results/{out_py_path}")

def main():
    parser = argparse.ArgumentParser(prog="patabimv4", description="Packer: gen-keys | pack-bin | pack-py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("gen-keys", help="Generate RSA key pair")
    p_gen.add_argument("--priv", default="private_key.pem")
    p_gen.add_argument("--pub", default="public_key.pem")
    p_gen.add_argument("--bits", type=int, default=3072)

    p_bin = sub.add_parser("pack-bin", help="Pack input.py -> payload.bin")
    p_bin.add_argument("input")
    p_bin.add_argument("out_without_ext")
    p_bin.add_argument("privkey")

    p_py = sub.add_parser("pack-py", help="Pack input.py -> runnable obfed.py (stub)")
    p_py.add_argument("input")
    p_py.add_argument("out")
    p_py.add_argument("privkey")

    args = parser.parse_args()

    if args.cmd == "gen-keys":
        gen_rsa_keys(args.priv, args.pub, args.bits)
    elif args.cmd == "pack-bin":
        pw = getpass.getpass("Password (for deriving AES key): ").encode()
        pack_file(args.input, args.out_without_ext, args.privkey, pw)
    elif args.cmd == "pack-py":
        pw = getpass.getpass("Password (for deriving AES key): ").encode()
        pack_to_py(args.input, args.out, args.privkey, pw)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
