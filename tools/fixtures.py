#!/usr/bin/env python3
"""Verify/sync packaged synthetic copies; never read acquired evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

def beta(values):
    from Cryptodome.Cipher import AES
    def u32(value):
        return struct.pack(">I", value)

    def text(value):
        value = value.encode() if isinstance(value, str) else value
        return u32(len(value)) + value

    def attributes(hashed=False):
        result = u32(2)
        for name, value in {"application": "Signal Beta", "xdg:schema": "chrome_libsecret_os_crypt_password_v2"}.items():
            result += text(name) + u32(0) + text(hashlib.md5(value.encode()).hexdigest() if hashed else value)
        return result

    salt = bytes(range(8))
    rounds = 2000
    outer = b"GnomeKeyring\n\r\0\n" + bytes(4) + text("Synthetic Beta Collection")
    outer += struct.pack(">QQ", 1700000001, 1700000000)
    outer += u32(0) + u32(0) + u32(rounds) + salt + bytes(16) + u32(1)
    outer += u32(1) + u32(0) + attributes(True)
    body = text("Chromium Safe Storage") + text(values["safe_storage"])
    body += struct.pack(">QQ", 1700000000, 1700000001) + u32(0xffffffff) + bytes(16)
    body += attributes() + u32(0)
    body += bytes((-len(body)) % 16)
    plain = hashlib.md5(body).digest() + body
    key_iv = hashlib.sha256(values["password"].encode() + salt).digest()
    for _ in range(rounds - 1):
        key_iv = hashlib.sha256(key_iv).digest()
    encrypted = AES.new(key_iv[:16], AES.MODE_CBC, key_iv[16:]).encrypt(plain)
    return outer + u32(len(encrypted)) + encrypted

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["check","verify","sync"])
    parser.add_argument("--artefacts",type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    destination=root/"src/recovery/fixtures"
    copies=json.loads(Path(__file__).with_name("fixture-copies.json").read_text())
    for source,name in copies.items():
        data=(args.artefacts/source).read_bytes()
        if args.command=="sync":(destination/name).write_bytes(data)
        elif (destination/name).read_bytes()!=data:raise SystemExit("Stale fixture copy: "+name)
    # Hash-only checks need no optional crypto package.
    expected=json.loads(Path(__file__).with_name("fixture-hashes.json").read_text())
    if args.command in ("verify","sync"):
        generated=beta(json.loads((destination/"linux-values.json").read_text()))
        if args.command=="verify" and generated!=(destination/"linux-gnome-beta.keyring").read_bytes():raise SystemExit("Independent beta fixture regeneration differs")
        if args.command=="sync":(destination/"linux-gnome-beta.keyring").write_bytes(generated)
    if args.command=="sync":
        expected={name:hashlib.sha256((destination/name).read_bytes()).hexdigest() for name in expected}
        Path(__file__).with_name("fixture-hashes.json").write_text(json.dumps(expected,indent=2)+"\n")
    for name,digest in expected.items():
        if hashlib.sha256((destination/name).read_bytes()).hexdigest()!=digest:raise SystemExit("Fixture hash differs: "+name)
    print("Verified indexer fixture copies and independent beta collection.")
if __name__=="__main__":main()
