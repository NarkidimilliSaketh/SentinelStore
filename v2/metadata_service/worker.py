import os
import json
import base64
import asyncio
import random
import hashlib
import subprocess
import shutil
from typing import List, Tuple, Optional

import httpx
from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.encoding import RawEncoder
from hashlib import pbkdf2_hmac

# -------------------------------
# Utilities
# -------------------------------

def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)

def bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def pick_node(nodes: List[str]) -> str:
    return random.choice(nodes)

def parse_two_part_b64(packed: str) -> Tuple[str, str]:
    for sep in ("::", "|", ":", ","):
        if sep in packed:
            a, b = packed.split(sep, 1)
            if a and b:
                return a, b
    parts = packed.split()
    if len(parts) == 2:
        return parts[0], parts[1]
    raise ValueError("Encrypted payload format not recognized (expected nonce + ciphertext)")

# -------------------------------
# GF(256) arithmetic (Python fallback for splitting)
# -------------------------------
def split_secret_gf256(secret: bytes, n: int, k: int) -> List[bytes]:
    if not (2 <= k <= n <= 255):
        raise ValueError("Constraints not met: 2 <= k <= n <= 255")
    shares = [bytearray(len(secret) + 1) for _ in range(n)]
    for i in range(n):
        shares[i][0] = i + 1
    
    GF_POLY = 0x11B
    EXP = [0] * 512
    LOG = [0] * 256
    _x = 1
    for _i in range(255):
        EXP[_i] = _x
        LOG[_x] = _i
        _x <<= 1
        if _x & 0x100: _x ^= GF_POLY
    for _i in range(255, 512): EXP[_i] = EXP[_i - 255]
    def gf_mul(a: int, b: int) -> int:
        if a == 0 or b == 0: return 0
        return EXP[LOG[a] + LOG[b]]

    for i in range(len(secret)):
        secret_byte = secret[i]
        coeffs = [secret_byte] + [random.randint(0, 255) for _ in range(k - 1)]
        for x in range(1, n + 1):
            y = 0
            for coeff_idx in range(k - 1, -1, -1):
                y = gf_mul(y, x) ^ coeffs[coeff_idx]
            shares[x-1][i+1] = y
    return [bytes(s) for s in shares]

# -------------------------------
# Crypto helpers
# -------------------------------
def derive_password_key(password: str) -> bytes:
    salt = bytes([1] * 16)
    return pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000, dklen=32)
def decrypt_secretbox(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    return SecretBox(key).decrypt(ciphertext, nonce)
def decrypt_file_key_asymmetric(encrypted: bytes, owner_secret_key: bytes) -> bytes:
    eph_pk, nonce, ciphertext = encrypted[:32], encrypted[32:56], encrypted[56:]
    sk = PrivateKey(owner_secret_key, encoder=RawEncoder)
    pk = PublicKey(eph_pk, encoder=RawEncoder)
    return Box(sk, pk).decrypt(ciphertext, nonce)
def encrypt_file_key_asymmetric(file_key: bytes, owner_public_key: bytes) -> bytes:
    eph_sk = PrivateKey.generate()
    recip_pk = PublicKey(owner_public_key, encoder=RawEncoder)
    box = Box(eph_sk, recip_pk)
    nonce = os.urandom(Box.NONCE_SIZE)
    encrypted = box.encrypt(file_key, nonce)
    return bytes(eph_sk.public_key) + encrypted

# -------------------------------
# P2P fetch/store helpers
# -------------------------------
async def p2p_get(client: httpx.AsyncClient, nodes: List[str], key: str) -> Optional[bytes]:
    order = random.sample(nodes, len(nodes))
    for node in order:
        try:
            res = await client.get(f"{node}/p2p/get/{key}", timeout=15)
            if res.status_code == 200:
                return b64_to_bytes(res.json()["value"])
        except Exception:
            continue
    return None
async def p2p_store(client: httpx.AsyncClient, node: str, key: str, value: bytes) -> None:
    payload = {"key": key, "value": bytes_to_b64(value)}
    r = await client.post(f"{node}/p2p/store", json=payload, timeout=30)
    r.raise_for_status()

# --- FIX IMPLEMENTED: Node.js helper for reconstruction ---
def combine_via_node(raw_shares_b64: list[str], k: int, cipher_len: int) -> bytes:
    node_bin = shutil.which("node")
    if not node_bin:
        raise RuntimeError("Node.js not found in container")
    
    script_path = "/app/combine_shares.js"
    if not os.path.exists(script_path):
        raise RuntimeError(f"Helper script not found at {script_path}")

    payload = json.dumps({"shares": raw_shares_b64, "k": k, "cipherLen": cipher_len}).encode("utf-8")
    proc = subprocess.Popen(
        [node_bin, script_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate(payload, timeout=20)
    
    err_decoded = err.decode('utf-8')
    if proc.returncode != 0 or "error" in err_decoded:
        raise RuntimeError(f"Node combine error: {err_decoded or out.decode('utf-8')}")
    
    resp = json.loads(out.decode("utf-8") or "{}")
    if "error" in resp:
        raise RuntimeError(f"Node combine reported: {resp['error']}")
    if "ciphertextB64" not in resp:
        raise RuntimeError("Node combine returned no ciphertext")
        
    print(f"   -> Node.js helper succeeded with strategy: {resp.get('strategy')}")
    return base64.b64decode(resp["ciphertextB64"])

# -------------------------------
# Core re-shard worker
# -------------------------------
async def re_shard_file(file_doc: dict, owner_doc: dict, new_n: int, new_k: int, owner_password: str) -> Tuple[str, str]:
    nodes_env = os.getenv("P2P_NODE_URLS", "http://p2p_node_0:8001,http://p2p_node_1:8001,http://p2p_node_2:8001")
    p2p_nodes = [u.strip() for u in nodes_env.split(",") if u.strip()]

    print("--- Starting Re-shard Process ---")

    # Robust key access
    enc_priv = owner_doc.get("encrypted_private_key") or owner_doc.get("encryptedprivatekey")
    if not enc_priv: raise KeyError("encrypted_private_key missing")
    enc_fk_b64 = file_doc.get("encrypted_file_key") or file_doc.get("encryptedfilekey")
    if not enc_fk_b64: raise KeyError("encrypted_file_key missing")
    root_hash = file_doc.get("root_hash") or file_doc.get("roothash")
    if not root_hash: raise KeyError("root_hash missing")
    owner_pub_b64 = owner_doc.get("public_key") or owner_doc.get("publickey")
    if not owner_pub_b64: raise KeyError("public_key missing")

    # 1 & 2) Decrypt keys
    print("1. Decrypting owner's private key...")
    key_derived = derive_password_key(owner_password)
    nonce_b64, enc_sk_b64 = parse_two_part_b64(enc_priv)
    owner_secret_key = decrypt_secretbox(b64_to_bytes(enc_sk_b64), b64_to_bytes(nonce_b64), key_derived)
    print("✅ Owner's private key decrypted.")
    print("2. Decrypting file key...")
    file_key = decrypt_file_key_asymmetric(b64_to_bytes(enc_fk_b64), owner_secret_key)
    if len(file_key) != 32: raise ValueError("Decrypted file key is not 32 bytes")
    print("✅ File key decrypted.")

    # 3) Fetch manifest
    print("3. Fetching manifest...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        manifest_bytes = await p2p_get(client, p2p_nodes, root_hash)
        if manifest_bytes is None: raise RuntimeError("Manifest not found")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    print("✅ Manifest fetched.")

    old_k = int(manifest["erasure"]["k"])
    shards_hashes = list(manifest["shards"])
    nonce_b64 = manifest["crypto"]["nonce"]
    cipher_len = int(manifest["crypto"]["ciphertextLength"])
    
    # 4) Fetch and validate shares
    print(f"4. Fetching and validating shares (need at least {old_k})...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        tasks = [p2p_get(client, p2p_nodes, h) for h in shards_hashes]
        results = await asyncio.gather(*tasks)

    hash_to_bytes = {h: s for h, s in zip(shards_hashes, results) if s and sha256_hex(s) == h}
    
    if len(hash_to_bytes) < old_k:
        raise RuntimeError(f"Not enough hash-verified shares: {len(hash_to_bytes)}/{old_k}")
    print(f"✅ Retrieved {len(hash_to_bytes)} hash-verified shares.")

    # 5) Reconstruct using Node.js helper for browser parity
    print("5. Reconstructing original file content via Node.js helper...")
    # Provide shares in manifest order for deterministic reconstruction
    raw_b64_ordered = [bytes_to_b64(hash_to_bytes[h]) for h in shards_hashes if h in hash_to_bytes]
    
    try:
        ciphertext = combine_via_node(raw_b64_ordered, old_k, cipher_len)
        # Validate AEAD immediately
        _ = decrypt_secretbox(ciphertext, b64_to_bytes(nonce_b64), file_key)
        print("   -> Node.js combine and validation succeeded.")
    except Exception as e:
        raise RuntimeError(f"Failed to reconstruct valid ciphertext from all available share combinations: {e}")

    # 6) Decrypt to get plaintext
    print("6. Decrypting the reconstructed ciphertext...")
    plaintext = decrypt_secretbox(ciphertext, b64_to_bytes(nonce_b64), file_key)
    print("✅ Plaintext recovered.")

    # 7-10) Reconstruct and upload
    print(f"7. Creating new shares (n={new_n}, k={new_k})...")
    new_shares = split_secret_gf256(ciphertext, new_n, new_k)
    print("8. Uploading new shares to P2P...")
    new_share_hashes = [sha256_hex(s) for s in new_shares]
    async with httpx.AsyncClient(timeout=60.0) as client:
        await asyncio.gather(*[
            p2p_store(client, pick_node(p2p_nodes), h, s)
            for h, s in zip(new_share_hashes, new_shares)
        ])
    print("✅ New shares uploaded.")
    new_manifest = manifest.copy()
    new_manifest["erasure"] = {"n": new_n, "k": new_k}
    new_manifest["shards"] = new_share_hashes
    new_manifest_bytes = json.dumps(new_manifest, separators=(",", ":")).encode("utf-8")
    new_root_hash = sha256_hex(new_manifest_bytes)
    print("9. Uploading new manifest to P2P...")
    async with httpx.AsyncClient(timeout=30.0) as client:
        await p2p_store(client, pick_node(p2p_nodes), new_root_hash, new_manifest_bytes)
    print("✅ New manifest uploaded.")
    print("10. Re-encrypting file key for owner...")
    owner_public_key = b64_to_bytes(owner_pub_b64)
    new_encrypted_file_key_bytes = encrypt_file_key_asymmetric(file_key, owner_public_key)
    new_encrypted_file_key_b64 = bytes_to_b64(new_encrypted_file_key_bytes)
    print("✅ File key re-encrypted for owner.")
    print("🎉 Re-shard complete.")
    return new_root_hash, new_encrypted_file_key_b64