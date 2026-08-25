#!/usr/bin/env python3
"""
Verify a COSE_Sign1 signed firmware image using the same algorithm
as cose_verify.rs — to confirm sign_firmware.py and the Rust verifier agree.

This test builds the Sig_structure the same way the Rust code does
(manual CBOR byte construction) and verifies with the platform key.

Usage:
    python3 verify_test.py
"""

import sys
import hashlib
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.backends import default_backend
    import cbor2
except ImportError:
    print("Required packages: pip install cryptography cbor2")
    sys.exit(1)


def cbor_encode_bstr_header(length):
    """Encode CBOR bstr header bytes — matches Rust cbor_encode_bstr_header()"""
    if length < 24:
        return bytes([0x40 | length])
    elif length < 256:
        return bytes([0x58, length])
    elif length < 65536:
        return bytes([0x59, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x5A,
                      (length >> 24) & 0xFF, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def build_sig_structure_manual(protected_header, payload):
    """Build Sig_structure using manual CBOR encoding — matches Rust verify_signature()"""
    buf = bytearray()

    # 4-element array header
    buf.append(0x84)

    # context: "Signature1" (tstr, 10 bytes)
    buf.append(0x6A)
    buf.extend(b"Signature1")

    # body_protected: bstr wrapping protected header
    buf.extend(cbor_encode_bstr_header(len(protected_header)))
    buf.extend(protected_header)

    # external_aad: empty bstr
    buf.append(0x40)

    # payload: bstr
    buf.extend(cbor_encode_bstr_header(len(payload)))
    buf.extend(payload)

    return bytes(buf)


def test_verify():
    test_dir = Path(__file__).parent

    # Load private key
    key_path = test_dir / "platform_key.pem"
    if not key_path.exists():
        print(f"FAIL: Key not found: {key_path}")
        return False

    pem_data = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    print(f"Platform key X: {public_numbers.x.to_bytes(32, 'big').hex()}")
    print(f"Platform key Y: {public_numbers.y.to_bytes(32, 'big').hex()}")

    # Load signed firmware
    cose_path = test_dir / "signed_payload.cose"
    if not cose_path.exists():
        print(f"FAIL: Signed payload not found: {cose_path}")
        return False

    cose_data = cose_path.read_bytes()
    print(f"Signed payload: {len(cose_data)} bytes")

    # Parse COSE_Sign1
    decoded = cbor2.loads(cose_data)
    if hasattr(decoded, 'tag') and decoded.tag == 18:
        sign1 = list(decoded.value)
    elif isinstance(decoded, (list, tuple)):
        sign1 = list(decoded)
    else:
        print(f"FAIL: Unexpected type {type(decoded)}")
        return False

    if len(sign1) != 4:
        print(f"FAIL: Expected 4-element array, got len={len(sign1)}")
        return False

    protected_header = sign1[0]
    _unprotected = sign1[1]
    payload_cbor = sign1[2]
    signature_raw = sign1[3]

    print(f"Protected header: {len(protected_header)} bytes")
    print(f"Payload: {len(payload_cbor)} bytes")
    print(f"Signature: {len(signature_raw)} bytes")

    # Parse protected header
    ph = cbor2.loads(protected_header)
    alg = ph.get(1, 0)
    print(f"Algorithm: {alg} (expected -7 = ES256)")
    if alg != -7:
        print("FAIL: Wrong algorithm")
        return False

    # Parse payload as 10-element array
    payload = cbor2.loads(payload_cbor)
    if not isinstance(payload, list) or len(payload) != 10:
        print(f"FAIL: Expected 10-element payload array, got {type(payload)} len={len(payload) if isinstance(payload, list) else 'N/A'}")
        return False

    magic = payload[0]
    version = payload[1]
    platform = payload[2]
    arch = payload[3]
    image_type = payload[4]
    timestamp = payload[5]
    fw_rev = payload[6]
    build_id = payload[7]
    image_hash_entry = payload[8]
    image_data = payload[9]

    print(f"Magic: 0x{magic:08x} (expected 0x46444F46)")
    print(f"Version: {version}")
    print(f"Platform: {platform}")
    print(f"Architecture: {arch}")
    print(f"ImageType: {image_type}")
    print(f"Timestamp: {timestamp}")
    print(f"FirmwareRev: {fw_rev}")
    print(f"BuildId: {build_id}")
    print(f"ImageHash: type={image_hash_entry[0]}, len={len(image_hash_entry[1])}")
    print(f"Image: {len(image_data)} bytes")

    if magic != 0x46444F46:
        print("FAIL: Wrong magic")
        return False

    # Verify image hash
    computed_hash = hashlib.sha256(image_data).digest()
    if computed_hash != image_hash_entry[1]:
        print("FAIL: Image hash mismatch")
        return False
    print(f"Image hash: MATCH ({computed_hash.hex()[:16]}...)")

    # Test 1: Verify using cbor2-built Sig_structure (what sign_firmware.py does)
    sig_structure_cbor2 = cbor2.dumps([
        "Signature1",
        protected_header,
        b"",
        payload_cbor
    ])

    # Test 2: Verify using manual Sig_structure (what Rust cose_verify.rs does)
    sig_structure_manual = build_sig_structure_manual(protected_header, payload_cbor)

    # These must be identical
    if sig_structure_cbor2 != sig_structure_manual:
        print("FAIL: Sig_structure mismatch between cbor2 and manual encoding!")
        print(f"  cbor2:  {sig_structure_cbor2[:40].hex()}... ({len(sig_structure_cbor2)} bytes)")
        print(f"  manual: {sig_structure_manual[:40].hex()}... ({len(sig_structure_manual)} bytes)")
        # Find first diff
        for i in range(min(len(sig_structure_cbor2), len(sig_structure_manual))):
            if sig_structure_cbor2[i] != sig_structure_manual[i]:
                print(f"  First diff at byte {i}: cbor2=0x{sig_structure_cbor2[i]:02x} manual=0x{sig_structure_manual[i]:02x}")
                break
        return False
    print(f"Sig_structure: cbor2 == manual ({len(sig_structure_manual)} bytes) ✓")

    # Verify signature using cryptography library
    r = int.from_bytes(signature_raw[:32], 'big')
    s = int.from_bytes(signature_raw[32:], 'big')
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    signature_der = encode_dss_signature(r, s)

    try:
        public_key.verify(signature_der, sig_structure_manual, ec.ECDSA(hashes.SHA256()))
        print("Signature verification: PASS ✓")
    except Exception as e:
        print(f"Signature verification: FAIL ✗ ({e})")
        return False

    # Test negative: tamper with payload, verify fails
    tampered = bytearray(sig_structure_manual)
    tampered[-1] ^= 0xFF
    try:
        public_key.verify(signature_der, bytes(tampered), ec.ECDSA(hashes.SHA256()))
        print("Tamper test: FAIL (should have rejected tampered data)")
        return False
    except Exception:
        print("Tamper test: PASS (correctly rejected tampered data) ✓")

    print("\n=== ALL TESTS PASSED ===")
    return True


if __name__ == "__main__":
    success = test_verify()
    sys.exit(0 if success else 1)
