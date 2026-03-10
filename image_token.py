#!/usr/bin/env python3
"""Generate a secure JWT token from raw image bytes.

The token is derived from multiple cryptographic layers over the image
binary content, without visual fingerprint fields in the payload.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
TOKEN_VERSION = "imgtok_jwt_v2"
DEFAULT_PBKDF2_ITERATIONS = 310_000


def _b64url_encode(data: bytes) -> str:
    """Return base64url without padding, as used by JWT."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sign_hs256(signing_input: str, secret: str) -> str:
    """Return JWT HS256 signature in base64url format."""
    digest = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(digest)


def _derive_image_token_material(image_bytes: bytes, secret: str, iterations: int) -> str:
    """Derive token material through multiple cryptographic layers.

    Layers:
    1) SHA3-512 over image bytes
    2) PBKDF2-HMAC-SHA512 key stretching
    3) HMAC-SHA512 with secret key
    4) SHA-256 compression for compact token material
    """
    secret_bytes = secret.encode("utf-8")
    secret_key = hashlib.sha256(secret_bytes).digest()

    layer1 = hashlib.sha3_512(image_bytes).digest()
    salt = hashlib.sha3_256(secret_bytes + b"|img-token-salt|").digest()
    layer2 = hashlib.pbkdf2_hmac("sha512", layer1, salt, iterations, dklen=64)
    layer3 = hmac.new(secret_key, layer2 + layer1, hashlib.sha512).digest()
    layer4 = hashlib.sha256(layer1 + layer2 + layer3).digest()
    return _b64url_encode(layer4)


def generate_image_token(image_path: str, secret: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> str:
    """Generate a JWT token from image binary content.

    Args:
        image_path: Path to image file.
        secret: Secret key used to sign JWT with HS256.
        iterations: PBKDF2 iteration count for key stretching.
    """
    path = Path(image_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Image not found: {image_path}")
    if not secret:
        raise ValueError("A non-empty secret is required for secure token generation.")
    if iterations < 100_000:
        raise ValueError("Use at least 100000 PBKDF2 iterations for adequate security.")

    image_bytes = path.read_bytes()
    if not image_bytes:
        raise ValueError("Image file is empty.")

    img_token = _derive_image_token_material(image_bytes=image_bytes, secret=secret, iterations=iterations)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "v": TOKEN_VERSION,
        "sub": "image-token",
        "img_token": img_token,
        "kdf": "pbkdf2-hmac-sha512",
        "iter": iterations,
    }

    header_b64 = _b64url_encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature_b64 = _sign_hs256(signing_input, secret)
    return f"{signing_input}.{signature_b64}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate secure JWT token from raw image bytes",
    )
    parser.add_argument("image", help="Path to the input image")
    parser.add_argument(
        "--secret",
        default=os.getenv("IMAGE_TOKEN_SECRET", ""),
        help="JWT signing secret (or set IMAGE_TOKEN_SECRET)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_PBKDF2_ITERATIONS,
        help=f"PBKDF2 iterations (default: {DEFAULT_PBKDF2_ITERATIONS})",
    )
    args = parser.parse_args()

    token = generate_image_token(args.image, secret=args.secret, iterations=args.iterations)
    print(token)


if __name__ == "__main__":
    main()
