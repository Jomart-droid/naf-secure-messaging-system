import os
from cryptography.fernet import Fernet, InvalidToken

class CryptoError(Exception):
    pass


def _get_fernet() -> Fernet:
    key = os.getenv("MESSAGE_ENCRYPTION_KEY", "").strip()
    if not key:
        raise CryptoError("MESSAGE_ENCRYPTION_KEY is not set. Startup should refuse this configuration.")
    return Fernet(key.encode("utf-8"))


def encrypt_text(plaintext: str) -> bytes:
    if plaintext is None:
        plaintext = ""
    try:
        return _get_fernet().encrypt(plaintext.encode("utf-8"))
    except CryptoError:
        raise
    except Exception as e:
        raise CryptoError(str(e))


def decrypt_text(ciphertext: bytes) -> str:
    if ciphertext is None:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext).decode("utf-8")
    except InvalidToken:
        # Legacy compatibility only: older demo databases may contain plaintext because
        # the previous build silently fell back when no encryption key existed.
        try:
            legacy = ciphertext.decode("utf-8")
            if legacy and not legacy.startswith("gAAAA"):
                return legacy
        except Exception:
            pass
        return "[Unable to decrypt: invalid key or tampered payload]"
    except CryptoError:
        raise
    except Exception:
        return "[Unable to decrypt]"
