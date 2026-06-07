"""AES-256-CBC + PKCS7 + format pakietu sieciowego (Encrypt-then-MAC)."""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


ROZMIAR_BLOKU_AES: int = 16
ROZMIAR_KLUCZA_AES: int = 32
ROZMIAR_IV: int = 16


def pkcs7_pad(dane: bytes, rozmiar_bloku: int = ROZMIAR_BLOKU_AES) -> bytes:
    """Dodaje padding PKCS7 — zawsze 1–16 bajtów, nigdy 0."""
    if not isinstance(dane, (bytes, bytearray)):
        raise TypeError(f"dane muszą być bytes, otrzymano: {type(dane).__name__}")
    if not 1 <= rozmiar_bloku <= 255:
        raise ValueError(f"rozmiar_bloku musi być 1-255, otrzymano: {rozmiar_bloku}")
    brakujace = rozmiar_bloku - (len(dane) % rozmiar_bloku)
    return bytes(dane) + bytes([brakujace] * brakujace)


def pkcs7_unpad(dane: bytes, rozmiar_bloku: int = ROZMIAR_BLOKU_AES) -> bytes:
    """Usuwa padding PKCS7. Weryfikuje poprawność przed usunięciem."""
    if not isinstance(dane, (bytes, bytearray)):
        raise TypeError(f"dane muszą być bytes, otrzymano: {type(dane).__name__}")
    if len(dane) == 0:
        raise ValueError("Puste dane — brak paddingu PKCS7 do usunięcia")
    if len(dane) % rozmiar_bloku != 0:
        raise ValueError(
            f"Długość danych ({len(dane)} B) nie jest wielokrotnością "
            f"rozmiaru bloku ({rozmiar_bloku} B)"
        )
    wartosc_pad = dane[-1]
    if not 1 <= wartosc_pad <= rozmiar_bloku:
        raise ValueError(
            f"Nieprawidłowa wartość paddingu PKCS7: {wartosc_pad} "
            f"(oczekiwano 1-{rozmiar_bloku})"
        )
    if len(dane) < wartosc_pad:
        raise ValueError("Dane są zbyt krótkie dla zadeklarowanego paddingu")
    if any(b != wartosc_pad for b in dane[-wartosc_pad:]):
        raise ValueError("Nieprawidłowy padding PKCS7 — bajty nie są jednorodne")
    return bytes(dane[:-wartosc_pad])


def szyfruj_aes_cbc(plaintext: bytes, klucz: bytes) -> tuple[bytes, bytes]:
    """Szyfruje AES-256-CBC z losowym IV. Zwraca (iv, szyfrogram)."""
    if len(klucz) != ROZMIAR_KLUCZA_AES:
        raise ValueError(
            f"Klucz AES musi mieć {ROZMIAR_KLUCZA_AES} bajtów (AES-256), "
            f"otrzymano: {len(klucz)} B"
        )
    iv = os.urandom(ROZMIAR_IV)
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(klucz), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    szyfrogram = encryptor.update(padded) + encryptor.finalize()
    return iv, szyfrogram


def deszyfruj_aes_cbc(szyfrogram: bytes, klucz: bytes, iv: bytes) -> bytes:
    """Odszyfrowuje AES-256-CBC. Wywołuj tylko po weryfikacji HMAC."""
    if len(klucz) != ROZMIAR_KLUCZA_AES:
        raise ValueError(
            f"Klucz AES musi mieć {ROZMIAR_KLUCZA_AES} bajtów, "
            f"otrzymano: {len(klucz)} B"
        )
    if len(iv) != ROZMIAR_IV:
        raise ValueError(f"IV musi mieć {ROZMIAR_IV} bajtów, otrzymano: {len(iv)} B")
    if len(szyfrogram) == 0 or len(szyfrogram) % ROZMIAR_BLOKU_AES != 0:
        raise ValueError(
            f"Szyfrogram ({len(szyfrogram)} B) musi być niepustą "
            f"wielokrotnością {ROZMIAR_BLOKU_AES} B"
        )
    cipher = Cipher(algorithms.AES(klucz), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(szyfrogram) + decryptor.finalize()
    return pkcs7_unpad(padded)


def zbuduj_pakiet(
    plaintext: bytes,
    klucz_aes: bytes,
    klucz_hmac: bytes,
    session_id: int,
    nonce: int
) -> bytes:
    """Buduje pakiet: [4B session_id | 4B nonce | 16B IV | 32B HMAC | 4B len | N B ct]"""
    from secure_messenger.crypto.hmac_sha256 import oblicz_hmac_pakietu
    iv, szyfrogram = szyfruj_aes_cbc(plaintext, klucz_aes)
    tag_hmac = oblicz_hmac_pakietu(klucz_hmac, iv, szyfrogram)
    return (
        session_id.to_bytes(4, 'big') +
        nonce.to_bytes(4, 'big') +
        iv + tag_hmac +
        len(szyfrogram).to_bytes(4, 'big') +
        szyfrogram
    )


def rozpakuj_pakiet(
    pakiet: bytes,
    klucz_aes: bytes,
    klucz_hmac: bytes
) -> tuple[int, int, bytes]:
    """
    Weryfikuje HMAC i odszyfrowuje pakiet. Zwraca (session_id, nonce, plaintext).
    Zgłasza ValueError gdy pakiet za krótki, HMAC nieprawidłowy lub padding zły.
    """
    from secure_messenger.crypto.hmac_sha256 import weryfikuj_hmac_pakietu

    MIN_DLUGOSC = 4 + 4 + 16 + 32 + 4 + 16
    if len(pakiet) < MIN_DLUGOSC:
        raise ValueError(f"Pakiet za krótki: {len(pakiet)} B (minimum {MIN_DLUGOSC} B)")

    offset = 0
    session_id = int.from_bytes(pakiet[offset:offset+4], 'big'); offset += 4
    nonce      = int.from_bytes(pakiet[offset:offset+4], 'big'); offset += 4
    iv         = pakiet[offset:offset+16];                       offset += 16
    tag_hmac   = pakiet[offset:offset+32];                       offset += 32
    dlugosc    = int.from_bytes(pakiet[offset:offset+4], 'big'); offset += 4
    szyfrogram = pakiet[offset:offset+dlugosc]

    if len(szyfrogram) != dlugosc:
        raise ValueError(
            f"Niezgodność długości szyfrogramu: zadeklarowano {dlugosc} B, "
            f"odebrano {len(szyfrogram)} B"
        )
    if not weryfikuj_hmac_pakietu(klucz_hmac, iv, szyfrogram, tag_hmac):
        raise ValueError("Weryfikacja HMAC nieudana — pakiet zmodyfikowany lub błędny klucz")

    plaintext = deszyfruj_aes_cbc(szyfrogram, klucz_aes, iv)
    return session_id, nonce, plaintext
