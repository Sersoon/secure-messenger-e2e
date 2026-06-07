"""HMAC-SHA256 — ręczna implementacja wg RFC 2104. Tylko hashlib.sha256, bez bibliotek HMAC."""

import hashlib

ROZMIAR_BLOKU: int = 64
ROZMIAR_SKROTU: int = 32

IPAD: bytes = bytes([0x36] * ROZMIAR_BLOKU)
OPAD: bytes = bytes([0x5C] * ROZMIAR_BLOKU)


def _sha256(dane: bytes) -> bytes:
    return hashlib.sha256(dane).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _przygotuj_klucz(klucz: bytes) -> bytes:
    """Dopasowuje klucz do 64 B (hash gdy > 64 B, padding zerami gdy < 64 B)."""
    if len(klucz) > ROZMIAR_BLOKU:
        klucz = _sha256(klucz)
    return klucz.ljust(ROZMIAR_BLOKU, b'\x00')


def oblicz_hmac(klucz: bytes, wiadomosc: bytes) -> bytes:
    """HMAC-SHA256: H((K⊕opad) || H((K⊕ipad) || m)). Zwraca 32-bajtowy tag."""
    if not isinstance(klucz, (bytes, bytearray)):
        raise TypeError(f"Klucz musi być typu bytes, otrzymano: {type(klucz).__name__}")
    if not isinstance(wiadomosc, (bytes, bytearray)):
        raise TypeError(f"Wiadomosc musi być typu bytes, otrzymano: {type(wiadomosc).__name__}")
    k_prim = _przygotuj_klucz(bytes(klucz))
    inner = _sha256(_xor_bytes(k_prim, IPAD) + bytes(wiadomosc))
    return _sha256(_xor_bytes(k_prim, OPAD) + inner)


def weryfikuj_hmac(klucz: bytes, wiadomosc: bytes, oczekiwany_hmac: bytes) -> bool:
    """Weryfikacja HMAC w stałym czasie — odporność na timing attack."""
    obliczony = oblicz_hmac(klucz, wiadomosc)
    if len(obliczony) != len(oczekiwany_hmac):
        return False
    roznica = 0
    for a, b in zip(obliczony, oczekiwany_hmac):
        roznica |= a ^ b
    return roznica == 0


def oblicz_hmac_pakietu(klucz_hmac: bytes, iv: bytes, szyfrogram: bytes) -> bytes:
    """HMAC dla pakietu: uwierzytelnia IV || ciphertext razem (Encrypt-then-MAC)."""
    return oblicz_hmac(klucz_hmac, iv + szyfrogram)


def weryfikuj_hmac_pakietu(
    klucz_hmac: bytes,
    iv: bytes,
    szyfrogram: bytes,
    oczekiwany_hmac: bytes
) -> bool:
    """Weryfikuje HMAC pakietu przed deszyfrowaniem (ochrona przed padding oracle)."""
    return weryfikuj_hmac(klucz_hmac, iv + szyfrogram, oczekiwany_hmac)
