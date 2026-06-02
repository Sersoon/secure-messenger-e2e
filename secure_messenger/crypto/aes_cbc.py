"""
Moduł AES-CBC — szyfrowanie symetryczne z losowym IV i paddingiem PKCS7.

Używamy biblioteki `cryptography` do samego AES (dopuszczalne wg wymagań projektu).
Ręcznie implementujemy: padding PKCS7, generowanie IV, format pakietu.

Schemat Encrypt-then-MAC (stosowany razem z hmac_sha256.py):
    1. IV       = os.urandom(16)        — losowy wektor inicjalizacyjny
    2. padded   = pkcs7_pad(plaintext)  — wyrównanie do bloku 16 B
    3. cipher   = AES_CBC(padded, key, IV)
    4. HMAC     = HMAC_SHA256(IV || cipher, key_hmac)  — w hmac_sha256.py
    5. pakiet   = IV + HMAC + cipher

Deszyfrowanie:
    1. Weryfikuj HMAC ZANIM odszyfrowanie (ochrona przed padding oracle)
    2. plaintext = AES_CBC_decrypt(cipher, key, IV)
    3. plaintext = pkcs7_unpad(plaintext)
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# STAŁE AES
# ---------------------------------------------------------------------------

ROZMIAR_BLOKU_AES: int = 16   # AES zawsze pracuje na blokach 128-bitowych (16 B)
ROZMIAR_KLUCZA_AES: int = 32  # AES-256: 256-bitowy klucz = 32 bajty
ROZMIAR_IV: int = 16          # IV = jeden blok AES = 16 bajtów


# ---------------------------------------------------------------------------
# PADDING PKCS7
# ---------------------------------------------------------------------------

def pkcs7_pad(dane: bytes, rozmiar_bloku: int = ROZMIAR_BLOKU_AES) -> bytes:
    """
    Dodaje padding PKCS7 do danych, aby ich długość była wielokrotnością rozmiaru bloku.

    Zasada PKCS7 (RFC 5652):
        Jeśli brakuje N bajtów do pełnego bloku → dopisz N bajtów o wartości N.
        Jeśli dane są już wyrównane → dopisz pełny blok wartości 16 (0x10).
        Dzięki temu padding jest zawsze obecny i jednoznaczny do usunięcia.

    Przykłady:
        b'ABC' (3 B)    → b'ABC' + b'\\x0d' * 13   (brakuje 13)
        b'A' * 16 (16 B) → b'A'*16 + b'\\x10' * 16  (pełny blok paddingu)
        b'' (0 B)       → b'\\x10' * 16              (pusty → pełny blok)

    Parametry:
        dane         — bajty do wyrównania
        rozmiar_bloku — rozmiar bloku szyfru (domyślnie 16 dla AES)

    Zwraca:
        Bajty z paddingiem, długość jest wielokrotnością rozmiar_bloku

    Zgłasza:
        TypeError  — gdy dane nie są bajtami
        ValueError — gdy rozmiar_bloku <= 0 lub > 255
    """
    if not isinstance(dane, (bytes, bytearray)):
        raise TypeError(f"dane muszą być bytes, otrzymano: {type(dane).__name__}")
    if not 1 <= rozmiar_bloku <= 255:
        raise ValueError(f"rozmiar_bloku musi być w zakresie 1-255, otrzymano: {rozmiar_bloku}")

    # Liczba bajtów paddingu: od 1 do rozmiar_bloku (nigdy 0!)
    brakujace = rozmiar_bloku - (len(dane) % rozmiar_bloku)
    padding = bytes([brakujace] * brakujace)
    return bytes(dane) + padding


def pkcs7_unpad(dane: bytes, rozmiar_bloku: int = ROZMIAR_BLOKU_AES) -> bytes:
    """
    Usuwa padding PKCS7 po deszyfrowaniu AES.

    Weryfikuje poprawność paddingu przed usunięciem.
    Nieprawidłowy padding może wskazywać na uszkodzone dane lub atak.

    Parametry:
        dane         — bajty po deszyfrowaniu (z paddingiem)
        rozmiar_bloku — rozmiar bloku szyfru

    Zwraca:
        Bajty bez paddingu (oryginalne dane)

    Zgłasza:
        ValueError — gdy padding jest nieprawidłowy lub dane są puste/za krótkie
    """
    if not isinstance(dane, (bytes, bytearray)):
        raise TypeError(f"dane muszą być bytes, otrzymano: {type(dane).__name__}")
    if len(dane) == 0:
        raise ValueError("Puste dane — brak paddingu PKCS7 do usunięcia")
    if len(dane) % rozmiar_bloku != 0:
        raise ValueError(
            f"Długość danych ({len(dane)} B) nie jest wielokrotnością "
            f"rozmiaru bloku ({rozmiar_bloku} B)"
        )

    # Odczytaj wartość ostatniego bajtu — to rozmiar paddingu
    wartosc_pad = dane[-1]

    # Walidacja: wartość paddingu musi być w zakresie [1, rozmiar_bloku]
    if not 1 <= wartosc_pad <= rozmiar_bloku:
        raise ValueError(
            f"Nieprawidłowa wartość paddingu PKCS7: {wartosc_pad} "
            f"(oczekiwano 1-{rozmiar_bloku})"
        )

    # Walidacja: wszystkie bajty paddingu muszą mieć tę samą wartość
    if len(dane) < wartosc_pad:
        raise ValueError("Dane są zbyt krótkie dla zadeklarowanego paddingu")

    bajty_paddingu = dane[-wartosc_pad:]
    if any(b != wartosc_pad for b in bajty_paddingu):
        raise ValueError("Nieprawidłowy padding PKCS7 — bajty nie są jednorodne")

    return bytes(dane[:-wartosc_pad])


# ---------------------------------------------------------------------------
# SZYFROWANIE AES-CBC
# ---------------------------------------------------------------------------

def szyfruj_aes_cbc(plaintext: bytes, klucz: bytes) -> tuple[bytes, bytes]:
    """
    Szyfruje plaintext algorytmem AES-256-CBC z losowym IV.

    Każda wiadomość otrzymuje nowy, unikalny IV (os.urandom).
    Powtórzenie IV z tym samym kluczem łamie bezpieczeństwo CBC!

    Parametry:
        plaintext — bajty do zaszyfrowania (dowolna długość, w tym pusta)
        klucz     — 32-bajtowy klucz AES-256

    Zwraca:
        (iv, szyfrogram) — IV (16 B) i zaszyfrowane dane

    Zgłasza:
        ValueError — gdy klucz ma nieprawidłową długość
    """
    if len(klucz) != ROZMIAR_KLUCZA_AES:
        raise ValueError(
            f"Klucz AES musi mieć {ROZMIAR_KLUCZA_AES} bajtów (AES-256), "
            f"otrzymano: {len(klucz)} B"
        )

    # Losowy IV dla każdej wiadomości — kluczowe dla bezpieczeństwa CBC
    iv = os.urandom(ROZMIAR_IV)

    # Padding PKCS7 przed szyfrowaniem
    padded = pkcs7_pad(plaintext)

    # Szyfrowanie AES-256-CBC
    cipher = Cipher(
        algorithms.AES(klucz),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    szyfrogram = encryptor.update(padded) + encryptor.finalize()

    return iv, szyfrogram


def deszyfruj_aes_cbc(szyfrogram: bytes, klucz: bytes, iv: bytes) -> bytes:
    """
    Odszyfrowuje szyfrogram AES-256-CBC.

    WAŻNE: wywołuj tę funkcję TYLKO po pozytywnej weryfikacji HMAC.
    Deszyfrowanie bez weryfikacji HMAC naraża na atak padding oracle.

    Parametry:
        szyfrogram — zaszyfrowane dane (wielokrotność 16 B)
        klucz      — 32-bajtowy klucz AES-256
        iv         — 16-bajtowy wektor inicjalizacyjny

    Zwraca:
        Odszyfrowane bajty bez paddingu

    Zgłasza:
        ValueError — gdy klucz/IV mają nieprawidłową długość
                   — gdy szyfrogram nie jest wielokrotnością bloku
                   — gdy padding PKCS7 jest nieprawidłowy
    """
    if len(klucz) != ROZMIAR_KLUCZA_AES:
        raise ValueError(
            f"Klucz AES musi mieć {ROZMIAR_KLUCZA_AES} bajtów, "
            f"otrzymano: {len(klucz)} B"
        )
    if len(iv) != ROZMIAR_IV:
        raise ValueError(
            f"IV musi mieć {ROZMIAR_IV} bajtów, otrzymano: {len(iv)} B"
        )
    if len(szyfrogram) == 0 or len(szyfrogram) % ROZMIAR_BLOKU_AES != 0:
        raise ValueError(
            f"Szyfrogram ({len(szyfrogram)} B) musi być niepustą "
            f"wielokrotnością {ROZMIAR_BLOKU_AES} B"
        )

    cipher = Cipher(
        algorithms.AES(klucz),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(szyfrogram) + decryptor.finalize()

    # Usuwamy padding — błędny padding zgłasza ValueError
    return pkcs7_unpad(padded)


# ---------------------------------------------------------------------------
# KOMPLETNY PAKIET: SZYFROWANIE + HMAC
# ---------------------------------------------------------------------------

def zbuduj_pakiet(
    plaintext: bytes,
    klucz_aes: bytes,
    klucz_hmac: bytes,
    session_id: int,
    nonce: int
) -> bytes:
    """
    Buduje kompletny pakiet sieciowy: szyfruje wiadomość i oblicza HMAC.

    Format pakietu (bajtowy):
        [4 B session_id | 4 B nonce | 16 B IV | 32 B HMAC | 4 B len | N B ciphertext]

    Parametry:
        plaintext  — treść wiadomości (bajty UTF-8)
        klucz_aes  — 32-bajtowy klucz AES sesji
        klucz_hmac — 32-bajtowy klucz HMAC sesji
        session_id — identyfikator sesji (int 32-bit)
        nonce      — licznik wiadomości (ochrona przed replay attack)

    Zwraca:
        Skonstruowany pakiet jako bajty
    """
    # Import tutaj, żeby uniknąć cyklicznego importu na poziomie modułu
    from secure_messenger.crypto.hmac_sha256 import oblicz_hmac_pakietu

    iv, szyfrogram = szyfruj_aes_cbc(plaintext, klucz_aes)
    tag_hmac = oblicz_hmac_pakietu(klucz_hmac, iv, szyfrogram)

    pakiet = (
        session_id.to_bytes(4, 'big') +
        nonce.to_bytes(4, 'big') +
        iv +
        tag_hmac +
        len(szyfrogram).to_bytes(4, 'big') +
        szyfrogram
    )
    return pakiet


def rozpakuj_pakiet(
    pakiet: bytes,
    klucz_aes: bytes,
    klucz_hmac: bytes
) -> tuple[int, int, bytes]:
    """
    Rozpakowuje i weryfikuje pakiet sieciowy, zwraca odszyfrowaną wiadomość.

    Kolejność weryfikacji:
        1. Sprawdź minimalną długość pakietu
        2. Wyodrębnij pola nagłówka
        3. Zweryfikuj HMAC (PRZED deszyfrowaniem!)
        4. Odszyfruj AES-CBC

    Parametry:
        pakiet     — surowe bajty pakietu sieciowego
        klucz_aes  — 32-bajtowy klucz AES sesji
        klucz_hmac — 32-bajtowy klucz HMAC sesji

    Zwraca:
        (session_id, nonce, plaintext)

    Zgłasza:
        ValueError — gdy pakiet jest za krótki, HMAC nieprawidłowy lub padding zły
    """
    from secure_messenger.crypto.hmac_sha256 import weryfikuj_hmac_pakietu

    # Minimalny rozmiar: 4+4+16+32+4 = 60 B nagłówka + min 16 B szyfrogramu
    MIN_DLUGOSC = 4 + 4 + 16 + 32 + 4 + 16
    if len(pakiet) < MIN_DLUGOSC:
        raise ValueError(
            f"Pakiet za krótki: {len(pakiet)} B (minimum {MIN_DLUGOSC} B)"
        )

    # Parsowanie pól nagłówka
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

    # Weryfikacja HMAC PRZED deszyfrowaniem
    if not weryfikuj_hmac_pakietu(klucz_hmac, iv, szyfrogram, tag_hmac):
        raise ValueError(
            "Weryfikacja HMAC nieudana — pakiet zmodyfikowany lub błędny klucz"
        )

    # Deszyfrowanie tylko po pozytywnej weryfikacji HMAC
    plaintext = deszyfruj_aes_cbc(szyfrogram, klucz_aes, iv)
    return session_id, nonce, plaintext
