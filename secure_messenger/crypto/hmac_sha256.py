"""
Moduł HMAC-SHA256 — ręczna implementacja bez użycia gotowych bibliotek HMAC.

Implementacja oparta na RFC 2104 (HMAC: Keyed-Hashing for Message Authentication).

Używamy wyłącznie:
    - hashlib.sha256 — surowa funkcja skrótu
    - operacje XOR na bajtach
    - brak: hmac, cryptography, pycryptodome ani żadnej gotowej implementacji HMAC

Schemat HMAC (RFC 2104):
    HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
    gdzie:
        H    = SHA-256
        K'   = klucz dopasowany do rozmiaru bloku SHA-256 (64 bajty)
        ipad = 0x36 powtórzony 64 razy
        opad = 0x5C powtórzony 64 razy
        ||   = konkatenacja
"""

import hashlib


# ---------------------------------------------------------------------------
# STAŁE SHA-256
# ---------------------------------------------------------------------------

# Rozmiar bloku wewnętrznego SHA-256 (512 bitów = 64 bajty)
ROZMIAR_BLOKU: int = 64

# Rozmiar wyjścia SHA-256 (256 bitów = 32 bajty)
ROZMIAR_SKROTU: int = 32

# Wzorce padding (RFC 2104)
IPAD: bytes = bytes([0x36] * ROZMIAR_BLOKU)  # inner padding
OPAD: bytes = bytes([0x5C] * ROZMIAR_BLOKU)  # outer padding


# ---------------------------------------------------------------------------
# FUNKCJE POMOCNICZE
# ---------------------------------------------------------------------------

def _sha256(dane: bytes) -> bytes:
    """Oblicza skrót SHA-256 z podanych bajtów."""
    return hashlib.sha256(dane).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR dwóch ciągów bajtów tej samej długości.
    Python 3.12+: można używać bytes.fromhex, ale pętla jest czytelniejsza.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def _przygotuj_klucz(klucz: bytes) -> bytes:
    """
    Przygotowuje klucz do rozmiaru bloku SHA-256 (64 bajty).

    Reguła RFC 2104:
        - jeśli len(klucz) > 64 → skróć: K' = SHA256(klucz)
        - jeśli len(klucz) < 64 → uzupełnij zerami z prawej
        - jeśli len(klucz) == 64 → użyj bez zmian
    """
    if len(klucz) > ROZMIAR_BLOKU:
        klucz = _sha256(klucz)  # długi klucz → haszujemy
    # Uzupełnienie zerami do 64 bajtów
    return klucz.ljust(ROZMIAR_BLOKU, b'\x00')


# ---------------------------------------------------------------------------
# GŁÓWNA FUNKCJA HMAC-SHA256
# ---------------------------------------------------------------------------

def oblicz_hmac(klucz: bytes, wiadomosc: bytes) -> bytes:
    """
    Oblicza HMAC-SHA256 dla podanej wiadomości i klucza.

    Algorytm (RFC 2104):
        1. K' = przygotuj_klucz(K)          — dopasuj do 64 B
        2. ipad_key = K' XOR ipad            — wewnętrzny padding
        3. opad_key = K' XOR opad            — zewnętrzny padding
        4. inner = SHA256(ipad_key || m)     — wewnętrzny skrót
        5. HMAC  = SHA256(opad_key || inner) — zewnętrzny skrót

    Parametry:
        klucz     — sekretny klucz HMAC (dowolna długość, zalecane 32 B)
        wiadomosc — dane do uwierzytelnienia

    Zwraca:
        32 bajty tagu HMAC-SHA256

    Zgłasza:
        TypeError — gdy klucz lub wiadomosc nie są bajtami
    """
    if not isinstance(klucz, (bytes, bytearray)):
        raise TypeError(f"Klucz musi być typu bytes, otrzymano: {type(klucz).__name__}")
    if not isinstance(wiadomosc, (bytes, bytearray)):
        raise TypeError(f"Wiadomosc musi być typu bytes, otrzymano: {type(wiadomosc).__name__}")

    # Krok 1: przygotowanie klucza
    k_prim = _przygotuj_klucz(bytes(klucz))

    # Krok 2-3: klucze z paddingiem
    ipad_key = _xor_bytes(k_prim, IPAD)
    opad_key = _xor_bytes(k_prim, OPAD)

    # Krok 4: wewnętrzny skrót: H(ipad_key || wiadomosc)
    inner = _sha256(ipad_key + bytes(wiadomosc))

    # Krok 5: zewnętrzny skrót: H(opad_key || inner)
    wynik = _sha256(opad_key + inner)

    return wynik


# ---------------------------------------------------------------------------
# WERYFIKACJA HMAC (BEZPIECZNE PORÓWNANIE)
# ---------------------------------------------------------------------------

def weryfikuj_hmac(klucz: bytes, wiadomosc: bytes, oczekiwany_hmac: bytes) -> bool:
    """
    Weryfikuje tag HMAC w sposób odporny na timing attack.

    Problem naiwnego porównania (a == b):
        Python przerywa porównanie przy pierwszej różnicy → atakujący może
        mierzyć czas odpowiedzi i odgadywać bajt po bajcie.

    Rozwiązanie — porównanie w stałym czasie:
        Oblicz XOR wszystkich bajtów — różni się od zera tylko gdy tagi są różne.
        Wszystkie bajty są zawsze przetwarzane, niezależnie od wyniku.

    Parametry:
        klucz          — klucz HMAC
        wiadomosc      — oryginalna wiadomość
        oczekiwany_hmac — tag do weryfikacji (32 bajty)

    Zwraca:
        True  — tag poprawny (wiadomość autentyczna i nienaruszona)
        False — tag niepoprawny (dane zmodyfikowane lub błędny klucz)
    """
    obliczony = oblicz_hmac(klucz, wiadomosc)

    if len(obliczony) != len(oczekiwany_hmac):
        return False

    # Porównanie w stałym czasie — XOR wszystkich bajtów
    roznica = 0
    for a, b in zip(obliczony, oczekiwany_hmac):
        roznica |= a ^ b

    return roznica == 0


# ---------------------------------------------------------------------------
# HMAC DLA PAKIETU SIECIOWEGO (IV + CIPHERTEXT)
# ---------------------------------------------------------------------------

def oblicz_hmac_pakietu(
    klucz_hmac: bytes,
    iv: bytes,
    szyfrogram: bytes
) -> bytes:
    """
    Oblicza HMAC dla pakietu sieciowego w schemacie Encrypt-then-MAC.

    Uwierzytelniamy: IV || ciphertext (oba razem, nie osobno).
    To chroni zarówno przed modyfikacją szyfrogramu, jak i IV.

    Schemat:
        HMAC = HMAC_SHA256(klucz_hmac, IV || ciphertext)

    Parametry:
        klucz_hmac — 32-bajtowy klucz HMAC sesji
        iv         — wektor inicjalizacyjny AES (16 bajtów)
        szyfrogram — zaszyfrowana treść wiadomości

    Zwraca:
        32-bajtowy tag HMAC
    """
    chroniony_material = iv + szyfrogram
    return oblicz_hmac(klucz_hmac, chroniony_material)


def weryfikuj_hmac_pakietu(
    klucz_hmac: bytes,
    iv: bytes,
    szyfrogram: bytes,
    oczekiwany_hmac: bytes
) -> bool:
    """
    Weryfikuje HMAC pakietu przed deszyfrowaniem (Encrypt-then-MAC).

    WAŻNE: zawsze weryfikuj HMAC PRZED próbą deszyfrowania AES.
    Deszyfrowanie bez weryfikacji HMAC otwiera lukę na atak padding oracle.

    Parametry:
        klucz_hmac     — 32-bajtowy klucz HMAC sesji
        iv             — wektor inicjalizacyjny AES
        szyfrogram     — zaszyfrowana wiadomość
        oczekiwany_hmac — tag HMAC z odebranego pakietu

    Zwraca:
        True  — pakiet autentyczny, można deszyfrować
        False — pakiet zmodyfikowany lub błędny klucz, ODRZUĆ
    """
    chroniony_material = iv + szyfrogram
    return weryfikuj_hmac(klucz_hmac, chroniony_material, oczekiwany_hmac)
