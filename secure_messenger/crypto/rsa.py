"""
Moduł RSA — ręczna implementacja od zera.

Zawiera:
- szybkie potęgowanie modularne
- rozszerzony algorytm Euklidesa (xGCD)
- odwrotność modularna
- test pierwszości Miller-Rabin
- generowanie liczb pierwszych
- generowanie kluczy RSA
- szyfrowanie i deszyfrowanie RSA (OAEP-free, edukacyjne)

UWAGA: Ta implementacja jest celowo prosta i służy celom edukacyjnym.
Nie używaj jej w środowiskach produkcyjnych.
"""

import os
import random


# ---------------------------------------------------------------------------
# 1. SZYBKIE POTĘGOWANIE MODULARNE
# ---------------------------------------------------------------------------

def mod_pow(podstawa: int, wykladnik: int, modulus: int) -> int:
    """
    Oblicza (podstawa ^ wykladnik) mod modulus metodą square-and-multiply.

    Złożoność: O(log(wykladnik)) mnożeń — wielokrotnie szybsza od naiwnej pętli.
    Kluczowa dla wydajności RSA: e i d mają zazwyczaj setki/tysiące bitów.

    Algorytm:
        wynik = 1
        podstawa = podstawa mod modulus
        dla każdego bitu wykladnika (od najniższego):
            jeśli bit == 1: wynik = wynik * podstawa mod modulus
            podstawa = podstawa^2 mod modulus
    """
    if modulus == 1:
        return 0
    wynik: int = 1
    podstawa = podstawa % modulus
    while wykladnik > 0:
        # Jeśli aktualny bit jest 1 — uwzględnij bieżącą podstawę w wyniku
        if wykladnik % 2 == 1:
            wynik = (wynik * podstawa) % modulus
        wykladnik //= 2
        podstawa = (podstawa * podstawa) % modulus
    return wynik


# ---------------------------------------------------------------------------
# 2. ROZSZERZONY ALGORYTM EUKLIDESA
# ---------------------------------------------------------------------------

def rozszerzony_euklides(a: int, b: int) -> tuple[int, int, int]:
    """
    Rozszerzony algorytm Euklidesa: znajduje (g, x, y) takie że:
        a*x + b*y = g = NWD(a, b)

    Zwraca:
        (g, x, y) — gdzie g = NWD(a,b), a*x + b*y = g

    Zastosowanie w RSA:
        e * d ≡ 1 (mod φ(n))
        → szukamy d = e⁻¹ mod φ(n)
        → stosujemy: e*x + φ(n)*y = 1 → d = x mod φ(n)
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = rozszerzony_euklides(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


# ---------------------------------------------------------------------------
# 3. ODWROTNOŚĆ MODULARNA
# ---------------------------------------------------------------------------

def odwrotnosc_modularna(a: int, m: int) -> int:
    """
    Oblicza a⁻¹ mod m — odwrotność modularną a względem m.

    Wymaga: NWD(a, m) = 1 (a i m muszą być względnie pierwsze).

    Zastosowanie: obliczenie prywatnego wykładnika d w RSA:
        d = e⁻¹ mod φ(n)

    Zgłasza:
        ValueError — gdy NWD(a, m) ≠ 1 (odwrotność nie istnieje)
    """
    g, x, _ = rozszerzony_euklides(a % m, m)
    if g != 1:
        raise ValueError(
            f"Odwrotność modularna nie istnieje: NWD({a}, {m}) = {g} ≠ 1"
        )
    return x % m


# ---------------------------------------------------------------------------
# 4. TEST PIERWSZOŚCI MILLER-RABIN
# ---------------------------------------------------------------------------

def miller_rabin(n: int, k: int = 20) -> bool:
    """
    Probabilistyczny test pierwszości Miller-Rabin.

    Parametry:
        n — testowana liczba
        k — liczba rund (więcej = mniejsze prawdopodobieństwo błędu)
            Przy k=20: P(błąd) < 4^(-20) ≈ 10^(-12)

    Algorytm:
        1. Zapisz n-1 = 2^r * d (wyciągnij czynniki 2)
        2. Dla k losowych baz a ∈ [2, n-2]:
           a. Oblicz x = a^d mod n
           b. Jeśli x == 1 lub x == n-1 → prawdopodobnie pierwsza, następna runda
           c. Dla i in range(r-1): x = x^2 mod n
              Jeśli x == n-1 → następna runda
           d. Jeśli żaden warunek nie spełniony → liczba złożona

    Zwraca:
        True  — prawdopodobnie pierwsza
        False — na pewno złożona
    """
    # Obsługa małych przypadków
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Krok 1: rozkład n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Krok 2: k rund testu
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue  # Ta baza nie wykryła złożoności

        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # Żadna iteracja nie dała n-1 → liczba złożona
            return False

    return True  # Prawdopodobnie pierwsza


# ---------------------------------------------------------------------------
# 5. GENEROWANIE LICZB PIERWSZYCH
# ---------------------------------------------------------------------------

def _losowy_nieparzysty(bity: int) -> int:
    """Generuje losową nieparzystą liczbę o zadanej długości bitowej."""
    # os.urandom zapewnia kryptograficznie bezpieczną losowość
    n = int.from_bytes(os.urandom(bity // 8 + 1), byteorder='big')
    # Wymuszamy odpowiednią długość: ustawiamy najwyższy i najniższy bit
    n |= (1 << (bity - 1))  # najwyższy bit = 1 (właściwa długość)
    n |= 1                   # najniższy bit = 1 (nieparzysta)
    return n


def generuj_liczbe_pierwsza(bity: int) -> int:
    """
    Generuje losową liczbę pierwszą o zadanej długości bitowej.

    Metoda: losuj kandydatów → testuj Miller-Rabin → powtarzaj do sukcesu.
    Średnio potrzeba ~ln(2^bity) = bity * ln(2) ≈ 0.7 * bity prób
    (twierdzenie o liczbach pierwszych).

    Parametry:
        bity — długość klucza w bitach (np. 512 dla klucza RSA-1024)
    """
    while True:
        kandydat = _losowy_nieparzysty(bity)
        if miller_rabin(kandydat):
            return kandydat


# ---------------------------------------------------------------------------
# 6. GENEROWANIE KLUCZY RSA
# ---------------------------------------------------------------------------

class KluczeRSA:
    """Kontener na parę kluczy RSA: publiczny (n, e) i prywatny (n, d)."""

    def __init__(self, n: int, e: int, d: int, bity: int):
        self.n = n          # moduł RSA
        self.e = e          # wykładnik publiczny
        self.d = d          # wykładnik prywatny
        self.bity = bity    # długość klucza w bitach

    @property
    def klucz_publiczny(self) -> tuple[int, int]:
        """Zwraca klucz publiczny jako (n, e)."""
        return (self.n, self.e)

    @property
    def klucz_prywatny(self) -> tuple[int, int]:
        """Zwraca klucz prywatny jako (n, d)."""
        return (self.n, self.d)

    def __repr__(self) -> str:
        return (
            f"KluczeRSA(bity={self.bity}, "
            f"n={str(self.n)[:20]}..., "
            f"e={self.e})"
        )


def generuj_klucze_rsa(bity: int = 1024) -> KluczeRSA:
    """
    Generuje parę kluczy RSA o zadanej długości.

    Algorytm:
        1. Wybierz dwie różne liczby pierwsze p, q o długości bity/2
        2. Oblicz n = p * q  (moduł RSA)
        3. Oblicz φ(n) = (p-1) * (q-1)  (funkcja Eulera)
        4. Wybierz e: 1 < e < φ(n), NWD(e, φ(n)) = 1
           Standardowo e = 65537 (szybkie potęgowanie, dobra właściwość)
        5. Oblicz d = e⁻¹ mod φ(n)

    Parametry:
        bity — długość klucza (1024 lub 2048 w projekcie)

    Zwraca:
        KluczeRSA z polami n, e, d, bity
    """
    if bity < 512:
        raise ValueError("Minimalna długość klucza RSA to 512 bitów")

    polowa = bity // 2

    # Generujemy p i q — muszą być różne
    p = generuj_liczbe_pierwsza(polowa)
    q = generuj_liczbe_pierwsza(polowa)
    while q == p:
        q = generuj_liczbe_pierwsza(polowa)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Standardowy wykładnik publiczny: e = 65537 = 2^16 + 1
    # Fermat F4 — tylko 2 bity ustawione → szybkie potęgowanie
    e = 65537
    if phi_n <= e or rozszerzony_euklides(e, phi_n)[0] != 1:
        raise RuntimeError("e = 65537 nie jest wzajemnie pierwsze z φ(n) — wygeneruj nowe klucze")

    d = odwrotnosc_modularna(e, phi_n)

    return KluczeRSA(n=n, e=e, d=d, bity=bity)


# ---------------------------------------------------------------------------
# 7. SZYFROWANIE I DESZYFROWANIE RSA
# ---------------------------------------------------------------------------

def _bytes_na_int(data: bytes) -> int:
    """Konwertuje bajty na liczbę całkowitą (big-endian)."""
    return int.from_bytes(data, byteorder='big')


def _int_na_bytes(liczba: int, dlugosc: int) -> bytes:
    """Konwertuje liczbę całkowitą na bajty o zadanej długości (big-endian)."""
    return liczba.to_bytes(dlugosc, byteorder='big')


def szyfruj_rsa(wiadomosc: bytes, klucz_pub: tuple[int, int]) -> bytes:
    """
    Szyfruje wiadomość kluczem publicznym RSA.

    Operacja: C = M^e mod n
    gdzie M = wiadomość jako liczba całkowita.

    Ograniczenie: wiadomość musi być krótsza niż n (moduł).
    W projekcie: szyfrujemy tylko klucze AES (32 B) i HMAC (32 B),
    więc nawet dla RSA-1024 (128 B) jest wystarczająco miejsca.

    Parametry:
        wiadomosc  — bajty do zaszyfrowania (maks. dlugosc_n - 1 bajtów)
        klucz_pub  — (n, e) klucz publiczny

    Zwraca:
        Zaszyfrowane bajty (długość = dlugosc_n bajtów)

    Zgłasza:
        ValueError — gdy wiadomość jest za długa dla danego modułu
    """
    n, e = klucz_pub
    dlugosc_n = (n.bit_length() + 7) // 8  # długość modułu w bajtach

    if len(wiadomosc) >= dlugosc_n:
        raise ValueError(
            f"Wiadomość ({len(wiadomosc)} B) za długa dla klucza RSA "
            f"({dlugosc_n} B). Użyj hybrydowego szyfrowania."
        )

    m = _bytes_na_int(wiadomosc)
    if m >= n:
        raise ValueError("Wartość wiadomości musi być mniejsza niż n")

    c = mod_pow(m, e, n)
    return _int_na_bytes(c, dlugosc_n)


def deszyfruj_rsa(szyfrogram: bytes, klucz_pryw: tuple[int, int]) -> bytes:
    """
    Deszyfruje szyfrogram kluczem prywatnym RSA.

    Operacja: M = C^d mod n

    Parametry:
        szyfrogram  — bajty do odszyfrowania
        klucz_pryw  — (n, d) klucz prywatny

    Zwraca:
        Odszyfrowane bajty (z usuniętymi wiodącymi zerami)

    Zgłasza:
        ValueError — gdy szyfrogram jest nieprawidłowy lub uszkodzony
    """
    n, d = klucz_pryw
    dlugosc_n = (n.bit_length() + 7) // 8

    if len(szyfrogram) != dlugosc_n:
        raise ValueError(
            f"Nieprawidłowa długość szyfrogramu: {len(szyfrogram)} B "
            f"(oczekiwano {dlugosc_n} B)"
        )

    c = _bytes_na_int(szyfrogram)
    if c >= n:
        raise ValueError("Szyfrogram wykracza poza zakres modułu n — dane uszkodzone")

    m = mod_pow(c, d, n)

    # Odtwarzamy bajty — wiodące zera są usuwane przez to_bytes tylko jeśli
    # podamy za małą długość; zwracamy strip lewych zer
    wynik = _int_na_bytes(m, dlugosc_n)
    # Usuwamy padding zerowy z lewej strony (artefakt konwersji int→bytes)
    return wynik.lstrip(b'\x00') or b'\x00'


# ---------------------------------------------------------------------------
# 8. SZYFROWANIE PARY KLUCZY AES+HMAC (FUNKCJA POMOCNICZA)
# ---------------------------------------------------------------------------

def szyfruj_klucze_sesji(
    klucz_aes: bytes,
    klucz_hmac: bytes,
    klucz_pub: tuple[int, int]
) -> tuple[bytes, bytes]:
    """
    Szyfruje klucz AES i klucz HMAC osobno kluczem publicznym RSA.

    Używana przez Alice podczas wymiany kluczy:
        Alice → Bob: (RSA(klucz_aes), RSA(klucz_hmac))

    Parametry:
        klucz_aes  — 32 bajty klucza AES-256
        klucz_hmac — 32 bajty klucza HMAC-SHA256
        klucz_pub  — klucz publiczny Boba (n, e)

    Zwraca:
        (zaszyfrowany_aes, zaszyfrowany_hmac) — dwa szyfrogramy RSA
    """
    zaszyfrowany_aes = szyfruj_rsa(klucz_aes, klucz_pub)
    zaszyfrowany_hmac = szyfruj_rsa(klucz_hmac, klucz_pub)
    return zaszyfrowany_aes, zaszyfrowany_hmac


def deszyfruj_klucze_sesji(
    zaszyfrowany_aes: bytes,
    zaszyfrowany_hmac: bytes,
    klucz_pryw: tuple[int, int]
) -> tuple[bytes, bytes]:
    """
    Odszyfrowuje klucze sesji AES i HMAC kluczem prywatnym RSA.

    Używana przez Boba po otrzymaniu zaszyfrowanych kluczy od Alice.

    Parametry:
        zaszyfrowany_aes  — szyfrogram klucza AES
        zaszyfrowany_hmac — szyfrogram klucza HMAC
        klucz_pryw        — klucz prywatny Boba (n, d)

    Zwraca:
        (klucz_aes, klucz_hmac) — odszyfrowane klucze sesji (po 32 bajty)

    Uwaga: rjust(32) przywraca wiodące zera usuniete przez lstrip w deszyfruj_rsa.
    Textbook RSA nie koduje dlugosci — bity wiodace klucza AES/HMAC sa tracone
    przy konwersji int->bytes i musza byc tu przywrocone.
    """
    klucz_aes  = deszyfruj_rsa(zaszyfrowany_aes,  klucz_pryw).rjust(32, b'\x00')
    klucz_hmac = deszyfruj_rsa(zaszyfrowany_hmac, klucz_pryw).rjust(32, b'\x00')
    return klucz_aes, klucz_hmac
