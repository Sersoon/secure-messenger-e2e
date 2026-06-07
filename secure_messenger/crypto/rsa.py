"""RSA — ręczna implementacja edukacyjna. Nie używać produkcyjnie."""

import os
import random


def mod_pow(podstawa: int, wykladnik: int, modulus: int) -> int:
    """(podstawa ^ wykladnik) mod modulus metodą square-and-multiply. O(log e)."""
    if modulus == 1:
        return 0
    wynik: int = 1
    podstawa = podstawa % modulus
    while wykladnik > 0:
        if wykladnik % 2 == 1:
            wynik = (wynik * podstawa) % modulus
        wykladnik //= 2
        podstawa = (podstawa * podstawa) % modulus
    return wynik


def rozszerzony_euklides(a: int, b: int) -> tuple[int, int, int]:
    """Zwraca (g, x, y) takie że a*x + b*y = g = NWD(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = rozszerzony_euklides(b % a, a)
    return g, y1 - (b // a) * x1, x1


def odwrotnosc_modularna(a: int, m: int) -> int:
    """a⁻¹ mod m. Wymaga NWD(a, m) = 1, inaczej ValueError."""
    g, x, _ = rozszerzony_euklides(a % m, m)
    if g != 1:
        raise ValueError(
            f"Odwrotność modularna nie istnieje: NWD({a}, {m}) = {g} ≠ 1"
        )
    return x % m


def miller_rabin(n: int, k: int = 20) -> bool:
    """Probabilistyczny test pierwszości. k rund, P(błąd) < 4⁻ᵏ ≈ 10⁻¹² dla k=20."""
    if n < 2:   return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generuj_liczbe_pierwsza(bity: int) -> int:
    """Losuje kandydatów i testuje Miller-Rabinem do skutku."""
    while True:
        n = int.from_bytes(os.urandom(bity // 8 + 1), byteorder='big')
        n |= (1 << (bity - 1))
        n |= 1
        if miller_rabin(n):
            return n


class KluczeRSA:
    """Para kluczy RSA z opcjonalnymi parametrami CRT (d_p, d_q, q_inv)."""

    def __init__(self, n: int, e: int, d: int, bity: int,
                 p: int | None = None, q: int | None = None):
        self.n = n
        self.e = e
        self.d = d
        self.bity = bity
        self.p = p
        self.q = q
        if p is not None and q is not None:
            self.d_p:   int | None = d % (p - 1)
            self.d_q:   int | None = d % (q - 1)
            self.q_inv: int | None = odwrotnosc_modularna(q, p)
        else:
            self.d_p = self.d_q = self.q_inv = None

    @property
    def ma_parametry_crt(self) -> bool:
        return self.p is not None and self.q is not None

    @property
    def klucz_publiczny(self) -> tuple[int, int]:
        return (self.n, self.e)

    @property
    def klucz_prywatny(self) -> tuple[int, int]:
        return (self.n, self.d)


def generuj_klucze_rsa(bity: int = 1024) -> KluczeRSA:
    """Generuje parę kluczy RSA-{bity}. e = 65537, oblicza parametry CRT."""
    if bity < 512:
        raise ValueError("Minimalna długość klucza RSA to 512 bitów")
    polowa = bity // 2
    p = generuj_liczbe_pierwsza(polowa)
    q = generuj_liczbe_pierwsza(polowa)
    while q == p:
        q = generuj_liczbe_pierwsza(polowa)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    if phi_n <= e or rozszerzony_euklides(e, phi_n)[0] != 1:
        raise RuntimeError("e = 65537 nie jest wzajemnie pierwsze z φ(n) — wygeneruj nowe klucze")
    d = odwrotnosc_modularna(e, phi_n)
    return KluczeRSA(n=n, e=e, d=d, bity=bity, p=p, q=q)


def normaliz_bity_rsa(n: int) -> int:
    """Normalizuje bit_length() modułu n do standardowego rozmiaru klucza (512/1024/2048/4096)."""
    bl = n.bit_length()
    for standard in (512, 1024, 2048, 4096):
        if bl <= standard * 3 // 2:
            return standard
    return bl


def szyfruj_rsa(wiadomosc: bytes, klucz_pub: tuple[int, int]) -> bytes:
    """C = M^e mod n. Wiadomość musi być krótsza niż moduł n."""
    n, e = klucz_pub
    dlugosc_n = (n.bit_length() + 7) // 8
    if len(wiadomosc) >= dlugosc_n:
        raise ValueError(
            f"Wiadomość ({len(wiadomosc)} B) za długa dla klucza RSA "
            f"({dlugosc_n} B). Użyj hybrydowego szyfrowania."
        )
    m = int.from_bytes(wiadomosc, byteorder='big')
    if m >= n:
        raise ValueError("Wartość wiadomości musi być mniejsza niż n")
    c = mod_pow(m, e, n)
    return c.to_bytes(dlugosc_n, byteorder='big')


def deszyfruj_rsa(szyfrogram: bytes, klucz_pryw: tuple[int, int]) -> bytes:
    """M = C^d mod n. Zwraca bajty bez wiodących zer."""
    n, d = klucz_pryw
    dlugosc_n = (n.bit_length() + 7) // 8
    if len(szyfrogram) != dlugosc_n:
        raise ValueError(
            f"Nieprawidłowa długość szyfrogramu: {len(szyfrogram)} B "
            f"(oczekiwano {dlugosc_n} B)"
        )
    c = int.from_bytes(szyfrogram, byteorder='big')
    if c >= n:
        raise ValueError("Szyfrogram wykracza poza zakres modułu n — dane uszkodzone")
    m = mod_pow(c, d, n)
    return m.to_bytes(dlugosc_n, byteorder='big').lstrip(b'\x00') or b'\x00'


def deszyfruj_rsa_crt(szyfrogram: bytes, klucze: 'KluczeRSA') -> bytes:
    """M = C^d mod n metodą CRT (~4× szybciej niż naiwne przez dwa małe potęgowania)."""
    if not klucze.ma_parametry_crt:
        raise RuntimeError("Klucze RSA nie zawierają parametrów CRT (p, q).")
    n = klucze.n
    dlugosc_n = (n.bit_length() + 7) // 8
    if len(szyfrogram) != dlugosc_n:
        raise ValueError(
            f"Nieprawidłowa długość szyfrogramu: {len(szyfrogram)} B "
            f"(oczekiwano {dlugosc_n} B)"
        )
    c = int.from_bytes(szyfrogram, byteorder='big')
    if c >= n:
        raise ValueError("Szyfrogram wykracza poza zakres modułu n — dane uszkodzone")
    m1 = mod_pow(c, klucze.d_p, klucze.p)
    m2 = mod_pow(c, klucze.d_q, klucze.q)
    h = (klucze.q_inv * (m1 - m2)) % klucze.p
    m = m2 + h * klucze.q
    return m.to_bytes(dlugosc_n, byteorder='big').lstrip(b'\x00') or b'\x00'


def szyfruj_klucze_sesji(
    klucz_aes: bytes,
    klucz_hmac: bytes,
    klucz_pub: tuple[int, int]
) -> tuple[bytes, bytes]:
    """Szyfruje klucze AES i HMAC kluczem publicznym RSA (do wymiany kluczy)."""
    return szyfruj_rsa(klucz_aes, klucz_pub), szyfruj_rsa(klucz_hmac, klucz_pub)


def deszyfruj_klucze_sesji(
    zaszyfrowany_aes: bytes,
    zaszyfrowany_hmac: bytes,
    klucz_pryw: tuple[int, int]
) -> tuple[bytes, bytes]:
    """
    Odszyfrowuje klucze AES i HMAC kluczem prywatnym RSA.
    rjust(32) przywraca wiodące zera usunięte przez lstrip w deszyfruj_rsa.
    """
    klucz_aes  = deszyfruj_rsa(zaszyfrowany_aes,  klucz_pryw).rjust(32, b'\x00')
    klucz_hmac = deszyfruj_rsa(zaszyfrowany_hmac, klucz_pryw).rjust(32, b'\x00')
    return klucz_aes, klucz_hmac
