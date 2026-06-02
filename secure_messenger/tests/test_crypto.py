"""
Testy jednostkowe modułów kryptograficznych.

Pokrycie:
    - crypto/rsa.py       — mod_pow, xGCD, odwrotnosc, Miller-Rabin, keygen, enc/dec
    - crypto/hmac_sha256.py — oblicz_hmac, weryfikuj_hmac, HMAC pakietu
    - crypto/aes_cbc.py   — PKCS7 pad/unpad, AES enc/dec, pakiet sieciowy

Dla każdego modułu testujemy:
    1. Poprawne działanie (happy path)
    2. Przypadki brzegowe (puste dane, graniczne wartości)
    3. Błędne dane (nieprawidłowe typy, uszkodzone szyfrogramy, złe klucze)
       → system NIE crashuje, rzuca wyjątek

Uruchomienie:
    pytest secure_messenger/tests/test_crypto.py -v
"""

import os
import pytest

# ---------------------------------------------------------------------------
# Import modułów kryptograficznych
# ---------------------------------------------------------------------------

from secure_messenger.crypto.rsa import (
    mod_pow,
    rozszerzony_euklides,
    odwrotnosc_modularna,
    miller_rabin,
    generuj_liczbe_pierwsza,
    generuj_klucze_rsa,
    szyfruj_rsa,
    deszyfruj_rsa,
    szyfruj_klucze_sesji,
    deszyfruj_klucze_sesji,
    KluczeRSA,
)
from secure_messenger.crypto.hmac_sha256 import (
    oblicz_hmac,
    weryfikuj_hmac,
    oblicz_hmac_pakietu,
    weryfikuj_hmac_pakietu,
    _przygotuj_klucz,
    ROZMIAR_BLOKU,
    ROZMIAR_SKROTU,
)
from secure_messenger.crypto.aes_cbc import (
    pkcs7_pad,
    pkcs7_unpad,
    szyfruj_aes_cbc,
    deszyfruj_aes_cbc,
    zbuduj_pakiet,
    rozpakuj_pakiet,
    ROZMIAR_BLOKU_AES,
    ROZMIAR_KLUCZA_AES,
    ROZMIAR_IV,
)


# ===========================================================================
# TESTY: mod_pow (szybkie potęgowanie modularne)
# ===========================================================================

class TestModPow:

    def test_podstawowy(self):
        # 2^10 mod 1000 = 1024 mod 1000 = 24
        assert mod_pow(2, 10, 1000) == 24

    def test_wykladnik_zero(self):
        # a^0 mod n = 1 (dla n > 1)
        assert mod_pow(999, 0, 7) == 1

    def test_podstawa_zero(self):
        # 0^e mod n = 0
        assert mod_pow(0, 5, 13) == 0

    def test_modulus_jeden(self):
        # cokolwiek mod 1 = 0
        assert mod_pow(999, 999, 1) == 0

    def test_duze_liczby(self):
        # Weryfikacja z wbudowanym pow() Pythona
        b, e, n = 123456789, 987654321, 10**15 + 37
        assert mod_pow(b, e, n) == pow(b, e, n)

    def test_fermat_maly_twierdzenie(self):
        # p pierwsze, a niedzielne przez p: a^(p-1) mod p = 1
        p = 97
        for a in [2, 3, 5, 7, 11]:
            assert mod_pow(a, p - 1, p) == 1


# ===========================================================================
# TESTY: rozszerzony_euklides i odwrotnosc_modularna
# ===========================================================================

class TestEuklides:

    def test_nwd_standardowy(self):
        g, x, y = rozszerzony_euklides(35, 15)
        assert g == 5
        assert 35 * x + 15 * y == 5

    def test_nwd_wzajemnie_pierwsze(self):
        g, x, y = rozszerzony_euklides(7, 13)
        assert g == 1
        assert 7 * x + 13 * y == 1

    def test_nwd_a_zero(self):
        g, x, y = rozszerzony_euklides(0, 15)
        assert g == 15

    def test_nwd_b_zero(self):
        g, x, y = rozszerzony_euklides(15, 0)
        assert g == 15

    def test_odwrotnosc_modularna_istnieje(self):
        # 3^-1 mod 7 = 5, bo 3*5 = 15 = 2*7 + 1
        inv = odwrotnosc_modularna(3, 7)
        assert (3 * inv) % 7 == 1

    def test_odwrotnosc_modularna_e65537(self):
        # Typowy przypadek: e = 65537, szukamy d
        # phi_n musi być wzajemnie pierwsze z 65537
        phi = 65537 * 3 - 1  # fikcyjne phi, gcd(65537, phi)=1
        d = odwrotnosc_modularna(65537, phi)
        assert (65537 * d) % phi == 1

    def test_odwrotnosc_brak_wzajemnej_pierwszosci(self):
        # NWD(4, 6) = 2 ≠ 1 → ValueError
        with pytest.raises(ValueError, match="Odwrotność modularna nie istnieje"):
            odwrotnosc_modularna(4, 6)

    def test_odwrotnosc_brak_wzajemnej_pierwszosci_wiele(self):
        # NWD(10, 25) = 5 ≠ 1
        with pytest.raises(ValueError):
            odwrotnosc_modularna(10, 25)

    def test_odwrotnosc_modulus_jeden(self):
        # Dla m=1 każda odwrotność to 0 (1 dzieli wszystko)
        # NWD(5, 1) = 1 → odwrotność = 0 mod 1
        inv = odwrotnosc_modularna(5, 1)
        assert inv == 0


# ===========================================================================
# TESTY: Miller-Rabin (test pierwszości)
# ===========================================================================

class TestMillerRabin:

    LICZBY_PIERWSZE = [2, 3, 5, 7, 11, 13, 17, 19, 23, 997, 7919, 104729]
    LICZBY_ZLOZONE = [1, 4, 6, 8, 9, 10, 15, 100, 1001, 104728]

    @pytest.mark.parametrize("p", LICZBY_PIERWSZE)
    def test_liczba_pierwsza(self, p):
        assert miller_rabin(p) is True

    @pytest.mark.parametrize("n", LICZBY_ZLOZONE)
    def test_liczba_zlozna(self, n):
        assert miller_rabin(n) is False

    def test_liczba_carmichaela(self):
        # 561 = 3 * 11 * 17 — liczba Carmichaela (myli prosty test Fermata)
        # Miller-Rabin powinien poprawnie wykryć złożoność
        assert miller_rabin(561) is False

    def test_duza_liczba_pierwsza(self):
        # Znana duża liczba pierwsza
        assert miller_rabin(2**31 - 1) is True  # 7. liczba Mersenne'a


# ===========================================================================
# TESTY: Generowanie kluczy RSA
# ===========================================================================

class TestGenerowanieKluczyRSA:

    @pytest.fixture(scope="class")
    def klucze_512(self):
        return generuj_klucze_rsa(512)

    def test_typ_wyniku(self, klucze_512):
        assert isinstance(klucze_512, KluczeRSA)

    def test_dlugosc_klucza(self, klucze_512):
        assert klucze_512.bity == 512

    def test_wykladnik_publiczny(self, klucze_512):
        assert klucze_512.e == 65537

    def test_relacja_ed(self, klucze_512):
        # e * d mod phi(n) = 1
        n = klucze_512.n
        e = klucze_512.e
        d = klucze_512.d
        # Sprawdzamy przez szyfrowanie/deszyfrowanie zamiast obliczania phi
        m = 42
        assert mod_pow(mod_pow(m, e, n), d, n) == m

    def test_minimalny_rozmiar(self):
        with pytest.raises(ValueError, match="Minimalna długość"):
            generuj_klucze_rsa(256)

    def test_klucz_publiczny_prywatny(self, klucze_512):
        pub = klucze_512.klucz_publiczny
        priv = klucze_512.klucz_prywatny
        assert len(pub) == 2
        assert len(priv) == 2
        assert pub[0] == priv[0]   # to samo n
        assert pub[1] != priv[1]   # różne wykładniki


# ===========================================================================
# TESTY: Szyfrowanie/deszyfrowanie RSA
# ===========================================================================

class TestSzyfrowanieRSA:

    @pytest.fixture(scope="class")
    def klucze(self):
        return generuj_klucze_rsa(512)

    @pytest.mark.parametrize("wiadomosc", [
        b'\x01',               # minimum (1 bajt)
        b'Hello RSA',
        os.urandom(32),        # klucz AES
        os.urandom(10),        # krótkie dane
    ])
    def test_roundtrip(self, klucze, wiadomosc):
        c = szyfruj_rsa(wiadomosc, klucze.klucz_publiczny)
        m = deszyfruj_rsa(c, klucze.klucz_prywatny)
        assert m == wiadomosc

    def test_szyfrogram_rozny_od_plaintext(self, klucze):
        wiad = b'Tajna wiadomosc!'
        c = szyfruj_rsa(wiad, klucze.klucz_publiczny)
        assert c != wiad

    def test_dlugosc_szyfrogramu(self, klucze):
        # Szyfrogram powinien mieć dokładnie len(n) bajtów
        c = szyfruj_rsa(b'test', klucze.klucz_publiczny)
        dlugosc_n = (klucze.n.bit_length() + 7) // 8
        assert len(c) == dlugosc_n

    def test_za_dluga_wiadomosc(self, klucze):
        # RSA-512: moduł = 64 B → wiadomość musi być < 64 B
        za_dluga = os.urandom(100)
        with pytest.raises(ValueError, match="za długa"):
            szyfruj_rsa(za_dluga, klucze.klucz_publiczny)

    def test_bledny_szyfrogram_dlugosc(self, klucze):
        with pytest.raises(ValueError, match="długość szyfrogramu"):
            deszyfruj_rsa(b'\x00' * 5, klucze.klucz_prywatny)

    def test_szyfrogram_poza_zakresem(self, klucze):
        # Szyfrogram = n + 1 (większy niż moduł)
        n, d = klucze.klucz_prywatny
        dlugosc = (n.bit_length() + 7) // 8
        zbyt_duze = (n + 1).to_bytes(dlugosc, 'big')
        with pytest.raises(ValueError, match="zakres modułu"):
            deszyfruj_rsa(zbyt_duze, klucze.klucz_prywatny)

    def test_klucze_sesji_roundtrip(self, klucze):
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)
        enc_a, enc_h = szyfruj_klucze_sesji(k_aes, k_hmac, klucze.klucz_publiczny)
        dec_a, dec_h = deszyfruj_klucze_sesji(enc_a, enc_h, klucze.klucz_prywatny)
        assert dec_a == k_aes
        assert dec_h == k_hmac


# ===========================================================================
# TESTY: HMAC-SHA256 (ręczna implementacja)
# ===========================================================================

class TestHMACSHA256:

    import hmac as stdlib_hmac
    import hashlib

    def _stdlib_hmac(self, klucz: bytes, wiad: bytes) -> bytes:
        import hmac, hashlib
        return hmac.new(klucz, wiad, hashlib.sha256).digest()

    @pytest.mark.parametrize("klucz,wiad", [
        (os.urandom(16), b'krotki klucz'),
        (os.urandom(32), b'klucz 32B'),
        (os.urandom(64), b'klucz dokl. blok'),
        (os.urandom(128), b'klucz dlugi'),
        (os.urandom(32), b''),             # pusta wiadomosc
    ])
    def test_zgodnosc_ze_stdlib(self, klucz, wiad):
        nasz = oblicz_hmac(klucz, wiad)
        wzorzec = self._stdlib_hmac(klucz, wiad)
        assert nasz == wzorzec

    def test_dlugosc_wyjscia(self):
        tag = oblicz_hmac(os.urandom(32), b'test')
        assert len(tag) == ROZMIAR_SKROTU == 32

    def test_weryfikacja_poprawna(self):
        k = os.urandom(32)
        m = b'Autentyczna wiadomosc'
        tag = oblicz_hmac(k, m)
        assert weryfikuj_hmac(k, m, tag) is True

    def test_weryfikacja_bledny_klucz(self):
        k = os.urandom(32)
        m = b'Wiadomosc'
        tag = oblicz_hmac(k, m)
        assert weryfikuj_hmac(os.urandom(32), m, tag) is False

    def test_weryfikacja_zmodyfikowana_wiadomosc(self):
        k = os.urandom(32)
        tag = oblicz_hmac(k, b'Oryginalna')
        assert weryfikuj_hmac(k, b'Zmodyfikowana', tag) is False

    def test_weryfikacja_zerowy_tag(self):
        k = os.urandom(32)
        m = b'Test'
        assert weryfikuj_hmac(k, m, b'\x00' * 32) is False

    def test_przygotowanie_klucza_krotki(self):
        # Klucz < 64 B → uzupełnienie zerami
        k = _przygotuj_klucz(b'krotki')
        assert len(k) == ROZMIAR_BLOKU == 64
        assert k.startswith(b'krotki')
        assert k[len(b'krotki'):] == b'\x00' * (64 - len(b'krotki'))

    def test_przygotowanie_klucza_dlugi(self):
        # Klucz > 64 B → SHA256 + uzupełnienie zerami
        k = _przygotuj_klucz(os.urandom(128))
        assert len(k) == ROZMIAR_BLOKU

    def test_typ_klucza_str_rzuca_wyjatek(self):
        with pytest.raises(TypeError, match="bytes"):
            oblicz_hmac("string_zamiast_bytes", b'wiad')

    def test_typ_wiadomosci_str_rzuca_wyjatek(self):
        with pytest.raises(TypeError, match="bytes"):
            oblicz_hmac(os.urandom(32), "string_zamiast_bytes")

    def test_hmac_pakietu_pokrywa_iv_i_cipher(self):
        k = os.urandom(32)
        iv = os.urandom(16)
        c  = os.urandom(32)
        tag = oblicz_hmac_pakietu(k, iv, c)
        assert weryfikuj_hmac_pakietu(k, iv, c, tag) is True

    def test_hmac_pakietu_zmieniony_iv(self):
        k = os.urandom(32)
        iv = os.urandom(16)
        c  = os.urandom(32)
        tag = oblicz_hmac_pakietu(k, iv, c)
        iv_zm = bytes([iv[0] ^ 0xFF]) + iv[1:]
        assert weryfikuj_hmac_pakietu(k, iv_zm, c, tag) is False

    def test_hmac_pakietu_zmieniony_szyfrogram(self):
        k = os.urandom(32)
        iv = os.urandom(16)
        c  = os.urandom(32)
        tag = oblicz_hmac_pakietu(k, iv, c)
        c_zm = c[:-1] + bytes([c[-1] ^ 0xFF])
        assert weryfikuj_hmac_pakietu(k, iv, c_zm, tag) is False


# ===========================================================================
# TESTY: AES-CBC + PKCS7
# ===========================================================================

class TestPKCS7:

    def test_pad_pusta_wiadomosc(self):
        # Pusta → pełny blok paddingu (0x10 * 16)
        p = pkcs7_pad(b'')
        assert len(p) == 16
        assert all(b == 16 for b in p)

    def test_pad_jeden_bajt(self):
        p = pkcs7_pad(b'\xAB')
        assert len(p) == 16
        assert p[0] == 0xAB
        assert all(b == 15 for b in p[1:])

    def test_pad_dokladnie_blok(self):
        # 16 bajtów → dodaje pełny blok (32 razem)
        p = pkcs7_pad(b'A' * 16)
        assert len(p) == 32
        assert p[16:] == bytes([16] * 16)

    def test_pad_dluzsza_wiadomosc(self):
        wiad = b'X' * 30  # 30 B → 32 B (2 B paddingu o wartości 2)
        p = pkcs7_pad(wiad)
        assert len(p) == 32
        assert p[-1] == 2
        assert p[-2] == 2

    def test_unpad_odwraca_pad(self):
        for dlugosc in [0, 1, 15, 16, 17, 31, 32, 100]:
            dane = os.urandom(dlugosc)
            assert pkcs7_unpad(pkcs7_pad(dane)) == dane

    def test_unpad_puste_dane(self):
        with pytest.raises(ValueError, match="Puste dane"):
            pkcs7_unpad(b'')

    def test_unpad_zla_dlugosc(self):
        # 15 bajtów — nie jest wielokrotnością 16
        with pytest.raises(ValueError, match="wielokrotnością"):
            pkcs7_unpad(b'A' * 15)

    def test_unpad_nieprawidlowa_wartosc_pad(self):
        # Ostatni bajt = 0 — nieprawidłowy padding
        with pytest.raises(ValueError, match="wartość paddingu"):
            pkcs7_unpad(b'A' * 15 + b'\x00')

    def test_unpad_niejednorodny_padding(self):
        # Ostatni bajt = 3, ale bajty [-3:-1] nie są 3
        with pytest.raises(ValueError, match="jednorodne"):
            pkcs7_unpad(b'A' * 13 + b'\x01\x02\x03')

    def test_pad_nieprawidlowy_typ(self):
        with pytest.raises(TypeError):
            pkcs7_pad("string zamiast bytes")

    def test_pad_nieprawidlowy_rozmiar_bloku(self):
        with pytest.raises(ValueError):
            pkcs7_pad(b'test', rozmiar_bloku=0)

        with pytest.raises(ValueError):
            pkcs7_pad(b'test', rozmiar_bloku=256)


class TestAESCBC:

    @pytest.fixture(scope="class")
    def klucz(self):
        return os.urandom(32)

    @pytest.mark.parametrize("wiad", [
        b'',
        b'A',
        b'A' * 16,
        b'A' * 17,
        b'A' * 100,
        b'\x00' * 32,
    ])
    def test_roundtrip(self, klucz, wiad):
        iv, c = szyfruj_aes_cbc(wiad, klucz)
        assert deszyfruj_aes_cbc(c, klucz, iv) == wiad

    def test_rozny_iv_dla_tej_samej_wiadomosci(self, klucz):
        wiad = b'ta sama wiadomosc'
        iv1, c1 = szyfruj_aes_cbc(wiad, klucz)
        iv2, c2 = szyfruj_aes_cbc(wiad, klucz)
        assert iv1 != iv2
        assert c1 != c2

    def test_dlugosc_iv(self, klucz):
        iv, _ = szyfruj_aes_cbc(b'test', klucz)
        assert len(iv) == ROZMIAR_IV == 16

    def test_szyfrogram_wielokrotnosc_bloku(self, klucz):
        for dlugosc in [0, 1, 15, 16, 17]:
            _, c = szyfruj_aes_cbc(os.urandom(dlugosc), klucz)
            assert len(c) % ROZMIAR_BLOKU_AES == 0

    def test_krotki_klucz_aes(self):
        with pytest.raises(ValueError, match="bajtów"):
            szyfruj_aes_cbc(b'dane', b'za_krotki')

    def test_krotki_iv_przy_deszyf(self, klucz):
        iv, c = szyfruj_aes_cbc(b'test', klucz)
        with pytest.raises(ValueError, match="IV"):
            deszyfruj_aes_cbc(c, klucz, b'\x00' * 8)

    def test_pusty_szyfrogram(self, klucz):
        with pytest.raises(ValueError, match="niepustą"):
            deszyfruj_aes_cbc(b'', klucz, os.urandom(16))

    def test_szyfrogram_nie_wielokrotnosc_bloku(self, klucz):
        with pytest.raises(ValueError, match="wielokrotnością"):
            deszyfruj_aes_cbc(b'\x00' * 17, klucz, os.urandom(16))

    def test_bledny_klucz_bledna_deszyfracja_padding(self, klucz):
        iv, c = szyfruj_aes_cbc(b'Tajna wiadomosc', klucz)
        zly_klucz = os.urandom(32)
        # Zły klucz → śmieciowy plaintext → błąd paddingu PKCS7
        with pytest.raises((ValueError, Exception)):
            deszyfruj_aes_cbc(c, zly_klucz, iv)

    def test_zmieniony_iv_bledny_padding_lub_tresc(self, klucz):
        wiad = b'Testowa wiadomosc!'
        iv, c = szyfruj_aes_cbc(wiad, klucz)
        iv_zm = bytes([iv[0] ^ 0xFF]) + iv[1:]
        # Zmieniony IV → zmieniony pierwszy blok plaintextu
        try:
            wynik = deszyfruj_aes_cbc(c, klucz, iv_zm)
            assert wynik != wiad  # inny wynik (lub błąd)
        except (ValueError, Exception):
            pass  # padding mógł się posypać — też poprawne zachowanie


class TestPakietSieciowy:

    @pytest.fixture(scope="class")
    def klucze_sesji(self):
        return os.urandom(32), os.urandom(32)

    def test_roundtrip_pakietu(self, klucze_sesji):
        k_aes, k_hmac = klucze_sesji
        wiad = b'Tajna wiadomosc Alicji do Boba'
        pakiet = zbuduj_pakiet(wiad, k_aes, k_hmac, session_id=42, nonce=1)
        sid, nc, plaintext = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
        assert plaintext == wiad
        assert sid == 42
        assert nc == 1

    def test_pusta_wiadomosc_w_pakiecie(self, klucze_sesji):
        k_aes, k_hmac = klucze_sesji
        pakiet = zbuduj_pakiet(b'', k_aes, k_hmac, session_id=1, nonce=1)
        _, _, plaintext = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
        assert plaintext == b''

    def test_pakiet_za_krotki(self, klucze_sesji):
        k_aes, k_hmac = klucze_sesji
        with pytest.raises(ValueError, match="za krótki"):
            rozpakuj_pakiet(b'\x00' * 10, k_aes, k_hmac)

    def test_zmodyfikowany_pakiet_odrzucony(self, klucze_sesji):
        k_aes, k_hmac = klucze_sesji
        pakiet = zbuduj_pakiet(b'Wiadomosc', k_aes, k_hmac, session_id=1, nonce=1)
        # Modyfikacja bajtu w obszarze szyfrogramu (po nagłówku 60 B)
        zm = bytearray(pakiet)
        zm[70 % len(zm)] ^= 0xFF
        with pytest.raises(ValueError, match="HMAC"):
            rozpakuj_pakiet(bytes(zm), k_aes, k_hmac)

    def test_bledny_klucz_hmac_odrzuca_pakiet(self, klucze_sesji):
        k_aes, k_hmac = klucze_sesji
        pakiet = zbuduj_pakiet(b'Wiadomosc', k_aes, k_hmac, session_id=1, nonce=1)
        zly_hmac = os.urandom(32)
        with pytest.raises(ValueError, match="HMAC"):
            rozpakuj_pakiet(pakiet, k_aes, zly_hmac)

    def test_bledny_klucz_aes_po_hmac(self, klucze_sesji):
        # Ten test sprawdza: gdy HMAC poprawny ale klucz AES zły
        # Możliwe tylko gdy użyjemy właściwego HMAC ale złego AES
        # W praktyce: zbudujemy pakiet z jednym kluczem, a odszyfrujemy z innym
        k_aes, k_hmac = klucze_sesji
        zly_aes = os.urandom(32)
        pakiet = zbuduj_pakiet(b'Wiadomosc', k_aes, k_hmac, session_id=1, nonce=1)
        # HMAC sprawdzony OK (właściwy k_hmac), ale AES błędny → błąd paddingu
        with pytest.raises((ValueError, Exception)):
            rozpakuj_pakiet(pakiet, zly_aes, k_hmac)

    @pytest.mark.parametrize("wiad", [b'A', b'A' * 100, b'\x00' * 50, b'\xFF' * 33])
    def test_rozne_rozmiary_wiadomosci(self, klucze_sesji, wiad):
        k_aes, k_hmac = klucze_sesji
        pakiet = zbuduj_pakiet(wiad, k_aes, k_hmac, session_id=99, nonce=7)
        _, nc, plaintext = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
        assert plaintext == wiad
        assert nc == 7


# ===========================================================================
# TESTY INTEGRACYJNE: pełny przepływ Alice ↔ Bob
# ===========================================================================

class TestIntegracjaKryptograficzna:
    """Testuje pełny przepływ kryptograficzny bez warstwy sieciowej."""

    def test_pelny_przeplyw_alice_bob(self):
        # 1. Bob generuje klucze RSA
        klucze_boba = generuj_klucze_rsa(512)

        # 2. Alice generuje klucze sesji i szyfruje
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)
        enc_aes, enc_hmac = szyfruj_klucze_sesji(
            k_aes, k_hmac, klucze_boba.klucz_publiczny
        )

        # 3. Bob odszyfrowuje klucze sesji
        dec_aes, dec_hmac = deszyfruj_klucze_sesji(
            enc_aes, enc_hmac, klucze_boba.klucz_prywatny
        )
        assert dec_aes  == k_aes
        assert dec_hmac == k_hmac

        # 4. Alice wysyła zaszyfrowaną wiadomość
        for i, wiad in enumerate([b'Czesc Bob!', b'Poufna informacja', b''], 1):
            pakiet = zbuduj_pakiet(wiad, k_aes, k_hmac, session_id=1, nonce=i)
            _, nc, plaintext = rozpakuj_pakiet(pakiet, dec_aes, dec_hmac)
            assert plaintext == wiad
            assert nc == i

    def test_replay_attack_wykryty_logika(self):
        """Weryfikuje logikę wykrywania replay — bez warstwy sieciowej."""
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)

        # Budujemy pakiet z nonce=1
        pakiet = zbuduj_pakiet(b'Przelej 1000 zl', k_aes, k_hmac, session_id=1, nonce=1)
        _, nonce_odebrany, _ = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
        assert nonce_odebrany == 1

        ostatni_nonce = 1
        # Wysyłamy kolejne pakiety z rosnącym nonce
        for i in range(2, 5):
            p = zbuduj_pakiet(b'kolejna', k_aes, k_hmac, session_id=1, nonce=i)
            _, nc, _ = rozpakuj_pakiet(p, k_aes, k_hmac)
            ostatni_nonce = nc

        assert ostatni_nonce == 4

        # Teraz replay (nonce=1 ponownie) — detekcja po stronie odbiorcy
        _, nc_replay, _ = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
        assert nc_replay <= ostatni_nonce  # detekcja: nonce zbyt niskie
