"""
Demonstracje podatności kryptograficznych — cel edukacyjny.

Zawiera trzy eksperymenty:
    1. DemoECBvsCBC             — ECB ujawnia wzorce; CBC z losowym IV ich nie ujawnia
    2. DemoBezNonce             — replay attack przechodzi gdy brak ochrony nonce
    3. DemoManipulacjaSzyfrogramu — bit-flip na szyfrogram: HMAC wykrywa, brak HMAC nie

MITM i Replay w środowisku sieciowym są zaimplementowane interaktywnie
w warstwie serwera (network/server.py) i sterowane z GUI serwera.
"""

import os
from collections import Counter
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from secure_messenger.crypto.aes_cbc import (
    zbuduj_pakiet, rozpakuj_pakiet, deszyfruj_aes_cbc,
)


# ---------------------------------------------------------------------------
# DEMO 1: ECB vs CBC
# ---------------------------------------------------------------------------

@dataclass
class WynikECBvsCBC:
    klucz: bytes
    plaintext: bytes
    szyfrogram_ecb: bytes
    szyfrogram_cbc: bytes
    identyczne_bloki_ecb: int   # ile bloków szyfrogramu ECB się powtarza
    identyczne_bloki_cbc: int   # powinno być 0


class DemoECBvsCBC:
    """
    Szyfruje powtarzający się plaintext w trybie ECB i CBC.

    ECB (Electronic Codebook): każdy 16-bajtowy blok szyfrowany niezależnie
    tym samym kluczem → identyczne bloki plaintextu dają identyczne bloki
    szyfrogramu → atakujący bez klucza widzi wzorce strukturalne.

    CBC (Cipher Block Chaining): każdy blok XOR-owany z poprzednim
    szyfrogramem przed szyfrowaniem + losowy IV → żadne dwa bloki
    szyfrogramu nie są identyczne nawet dla identycznego plaintextu.
    """

    def uruchom(self, liczba_blokow: int = 4) -> WynikECBvsCBC:
        """
        Parametry:
            liczba_blokow — ile razy powtórzyć 16-bajtowy blok plaintextu

        Zwraca:
            WynikECBvsCBC z szyfrogramami ECB i CBC oraz liczbą
            identycznych bloków w każdym z nich.
        """
        klucz = os.urandom(32)
        blok = b'POUFNY_BLOK_!!!!'          # dokładnie 16 B
        plaintext = blok * liczba_blokow

        # ECB — bez IV, każdy blok niezależnie
        c_ecb = Cipher(algorithms.AES(klucz), modes.ECB(), backend=default_backend())
        enc = c_ecb.encryptor()
        szyfr_ecb = enc.update(plaintext) + enc.finalize()

        # CBC — z losowym IV
        iv = os.urandom(16)
        c_cbc = Cipher(algorithms.AES(klucz), modes.CBC(iv), backend=default_backend())
        enc = c_cbc.encryptor()
        szyfr_cbc = enc.update(plaintext) + enc.finalize()

        bloki_ecb = [szyfr_ecb[i:i+16] for i in range(0, len(szyfr_ecb), 16)]
        bloki_cbc = [szyfr_cbc[i:i+16] for i in range(0, len(szyfr_cbc), 16)]
        # Liczymy bloki ktore wystepuja wiecej niz raz (sum zliczeń > 1).
        # Dla 4 identycznych blokow: Counter = {blok: 4}, suma = 4 (nie 3).
        identyczne_ecb = sum(cnt for cnt in Counter(bloki_ecb).values() if cnt > 1)
        identyczne_cbc = sum(cnt for cnt in Counter(bloki_cbc).values() if cnt > 1)

        return WynikECBvsCBC(
            klucz=klucz,
            plaintext=plaintext,
            szyfrogram_ecb=szyfr_ecb,
            szyfrogram_cbc=szyfr_cbc,
            identyczne_bloki_ecb=identyczne_ecb,
            identyczne_bloki_cbc=identyczne_cbc,
        )

    def formatuj(self, wynik: WynikECBvsCBC) -> str:
        """Zwraca czytelny raport tekstowy dla GUI / terminala."""
        bloki_ecb = [wynik.szyfrogram_ecb[i:i+16] for i in range(0, len(wynik.szyfrogram_ecb), 16)]
        bloki_cbc = [wynik.szyfrogram_cbc[i:i+16] for i in range(0, len(wynik.szyfrogram_cbc), 16)]
        n = len(bloki_ecb)

        linie = [
            f"Plaintext: {n} identycznych blokow po 16 B: '{wynik.plaintext[:16].decode()}'",
            "",
            "Szyfrogram ECB:",
        ]
        for blok in bloki_ecb:
            linie.append(f"  [{blok.hex()}]")
        linie.append(
            f"  [!] Wykryto {wynik.identyczne_bloki_ecb} identyczne bloki szyfrogramu"
            f" -- wzorzec widoczny bez znajomosci klucza!"
        )
        linie += ["", "Szyfrogram CBC:"]
        for blok in bloki_cbc:
            linie.append(f"  [{blok.hex()}]")
        linie.append(
            f"  [OK] Brak powtorek ({wynik.identyczne_bloki_cbc} identycznych blokow)"
            f" -- kazdy blok unikalny"
        )
        return "\n".join(linie)


# ---------------------------------------------------------------------------
# DEMO 2: Replay attack — z nonce i bez
# ---------------------------------------------------------------------------

@dataclass
class WynikDemoReplay:
    wiadomosc: str
    wyniki_bez_nonce: list[str]   # każde wysłanie replaya akceptowane
    wyniki_z_nonce: list[str]     # replay odrzucony po pierwszym odebraniu


class DemoBezNonce:
    """
    Demonstracja replay attack bez ochrony nonce.

    Atakujący przechwytuje pakiet (np. "Przelej 1000 zł") i wysyła go
    ponownie. Pakiet ma poprawny HMAC (nie był modyfikowany), więc bez
    ochrony nonce odbiorca akceptuje go wielokrotnie.

    Z nonce: odbiorca pamięta ostatni odebrany nonce. Każdy pakiet
    z nonce ≤ ostatni_nonce jest odrzucany.
    """

    def uruchom(self, wiadomosc: str = "Przelej 1000 zl", powtorzenia: int = 3) -> WynikDemoReplay:
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)

        # Budujemy jeden pakiet — atakujący go przechwytuje
        pakiet = zbuduj_pakiet(wiadomosc.encode(), k_aes, k_hmac, session_id=1, nonce=1)

        # --- bez ochrony nonce: każde rozpakowanie przechodzi ---
        wyniki_bez = []
        for i in range(powtorzenia):
            _, nc, pt = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
            wyniki_bez.append(f"Próba {i+1}: AKCEPTOWANY (nonce={nc}, treść='{pt.decode()}')")

        # --- z ochroną nonce ---
        wyniki_z = []
        ostatni_nonce = 0
        for i in range(powtorzenia):
            _, nc, pt = rozpakuj_pakiet(pakiet, k_aes, k_hmac)
            if nc <= ostatni_nonce and ostatni_nonce > 0:
                wyniki_z.append(
                    f"Proba {i+1}: ODRZUCONY -- replay attack! "
                    f"(nonce={nc} <= ostatni={ostatni_nonce})"
                )
            else:
                ostatni_nonce = nc
                wyniki_z.append(f"Próba {i+1}: AKCEPTOWANY (nonce={nc}, treść='{pt.decode()}')")

        return WynikDemoReplay(
            wiadomosc=wiadomosc,
            wyniki_bez_nonce=wyniki_bez,
            wyniki_z_nonce=wyniki_z,
        )

    def formatuj(self, wynik: WynikDemoReplay) -> str:
        linie = [
            f"Wiadomość: \"{wynik.wiadomosc}\"",
            "",
            "BEZ ochrony nonce (każdy replay przechodzi):",
        ]
        linie += [f"  {w}" for w in wynik.wyniki_bez_nonce]
        linie += ["", "Z ochroną nonce (replay odrzucany):"]
        linie += [f"  {w}" for w in wynik.wyniki_z_nonce]
        return "\n".join(linie)


# ---------------------------------------------------------------------------
# DEMO 3: Manipulacja szyfrogramem — bit-flip i rola HMAC
# ---------------------------------------------------------------------------

@dataclass
class WynikDemoManipulacji:
    wiadomosc: str
    offset: int           # pozycja zmodyfikowanego bajtu w szyfrogramie
    bajt_przed: int       # wartość oryginalna
    bajt_po: int          # wartość po modyfikacji
    wynik_hmac: str       # komunikat z weryfikacji HMAC
    plaintext_oryginalny: bytes
    plaintext_bez_hmac: bytes   # co odbiorca dostanie bez weryfikacji HMAC


class DemoManipulacjaSzyfrogramu:
    """
    Demonstruje atak bit-flip na szyfrogram AES-CBC i rolę HMAC.

    Atakujący modyfikuje jeden bajt szyfrogramu w trakcie transmisji.
    Z HMAC (Encrypt-then-MAC): odbiorca wykrywa modyfikację i odrzuca pakiet.
    Bez HMAC: deszyfrowanie przebiega bez błędu, ale plaintext jest uszkodzony
              — odbiorca nie wie że dane są zmanipulowane.

    Właściwość bit-flip CBC:
        Zmiana bajtu w bloku i niszczy cały blok i (16 B śmieci)
        i odwraca odpowiedni bit w bloku i+1 (kontrolowana zmiana).
        Atakujący znający plaintext może celowo zmodyfikować kolejny blok.
    """

    # Layout pakietu: 4B session_id + 4B nonce + 16B IV + 32B HMAC + 4B len + szyfrogram
    _OFFSET_SZYFROGRAM = 4 + 4 + 16 + 32 + 4  # = 60

    def uruchom(self, wiadomosc: str = "Przelej 1000 zl na konto 12345") -> WynikDemoManipulacji:
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)

        pakiet = zbuduj_pakiet(wiadomosc.encode(), k_aes, k_hmac, session_id=1, nonce=1)

        # Atakujący zmienia pierwszy bajt szyfrogramu (XOR 0xFF = odwrócenie wszystkich bitów)
        offset = self._OFFSET_SZYFROGRAM
        bajt_przed = pakiet[offset]
        bajt_po = bajt_przed ^ 0xFF
        pakiet_zmod = bytearray(pakiet)
        pakiet_zmod[offset] = bajt_po
        pakiet_zmod = bytes(pakiet_zmod)

        # Próba rozpakowania z weryfikacją HMAC
        try:
            rozpakuj_pakiet(pakiet_zmod, k_aes, k_hmac)
            wynik_hmac = "AKCEPTOWANY (nieoczekiwane — HMAC powinien wykryc zmiane)"
        except ValueError as exc:
            wynik_hmac = str(exc)

        # Odszyfrowanie BEZ weryfikacji HMAC (co by się stało bez HMAC)
        iv = pakiet[8:24]
        szyfrogram_zmod = pakiet_zmod[offset:]
        try:
            pt_zmod = deszyfruj_aes_cbc(szyfrogram_zmod, k_aes, iv)
        except Exception as exc:
            pt_zmod = f"[BLAD PADDINGU: {exc}]".encode()

        return WynikDemoManipulacji(
            wiadomosc=wiadomosc,
            offset=offset,
            bajt_przed=bajt_przed,
            bajt_po=bajt_po,
            wynik_hmac=wynik_hmac,
            plaintext_oryginalny=wiadomosc.encode(),
            plaintext_bez_hmac=pt_zmod,
        )

    def formatuj(self, wynik: WynikDemoManipulacji) -> str:
        poz = wynik.offset - self._OFFSET_SZYFROGRAM  # pozycja w samym szyfrogramie
        pt_zmod = wynik.plaintext_bez_hmac
        try:
            pt_str = pt_zmod.decode('utf-8', errors='replace')
        except Exception:
            pt_str = repr(pt_zmod)

        linie = [
            f"Wiadomosc: \"{wynik.wiadomosc}\"",
            f"Atakujacy zmienia bajt {poz} szyfrogramu:"
            f" 0x{wynik.bajt_przed:02X} -> 0x{wynik.bajt_po:02X} (XOR 0xFF)",
            "",
            "Z weryfikacja HMAC (Encrypt-then-MAC):",
            f"  ODRZUCONY -- {wynik.wynik_hmac}",
            "",
            "BEZ weryfikacji HMAC (gdyby nie bylo HMAC):",
            f"  Odszyfrowano: \"{pt_str}\"",
            f"  Oryginalne:   \"{wynik.wiadomosc}\"",
            "",
            "Wlasciwosc bit-flip CBC:",
            "  Zmiana 1 bajtu w bloku i  -> caly blok i (16 B) zamienia sie w smieci.",
            "  Jednoczesnie odwraca odpowiedni bit w bloku i+1 (przewidywalna zmiana).",
            "  Atakujacy znajacy plaintext moze celowo zmodyfikowac tresc kolejnego bloku.",
            "  HMAC wykrywa kazda modyfikacje szyfrogramu niezaleznie od jej wielkosci.",
        ]
        return "\n".join(linie)
