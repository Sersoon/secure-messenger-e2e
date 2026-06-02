"""
Moduł symulacji ataków kryptograficznych — cel edukacyjny.

Implementuje dwa ataki:
    1. MITM (Man-in-the-Middle) — podmiana klucza publicznego RSA
    2. Replay Attack         — ponowne wysłanie przechwyconego pakietu

WAŻNE: Ten kod służy wyłącznie do demonstracji i nauki.
Pokazuje mechanizm działania ataków i ich skutki.
"""

import os
import threading
import time
import socket
from typing import Callable, Optional

from secure_messenger.crypto.rsa import (
    generuj_klucze_rsa, KluczeRSA,
    szyfruj_klucze_sesji, deszyfruj_klucze_sesji
)
from secure_messenger.crypto.aes_cbc import (
    zbuduj_pakiet, rozpakuj_pakiet, szyfruj_aes_cbc, deszyfruj_aes_cbc
)
from secure_messenger.crypto.hmac_sha256 import oblicz_hmac_pakietu


# ---------------------------------------------------------------------------
# STRUKTURY WYNIKÓW
# ---------------------------------------------------------------------------

class WynikAtakuMITM:
    """Przechowuje wynik symulacji ataku MITM — dane odczytane i zmodyfikowane przez Eve."""

    def __init__(self):
        self.etapy: list[tuple[str, str]] = []      # (etap, opis)
        self.wiadomosci_eve: list[str] = []          # wiadomości odczytane przez Eve
        self.wiadomosci_zmodyfikowane: list[tuple[str, str]] = []  # (oryginał, po modyfikacji)
        self.klucz_aes_eve: Optional[bytes] = None
        self.klucz_hmac_eve: Optional[bytes] = None
        self.sukces: bool = False

    def dodaj_etap(self, nr: str, opis: str) -> None:
        """Rejestruje krok ataku do wyświetlenia w GUI."""
        self.etapy.append((nr, opis))

    def __repr__(self) -> str:
        return (
            f"WynikAtakuMITM(sukces={self.sukces}, "
            f"odczytane={len(self.wiadomosci_eve)}, "
            f"etapy={len(self.etapy)})"
        )


class WynikAtakuReplay:
    """Przechowuje wynik symulacji ataku Replay."""

    def __init__(self):
        self.etapy: list[tuple[str, str]] = []
        self.pakiety_wyslane: int = 0
        self.pakiety_replay: int = 0
        self.pakiety_wykryte: int = 0
        self.sukces_ataku: bool = False   # True gdy choć jeden replay przeszedł

    def dodaj_etap(self, nr: str, opis: str) -> None:
        self.etapy.append((nr, opis))


# ---------------------------------------------------------------------------
# ATAK 1: MAN-IN-THE-MIDDLE (MITM)
# ---------------------------------------------------------------------------

class AtakMITM:
    """
    Symulacja ataku Man-in-the-Middle na wymianę kluczy RSA.

    Scenariusz:
        1. Bob generuje klucze RSA (n_bob, e_bob, d_bob)
        2. Eve przechwytuje klucz publiczny Boba (n_bob, e_bob)
        3. Eve generuje własne klucze RSA (n_eve, e_eve, d_eve)
        4. Eve wysyła Alice swój klucz publiczny (n_eve, e_eve) zamiast Boba
        5. Alice szyfruje klucze AES+HMAC kluczem EVE (myśląc że to Bob)
        6. Eve odszyfrowuje → zna klucze sesji!
        7. Eve re-szyfruje klucze kluczem Boba i przekazuje
        8. Wszystkie wiadomości Alice↔Bob są teraz widoczne dla Eve

    Luka: brak weryfikacji tożsamości (brak certyfikatów PKI).
    """

    def symuluj(
        self,
        wiadomosci_alice: list[str],
        modyfikacja: Optional[Callable[[str], str]] = None,
        bity_rsa: int = 512,
        on_postep: Optional[Callable[[str, str], None]] = None
    ) -> WynikAtakuMITM:
        """
        Przeprowadza pełną symulację ataku MITM.

        Parametry:
            wiadomosci_alice — lista wiadomości które Alice chce wysłać
            modyfikacja      — funkcja(str) → str modyfikująca treść (None = tylko podsłuch)
            bity_rsa         — długość kluczy RSA (512 dla szybkości w demo)
            on_postep        — callback(etap, opis) do śledzenia postępu w GUI

        Zwraca:
            WynikAtakuMITM z pełnym opisem ataku
        """
        wynik = WynikAtakuMITM()

        def krok(nr: str, opis: str) -> None:
            wynik.dodaj_etap(nr, opis)
            if on_postep:
                on_postep(nr, opis)

        # ---- ETAP 1: Bob generuje swoje klucze RSA ----
        krok("1", f"Bob generuje klucze RSA-{bity_rsa}...")
        klucze_boba = generuj_klucze_rsa(bity_rsa)
        n_bob, e_bob = klucze_boba.klucz_publiczny
        krok("1", f"Bob ma klucz pub: n={str(n_bob)[:16]}..., e={e_bob}")

        # ---- ETAP 2: Bob wysyła klucz pub — Eve przechwytuje ----
        krok("2", "Bob wysyła klucz publiczny RSA → Eve PRZECHWYTUJE!")
        krok("2", f"Eve widzi klucz Boba: n={str(n_bob)[:16]}...")

        # ---- ETAP 3: Eve generuje własne klucze RSA ----
        krok("3", f"Eve generuje własne klucze RSA-{bity_rsa}...")
        klucze_eve = generuj_klucze_rsa(bity_rsa)
        n_eve, e_eve = klucze_eve.klucz_publiczny
        krok("3", f"Eve ma swój klucz pub: n={str(n_eve)[:16]}..., e={e_eve}")

        # ---- ETAP 4: Eve podaje Alice swój klucz zamiast Boba ----
        krok("4", "Eve wysyła Alice SWÓJ klucz publiczny zamiast Boba!")
        krok("4", "Alice myśli, że ma klucz Boba — a ma klucz Eve!")

        # ---- ETAP 5: Alice szyfruje klucze sesji (kluczem Eve!) ----
        krok("5", "Alice generuje klucze sesji AES + HMAC")
        k_aes_alice  = os.urandom(32)
        k_hmac_alice = os.urandom(32)

        krok("5", "Alice szyfruje klucze RSA... (używa klucza Eve!)")
        # Alice szyfruje kluczem Eve, bo myśli że to Bob
        enc_aes, enc_hmac = szyfruj_klucze_sesji(
            k_aes_alice, k_hmac_alice, klucze_eve.klucz_publiczny
        )
        krok("5", f"Alice wysyła zaszyfrowane klucze → Eve PRZECHWYTUJE!")

        # ---- ETAP 6: Eve odszyfrowuje kluczem prywatnym ----
        krok("6", "Eve odszyfrowuje kluczem PRYWATNYM Eve!")
        k_aes_eve, k_hmac_eve = deszyfruj_klucze_sesji(
            enc_aes, enc_hmac, klucze_eve.klucz_prywatny
        )
        assert k_aes_eve  == k_aes_alice
        assert k_hmac_eve == k_hmac_alice

        wynik.klucz_aes_eve  = k_aes_eve
        wynik.klucz_hmac_eve = k_hmac_eve
        krok("6", f"Eve zna klucz AES:  {k_aes_eve.hex()[:20]}...")
        krok("6", f"Eve zna klucz HMAC: {k_hmac_eve.hex()[:20]}...")

        # ---- ETAP 7: Eve re-szyfruje i przekazuje Bobowi ----
        krok("7", "Eve re-szyfruje klucze kluczem PUBLICZNYM Boba i przekazuje")
        enc_aes_do_boba, enc_hmac_do_boba = szyfruj_klucze_sesji(
            k_aes_alice, k_hmac_alice, klucze_boba.klucz_publiczny
        )
        k_aes_bob, k_hmac_bob = deszyfruj_klucze_sesji(
            enc_aes_do_boba, enc_hmac_do_boba, klucze_boba.klucz_prywatny
        )
        assert k_aes_bob  == k_aes_alice
        assert k_hmac_bob == k_hmac_alice
        krok("7", "Bob odszyfrowuje i aktywuje SECURE MODE — nie wie o ataku!")

        # ---- ETAP 8: Eve czyta i modyfikuje wiadomości Alice ----
        krok("8", f"Alice wysyła {len(wiadomosci_alice)} wiadomości — Eve wszystko czyta!")
        session_id = int.from_bytes(os.urandom(4), 'big')

        for i, tresc in enumerate(wiadomosci_alice, 1):
            # Alice szyfruje (wie tylko o kluczach sesji, nie wie o Eve)
            pakiet_alice = zbuduj_pakiet(
                tresc.encode('utf-8'), k_aes_alice, k_hmac_alice,
                session_id=session_id, nonce=i
            )

            # Eve przechwytuje i odszyfrowuje
            _, _, plaintext_eve = rozpakuj_pakiet(pakiet_alice, k_aes_eve, k_hmac_eve)
            odczytana = plaintext_eve.decode('utf-8')
            wynik.wiadomosci_eve.append(odczytana)

            if modyfikacja:
                # Eve modyfikuje treść i re-szyfruje
                zmodyfikowana = modyfikacja(odczytana)
                wynik.wiadomosci_zmodyfikowane.append((odczytana, zmodyfikowana))
                pakiet_do_boba = zbuduj_pakiet(
                    zmodyfikowana.encode('utf-8'), k_aes_bob, k_hmac_bob,
                    session_id=session_id, nonce=i
                )
                _, _, plaintext_bob = rozpakuj_pakiet(pakiet_do_boba, k_aes_bob, k_hmac_bob)
                krok("8", f"  Wiad. {i}: '{odczytana}' → Eve zmienia na: '{zmodyfikowana}'")
            else:
                krok("8", f"  Wiad. {i}: Eve czyta: '{odczytana}' (przekazuje bez zmian)")

        wynik.sukces = True
        krok("9", "ATAK MITM ZAKOŃCZONY SUKCESEM — Eve znała wszystkie wiadomości!")
        krok("9", "Obrona: certyfikaty PKI lub weryfikacja fingerprint klucza pub")
        return wynik


# ---------------------------------------------------------------------------
# ATAK 2: REPLAY ATTACK
# ---------------------------------------------------------------------------

class AtakReplay:
    """
    Symulacja ataku Replay — ponowne wysłanie przechwyconego pakietu.

    Scenariusz:
        1. Alice wysyła wiadomość do Boba (np. "Przelej 1000 zł")
        2. Atakujący przechwytuje zaszyfrowany pakiet
        3. Atakujący wysyła ten sam pakiet ponownie (bez deszyfrowania!)
        4. Bob sprawdza nonce — wykrywa duplikat → odrzuca

    Ochrona: monotonicznie rosnący nonce per sesja.
    Słabość naiwna: brak nonce → Bob przetwarza duplikat jako nową wiadomość.
    """

    def symuluj(
        self,
        wiadomosc: str,
        ile_replay: int = 3,
        on_postep: Optional[Callable[[str, str], None]] = None
    ) -> WynikAtakuReplay:
        """
        Symuluje atak replay z ochroną nonce.

        Parametry:
            wiadomosc  — treść wiadomości do przechwycenia i powtórzenia
            ile_replay — ile razy atakujący próbuje ponownie wysłać pakiet
            on_postep  — callback(etap, opis) do śledzenia w GUI

        Zwraca:
            WynikAtakuReplay z raportem wykrytych/pominiętych replay
        """
        wynik = WynikAtakuReplay()

        def krok(nr: str, opis: str) -> None:
            wynik.dodaj_etap(nr, opis)
            if on_postep:
                on_postep(nr, opis)

        # Przygotowanie kluczy sesji (symulacja po wymianie RSA)
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)
        session_id = 1001
        krok("1", "Sesja bezpieczna aktywna (klucze AES + HMAC ustalone)")

        # ---- Krok 2: Alice wysyła oryginalną wiadomość (nonce=1) ----
        nonce_oryginalny = 1
        pakiet_oryginalny = zbuduj_pakiet(
            wiadomosc.encode('utf-8'), k_aes, k_hmac,
            session_id=session_id, nonce=nonce_oryginalny
        )
        wynik.pakiety_wyslane += 1
        krok("2", f"Alice wysyła: '{wiadomosc}' (nonce={nonce_oryginalny})")

        # Bob odbiera i przetwarza oryginalną wiadomość
        sid, nc, pt = rozpakuj_pakiet(pakiet_oryginalny, k_aes, k_hmac)
        assert pt.decode() == wiadomosc
        ostatni_nonce_boba = nc
        krok("2", f"Bob odbiera poprawnie (nonce={nc}) → przetwarza wiadomość")

        # ---- Krok 3: Atakujący przechwytuje pakiet ----
        przechwycony = pakiet_oryginalny  # atakujący nie musi deszyfrować!
        krok("3", "Atakujący PRZECHWYTUJE pakiet (zaszyfrowany — nie czyta treści)")
        krok("3", f"Pakiet: {przechwycony[:20].hex()}... ({len(przechwycony)} B)")

        # ---- Krok 4: Wysłanie oryginalnych pakietów (nonce rosnący) ----
        for i in range(2, 5):
            nowa_wiad = f"Normalna wiadomosc nr {i}"
            p = zbuduj_pakiet(
                nowa_wiad.encode(), k_aes, k_hmac,
                session_id=session_id, nonce=i
            )
            _, nc, _ = rozpakuj_pakiet(p, k_aes, k_hmac)
            ostatni_nonce_boba = nc
            wynik.pakiety_wyslane += 1
        krok("4", f"Alice wysyła kolejne wiadomości (nonce=2,3,4 — Bob aktualizuje licznik do {ostatni_nonce_boba})")

        # ---- Krok 5: Replay attack ----
        krok("5", f"Atakujący próbuje wysłać przechwycony pakiet {ile_replay}x!")
        wynik.pakiety_replay = ile_replay

        for i in range(1, ile_replay + 1):
            # Symulacja odbioru przez Boba — sprawdzenie nonce
            try:
                _, nc_replay, _ = rozpakuj_pakiet(przechwycony, k_aes, k_hmac)
                # Sprawdzenie nonce jak robi _odbierz_wiadomosc w client.py
                if nc_replay <= ostatni_nonce_boba:
                    wynik.pakiety_wykryte += 1
                    krok("5", f"  Próba {i}: nonce={nc_replay} <= {ostatni_nonce_boba} → REPLAY WYKRYTY, odrzucono!")
                else:
                    wynik.sukces_ataku = True
                    krok("5", f"  Próba {i}: nonce={nc_replay} > {ostatni_nonce_boba} → Replay przeszedł! (LUKA)")
            except ValueError as e:
                wynik.pakiety_wykryte += 1
                krok("5", f"  Próba {i}: Błąd weryfikacji — {e}")

        # ---- Krok 6: Podsumowanie ----
        if wynik.pakiety_wykryte == ile_replay:
            krok("6", f"OCHRONA SKUTECZNA: wykryto {wynik.pakiety_wykryte}/{ile_replay} prób replay")
            krok("6", "Mechanizm: monotonicznie rosnący nonce — Bob zapamiętuje ostatni odebrany")
        else:
            krok("6", f"ATAK CZĘŚCIOWO UDANY: {ile_replay - wynik.pakiety_wykryte} prób przeszło!")

        krok("6", "Dodatkowe ochrony: znacznik czasu (timestamp) + okno ważności")
        return wynik


# ---------------------------------------------------------------------------
# DEMONSTRACJA PODATNOŚCI NA REPLAY BEZ NONCE
# ---------------------------------------------------------------------------

class DemoBezNonce:
    """
    Pokazuje co się stanie gdy system nie używa nonce — replay przechodzi.
    Służy wyłącznie do zilustrowania dlaczego nonce jest konieczny.
    """

    def symuluj_bez_ochrony(
        self,
        wiadomosc: str,
        on_postep: Optional[Callable[[str, str], None]] = None
    ) -> dict:
        """
        Demonstruje skuteczny atak replay gdy brak nonce/timestamp.

        Zwraca słownik z wynikami demonstracji.
        """
        wyniki: dict = {"etapy": [], "replay_udane": 0}

        def krok(nr: str, opis: str) -> None:
            wyniki["etapy"].append((nr, opis))
            if on_postep:
                on_postep(nr, opis)

        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)

        # Pakiet BEZ nonce — tylko AES+HMAC
        iv, szyfrogram = szyfruj_aes_cbc(wiadomosc.encode(), k_aes)
        tag = oblicz_hmac_pakietu(k_hmac, iv, szyfrogram)
        pakiet = iv + tag + szyfrogram

        krok("1", f"Alice wysyła: '{wiadomosc}' (brak nonce!)")
        krok("2", "Atakujący przechwytuje pakiet")
        krok("3", "Atakujący wysyła ten sam pakiet 3 razy...")

        for i in range(1, 4):
            # Bob nie ma jak sprawdzić czy to duplikat — brak nonce
            iv_r    = pakiet[:16]
            tag_r   = pakiet[16:48]
            ciph_r  = pakiet[48:]
            from secure_messenger.crypto.hmac_sha256 import weryfikuj_hmac_pakietu
            if weryfikuj_hmac_pakietu(k_hmac, iv_r, ciph_r, tag_r):
                pt = deszyfruj_aes_cbc(ciph_r, k_aes, iv_r)
                wyniki["replay_udane"] += 1
                krok("3", f"  Replay {i}: HMAC OK, Bob przetwarza: '{pt.decode()}' — ATAK UDANY!")

        krok("4", f"Bez nonce: {wyniki['replay_udane']}/3 repley przeszły bez wykrycia!")
        krok("4", "WNIOSEK: nonce jest KONIECZNY w każdym bezpiecznym protokole")
        return wyniki
