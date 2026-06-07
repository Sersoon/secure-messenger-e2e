"""
Klient sieciowy — Alice lub Bob w bezpiecznym komunikatorze.

Odpowiedzialności klienta:
    1. Połączenie z serwerem i rejestracja
    2. Wymiana kluczy RSA (Bob generuje, Alice szyfruje klucze sesji)
    3. Wysyłanie zaszyfrowanych wiadomości (AES-CBC + HMAC)
    4. Odbieranie i deszyfrowanie wiadomości w osobnym wątku
    5. Wykrywanie replay attack (counter nonce)

Architektura wątkowa:
    Wątek główny (GUI)  → wywołuje: polacz(), wyslij(), rozlacz()
    Wątek odbiorczy     → nasłuchuje pakietów, wywołuje callback przy nowej wiadomości

Callback on_wiadomosc(nadawca, tresc) jest wywoływany z wątku odbiorczego.
W PyQt6 należy go podpiąć przez signal/slot (patrz gui/main_window.py).
"""

import os
import socket
import threading
import logging
from typing import Callable, Optional

from secure_messenger.crypto.rsa import (
    generuj_klucze_rsa, KluczeRSA,
    szyfruj_klucze_sesji, deszyfruj_klucze_sesji,
    deszyfruj_rsa_crt,
    normaliz_bity_rsa,
)
from secure_messenger.crypto.aes_cbc import zbuduj_pakiet, rozpakuj_pakiet

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(message)s',
    datefmt='%H:%M:%S'
)

NAGLOWEK_DLUGOSCI: int = 4  # bajty nagłówka długości pakietu

# Typy pakietów kontrolnych (tekstowych, poprzedzonych 4B długości)
TYP_RSA_PUB  = b'RSA_PUB:'     # Bob → Alice: klucz publiczny RSA (bez PKI)
TYP_RSA_KEYS = b'RSA_KEYS:'   # Alice → Bob: zaszyfrowane klucze sesji
TYP_MSG      = b'MSG:'         # wiadomość zaszyfrowana AES+HMAC
TYP_SERVER_PUB = b'SERVER_PUB:'  # Server → Klient: klucz publiczny CA (PKI)
TYP_RSA_CERT   = b'RSA_CERT:'    # Server → Alice: certyfikowany klucz pub Boba (PKI)


class KlientMessenger:
    """
    Klient sieci bezpiecznego komunikatora (Alice lub Bob).

    Parametry:
        nazwa       — "alice" lub "bob"
        host        — adres serwera
        port        — port serwera
        on_wiadomosc  — callback(nadawca: str, tresc: str) wywoływany przy nowej wiadomości
        on_status     — callback(komunikat: str) dla zdarzeń połączenia/wymiany kluczy
        on_blad       — callback(blad: str) dla błędów
    """

    def __init__(
        self,
        nazwa: str,
        host: str = '127.0.0.1',
        port: int = 9999,
        on_wiadomosc: Optional[Callable[[str, str], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        on_blad: Optional[Callable[[str], None]] = None,
    ):
        self.nazwa = nazwa.lower()
        self.host = host
        self.port = port

        # Callbacki (podpinane przez GUI)
        self._on_wiadomosc = on_wiadomosc or (lambda n, t: None)
        self._on_status    = on_status    or (lambda s: None)
        self._on_blad       = on_blad       or (lambda e: None)

        self._logger = logging.getLogger(f"Klient-{self.nazwa}")

        # Stan połączenia
        self._socket: Optional[socket.socket] = None
        self._watek_odbioru: Optional[threading.Thread] = None
        self._dziala = threading.Event()

        # Klucze sesji (ustawiane po wymianie RSA)
        self._klucz_aes:  Optional[bytes] = None
        self._klucz_hmac: Optional[bytes] = None
        self._session_id: int = 0
        self._nonce_wyslany:  int = 0  # licznik wysłanych wiadomości
        self._nonce_odebrany: int = 0  # ostatni odebrany nonce (ochrona replay)
        self._blokada_nonce = threading.Lock()
        # Flaga "aktywna sesja" — oddzielona od posiadania kluczy,
        # żeby klucze mogły przetrwać rozłączenie i odszyfrować kolejkowane pakiety.
        self._sesja_aktywna: bool = False

        # Klucze RSA Boba (przechowywane przez Boba, klucz pub wysyłany Alice)
        self._klucze_rsa: Optional[KluczeRSA] = None

        # Klucz pub Boba (przechowywany przez Alice)
        self._pub_boba: Optional[tuple[int, int]] = None

        # PKI — klucz publiczny CA serwera (otrzymany po rejestracji)
        self._klucz_pub_ca: Optional[tuple[int, int]] = None
        # True jeśli ostatni klucz pub Boba przeszedł weryfikację certyfikatu CA
        self.certyfikat_zweryfikowany: bool = False

        # Ostatni wysłany pakiet krypto (do wyświetlenia IV/ciphertext/HMAC w GUI)
        self.ostatni_pakiet_krypto: Optional[bytes] = None

    # ------------------------------------------------------------------
    # WŁAŚCIWOŚCI
    # ------------------------------------------------------------------

    @property
    def tryb_bezpieczny(self) -> bool:
        """True gdy sesja AES+HMAC jest aktywna (wysyłanie + badge SECURE)."""
        return self._sesja_aktywna and self._klucz_aes is not None

    @property
    def polaczony(self) -> bool:
        """True gdy socket jest otwarty."""
        return self._socket is not None and self._dziala.is_set()

    # ------------------------------------------------------------------
    # POŁĄCZENIE
    # ------------------------------------------------------------------

    def polacz(self) -> bool:
        """
        Łączy się z serwerem i rejestruje jako alice/bob.
        Uruchamia wątek odbiorczy w tle.

        Zwraca:
            True — połączenie udane
            False — błąd połączenia
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self.host, self.port))
            self._logger.info(f"Połączono z {self.host}:{self.port}")

            # Rejestracja
            self._socket.sendall(f"REGISTER:{self.nazwa}\n".encode())
            odpowiedz = self._odbierz_linie()
            if odpowiedz != 'OK':
                raise ConnectionError(f"Rejestracja odrzucona: {odpowiedz}")

            self._dziala.set()
            self._logger.info(f"Zarejestrowano jako '{self.nazwa}'")
            self._on_status(f"Połączono z serwerem jako '{self.nazwa}'")

            # Uruchomienie wątku odbiorczego
            self._watek_odbioru = threading.Thread(
                target=self._petla_odbioru,
                daemon=True,
                name=f"Odbiorca-{self.nazwa}"
            )
            self._watek_odbioru.start()

            # Jesli sa zachowane klucze sesji (reconnect po rozlaczeniu),
            # przywroc tryb bezpieczny bez ponownej wymiany RSA.
            if self._klucz_aes is not None and self._klucz_hmac is not None:
                self._sesja_aktywna = True
                self._on_status("SECURE MODE przywrócony — klucze sesji z poprzedniej sesji")

            return True

        except Exception as e:
            blad = f"Błąd połączenia: {e}"
            self._logger.error(blad)
            self._on_blad(blad)
            self._dziala.clear()
            if self._socket:
                try:
                    self._socket.close()
                except OSError:
                    pass
            self._socket = None
            return False

    def rozlacz(self) -> None:
        """Rozłącza klienta i zatrzymuje wątek odbiorczy.

        Celowo NIE kasuje kluczy AES/HMAC — pozwala to odszyfrować pakiety
        zakolejkowane na serwerze i dostarczone po ponownym połączeniu.
        """
        self._sesja_aktywna = False
        self._dziala.clear()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self._logger.info("Rozłączono")
        self._on_status("Rozłączono od serwera")

    # ------------------------------------------------------------------
    # WYMIANA KLUCZY RSA
    # ------------------------------------------------------------------

    def inicjuj_wymiane_kluczy_jako_bob(self, bity: int = 1024) -> None:
        """
        Bob: generuje klucze RSA i wysyła klucz publiczny do Alice.
        Wywoływana przez Boba po połączeniu.

        Parametry:
            bity — długość klucza RSA (1024 lub 2048)
        """
        if self.nazwa != 'bob':
            raise RuntimeError("Tylko Bob inicjuje wymianę kluczy RSA")

        self._on_status(f"Bob generuje klucze RSA-{bity}...")
        self._klucze_rsa = generuj_klucze_rsa(bity)
        n, e = self._klucze_rsa.klucz_publiczny

        # Format: "RSA_PUB:<n_hex>:<e_hex>\n" owinięty w nagłówek długości
        payload = f"RSA_PUB:{hex(n)}:{hex(e)}\n".encode()
        self._wyslij_surowy(payload)

        self._on_status(f"Bob wysłał klucz publiczny RSA-{bity} do Alice")
        self._logger.info(f"Klucz publiczny RSA-{bity} wysłany")

    def wyslij_klucze_sesji_jako_alice(self) -> None:
        """
        Alice: generuje klucze AES+HMAC, szyfruje kluczem pub Boba i wysyła.
        Wywoływana przez Alice po odebraniu klucza pub od Boba.
        """
        if self.nazwa != 'alice':
            raise RuntimeError("Tylko Alice wysyła zaszyfrowane klucze sesji")
        if self._pub_boba is None:
            raise RuntimeError("Alice nie zna klucza publicznego Boba")

        self._on_status("Alice generuje klucze sesji AES + HMAC...")
        k_aes  = os.urandom(32)
        k_hmac = os.urandom(32)

        self._on_status("Alice szyfruje klucze RSA kluczem Boba...")
        enc_aes, enc_hmac = szyfruj_klucze_sesji(k_aes, k_hmac, self._pub_boba)

        # Format: "RSA_KEYS:<enc_aes_hex>:<enc_hmac_hex>\n"
        payload = (
            f"RSA_KEYS:{enc_aes.hex()}:{enc_hmac.hex()}\n"
        ).encode()
        self._wyslij_surowy(payload)

        # Zapisz lokalne klucze sesji
        self._klucz_aes  = k_aes
        self._klucz_hmac = k_hmac
        self._session_id = int.from_bytes(os.urandom(4), 'big')
        self._sesja_aktywna = True

        self._on_status("RSA Key Exchange zakończony")
        self._on_status("AES-256: aktywny | HMAC-SHA256: aktywny")
        self._on_status("SECURE MODE włączony")
        self._logger.info("Klucze sesji wysłane i zapisane przez Alice")

    # ------------------------------------------------------------------
    # WYSYŁANIE WIADOMOŚCI
    # ------------------------------------------------------------------

    def wyslij(self, tresc: str) -> bool:
        """
        Wysyła zaszyfrowaną wiadomość tekstową.
        Wymaga aktywnego trybu bezpiecznego (po wymianie kluczy RSA).

        Parametry:
            tresc — tekst wiadomości (zostanie zakodowany UTF-8)

        Zwraca:
            True — wysyłka udana
            False — błąd (brak klucza sesji lub problem z socketem)
        """
        if not self.tryb_bezpieczny:
            self._on_blad("Brak aktywnej sesji — najpierw wymień klucze RSA")
            return False

        try:
            with self._blokada_nonce:
                self._nonce_wyslany += 1
                nonce = self._nonce_wyslany

            pakiet_krypto = zbuduj_pakiet(
                plaintext=tresc.encode('utf-8'),
                klucz_aes=self._klucz_aes,
                klucz_hmac=self._klucz_hmac,
                session_id=self._session_id,
                nonce=nonce
            )
            # Zachowaj pakiet do wyświetlenia szczegółów w GUI (IV/HMAC/szyfrogram)
            self.ostatni_pakiet_krypto = pakiet_krypto

            # Owij w nagłówek typu MSG:
            payload = TYP_MSG + pakiet_krypto
            self._wyslij_surowy(payload)
            self._logger.info(f"Wysłano wiadomość (nonce={nonce}, {len(pakiet_krypto)} B)")
            return True

        except Exception as e:
            blad = f"Błąd wysyłania: {e}"
            self._logger.error(blad)
            self._on_blad(blad)
            return False

    # ------------------------------------------------------------------
    # WĄTEK ODBIORCZY
    # ------------------------------------------------------------------

    def _petla_odbioru(self) -> None:
        """
        Główna pętla odbiorczy (działa w osobnym wątku).
        Odczytuje pakiety z nagłówkiem długości i przetwarza je.
        """
        while self._dziala.is_set():
            try:
                dane = self._odbierz_pakiet()
                if dane is None:
                    break
                self._przetworz_odebrany(dane)
            except Exception as e:
                if self._dziala.is_set():
                    self._logger.error(f"Błąd wątku odbiorczego: {e}")
                    self._on_blad(f"Błąd odbioru: {e}")
                break

        if self._dziala.is_set():
            self._dziala.clear()
            self._on_status("Połączenie z serwerem utracone")

    def _przetworz_odebrany(self, dane: bytes) -> None:
        """
        Przetwarza odebrany pakiet w zależności od jego typu.
        """
        # PKI: klucz publiczny CA serwera (dostarczany zaraz po rejestracji)
        if dane.startswith(TYP_SERVER_PUB):
            self._odbierz_klucz_pub_ca(dane[len(TYP_SERVER_PUB):])
            return

        # PKI: certyfikowany klucz pub Boba (Bob → Serwer → [podpis CA] → Alice)
        if dane.startswith(TYP_RSA_CERT):
            self._odbierz_cert_rsa(dane[len(TYP_RSA_CERT):])
            return

        # Pakiet kontrolny RSA — klucz publiczny (Bob → Alice, tryb bez PKI)
        if dane.startswith(TYP_RSA_PUB):
            self._odbierz_klucz_pub_rsa(dane[len(TYP_RSA_PUB):])
            return

        # Pakiet kontrolny RSA — zaszyfrowane klucze sesji (Alice → Bob)
        if dane.startswith(TYP_RSA_KEYS):
            self._odbierz_klucze_sesji(dane[len(TYP_RSA_KEYS):])
            return

        # Zaszyfrowana wiadomość AES+HMAC
        if dane.startswith(TYP_MSG):
            self._odbierz_wiadomosc(dane[len(TYP_MSG):])
            return

        self._logger.warning(f"Nieznany typ pakietu: {dane[:20]}")

    def _odbierz_klucz_pub_rsa(self, payload: bytes) -> None:
        """Alice: odbiera klucz publiczny Boba i uruchamia wysyłkę kluczy sesji."""
        try:
            tekst = payload.decode().strip()
            n_hex, e_hex = tekst.split(':')
            self._pub_boba = (int(n_hex, 16), int(e_hex, 16))
            # Czysc stan PKI — to jest sciezka bez PKI (RSA_PUB zamiast RSA_CERT).
            # Zapobiega false-positive "BLAD WERYFIKACJI" gdy _klucz_pub_ca pochodzi
            # z poprzedniej sesji, w ktorej PKI bylo aktywne.
            self._klucz_pub_ca = None
            self.certyfikat_zweryfikowany = False
            bity = normaliz_bity_rsa(self._pub_boba[0])
            self._logger.info(f"Odebrano klucz publiczny RSA-{bity} od Boba")
            self._on_status(f"Alice odebrała klucz publiczny RSA-{bity} od Boba")
            # Alice automatycznie wysyła klucze sesji
            self.wyslij_klucze_sesji_jako_alice()
        except Exception as e:
            self._on_blad(f"Błąd odbioru klucza RSA: {e}")

    def _odbierz_klucz_pub_ca(self, payload: bytes) -> None:
        """Odbiera i zapisuje klucz publiczny CA serwera (PKI bootstrap)."""
        try:
            tekst = payload.decode().strip()
            n_hex, e_hex = tekst.split(':')
            self._klucz_pub_ca = (int(n_hex, 16), int(e_hex, 16))
            from secure_messenger.crypto.rsa import fingerprint_klucza, normaliz_bity_rsa
            bity = normaliz_bity_rsa(self._klucz_pub_ca[0])
            fp = fingerprint_klucza(*self._klucz_pub_ca)
            self._logger.info(f"PKI: odebrany klucz CA serwera RSA-{bity}")
            self._on_status(f"PKI: odebrany klucz CA serwera RSA-{bity} (fp={fp[:16]}...)")
        except Exception as exc:
            self._on_blad(f"PKI błąd odbioru klucza CA: {exc}")

    def _odbierz_cert_rsa(self, payload: bytes) -> None:
        """Alice: odbiera certyfikowany klucz pub Boba, weryfikuje podpis CA i kontynuuje."""
        if self.nazwa != 'alice':
            return
        try:
            from secure_messenger.crypto.rsa import weryfikuj_podpis_rsa, normaliz_bity_rsa
            tekst = payload.decode().strip()
            # Format: '<n_hex>:<e_hex>:<sig_hex>'
            czesci = tekst.rsplit(':', 1)          # split od prawej — sig_hex nie zawiera ':'
            sig_hex = czesci[1]
            dane_klucza = czesci[0]                # '<n_hex>:<e_hex>' — to co serwer podpisał
            n_hex, e_hex = dane_klucza.split(':', 1)
            klucz_boba = (int(n_hex, 16), int(e_hex, 16))
            podpis = bytes.fromhex(sig_hex)

            if self._klucz_pub_ca is None:
                # Brak klucza CA — zaakceptuj bez weryfikacji (backward compat)
                self._on_status("PKI: brak klucza CA — certyfikat pominięty (tryb bez PKI)")
                self.certyfikat_zweryfikowany = False
                self._pub_boba = klucz_boba
                self.wyslij_klucze_sesji_jako_alice()
                return

            ok = weryfikuj_podpis_rsa(dane_klucza.encode(), podpis, self._klucz_pub_ca)
            if ok:
                bity = normaliz_bity_rsa(klucz_boba[0])
                self._on_status(
                    f"PKI: certyfikat Boba ZWERYFIKOWANY — podpis CA poprawny RSA-{bity}"
                )
                self._logger.info("PKI: weryfikacja certyfikatu Boba: OK")
                self.certyfikat_zweryfikowany = True
                self._pub_boba = klucz_boba
                self.wyslij_klucze_sesji_jako_alice()
            else:
                self.certyfikat_zweryfikowany = False
                self._on_blad(
                    "PKI: BŁĄD WERYFIKACJI CERTYFIKATU — podpis CA niepoprawny!"
                )
                self._on_blad(
                    "Możliwy atak MITM: klucz pub Boba mógł zostać podmieniony"
                )
                self._logger.warning("PKI: weryfikacja certyfikatu FAILED")
        except Exception as exc:
            self._on_blad(f"PKI błąd parsowania certyfikatu: {exc}")

    def _odbierz_klucze_sesji(self, payload: bytes) -> None:
        """Bob: odszyfrowuje klucze sesji AES+HMAC kluczem prywatnym RSA."""
        if self.nazwa != 'bob' or self._klucze_rsa is None:
            return
        try:
            tekst = payload.decode().strip()
            enc_aes_hex, enc_hmac_hex = tekst.split(':')
            enc_aes  = bytes.fromhex(enc_aes_hex)
            enc_hmac = bytes.fromhex(enc_hmac_hex)

            self._on_status("Bob odszyfrowuje klucze sesji kluczem prywatnym RSA (CRT)...")
            k_aes  = deszyfruj_rsa_crt(enc_aes,  self._klucze_rsa).rjust(32, b'\x00')
            k_hmac = deszyfruj_rsa_crt(enc_hmac, self._klucze_rsa).rjust(32, b'\x00')
            self._klucz_aes  = k_aes
            self._klucz_hmac = k_hmac
            self._session_id = 0    # Bob nie zna session_id — akceptuje dowolne
            self._nonce_odebrany = 0  # reset nonce dla nowej sesji
            self._sesja_aktywna  = True

            self._on_status("RSA Key Exchange zakończony")
            self._on_status("AES-256: aktywny | HMAC-SHA256: aktywny")
            self._on_status("SECURE MODE włączony")
            self._logger.info("Klucze sesji odszyfrowane przez Boba")
        except Exception as e:
            self._on_blad(f"Błąd odszyfrowania kluczy sesji: {e}")

    def _odbierz_wiadomosc(self, pakiet: bytes) -> None:
        """Odszyfrowuje i weryfikuje odebraną wiadomość AES+HMAC.

        Działa też gdy sesja nie jest aktywna (tryb_bezpieczny=False) ale klucze
        istnieją — pozwala odszyfrować pakiety zakolejkowane z poprzedniej sesji.
        """
        if not (self._klucz_aes and self._klucz_hmac):
            self._on_blad("Odebrano wiadomość bez kluczy sesji — ignoruję")
            return
        try:
            session_id, nonce, plaintext = rozpakuj_pakiet(
                pakiet, self._klucz_aes, self._klucz_hmac
            )

            # Sprawdzenie replay attack
            with self._blokada_nonce:
                if nonce <= self._nonce_odebrany and self._nonce_odebrany > 0:
                    self._on_blad(f"REPLAY ATTACK wykryty!")
                    self._on_blad(
                        f"Powód: nonce={nonce} został już wykorzystany "
                        f"(ostatni={self._nonce_odebrany})"
                    )
                    self._on_blad("Pakiet odrzucony")
                    return
                self._nonce_odebrany = nonce

            tresc = plaintext.decode('utf-8')
            nadawca = 'alice' if self.nazwa == 'bob' else 'bob'
            self._logger.info(f"Odebrano wiadomość od '{nadawca}' (nonce={nonce})")
            self._on_wiadomosc(nadawca, tresc)

        except ValueError as e:
            self._on_blad(f"Błąd weryfikacji pakietu: {e}")

    # ------------------------------------------------------------------
    # NARZĘDZIA SIECIOWE
    # ------------------------------------------------------------------

    def _wyslij_surowy(self, dane: bytes) -> None:
        """
        Wysyła bajty poprzedzone 4-bajtowym nagłówkiem długości.
        Metoda jest thread-safe (Python GIL + atomowe sendall).
        """
        naglowek = len(dane).to_bytes(NAGLOWEK_DLUGOSCI, 'big')
        self._socket.sendall(naglowek + dane)

    def _odbierz_dokladnie(self, ile: int) -> Optional[bytes]:
        """Odbiera dokładnie `ile` bajtów. Zwraca None przy zerwaniu połączenia."""
        bufor = b''
        while len(bufor) < ile:
            try:
                fragment = self._socket.recv(ile - len(bufor))
            except OSError:
                return None
            if not fragment:
                return None
            bufor += fragment
        return bufor

    def _odbierz_pakiet(self) -> Optional[bytes]:
        """Odbiera jeden pakiet: najpierw nagłówek długości, potem treść."""
        naglowek = self._odbierz_dokladnie(NAGLOWEK_DLUGOSCI)
        if naglowek is None:
            return None
        dlugosc = int.from_bytes(naglowek, 'big')
        if dlugosc == 0 or dlugosc > 1_000_000:
            self._logger.warning(f"Podejrzana długość pakietu: {dlugosc}")
            return None
        return self._odbierz_dokladnie(dlugosc)

    def _odbierz_linie(self) -> str:
        """Odbiera tekst do znaku nowej linii (używane przy rejestracji)."""
        bufor = b''
        while b'\n' not in bufor:
            znak = self._socket.recv(1)
            if not znak:
                raise ConnectionError("Połączenie zerwane podczas rejestracji")
            bufor += znak
        return bufor.decode().strip()
