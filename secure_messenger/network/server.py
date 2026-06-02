"""
Serwer-router wiadomości — prosty przekaźnik TCP dla Alice i Boba.

Normalny tryb:
    Serwer przeźroczyście przekazuje zaszyfrowane pakiety.
    NIC nie deszyfruje — widzi tylko bity.

Tryb Eve (MITM):
    Checkbox w GUI serwera włącza tryb MITM.
    Eve przechwytuje klucz pub Boba, wysyła Alice swój klucz,
    odczytuje klucze sesji AES+HMAC i re-szyfruje je dla Boba.
    Po wymianie kluczy Eve może czytać wszystkie wiadomości.

Tryb Replay:
    Serwer przechwytuje pierwszy pakiet MSG i przechowuje go.
    Przycisk "Wyslij Replay" wysyła go ponownie → klient wykrywa nonce.

Protokół rejestracji:
    Klient → Serwer: "REGISTER:alice\\n" lub "REGISTER:bob\\n"
    Serwer → Klient: "OK\\n"

Format pakietów (binarny):
    [4 B dlugosc big-endian | N B payload]
    payload dla RSA_PUB:  b"RSA_PUB:<n_hex>:<e_hex>\\n"
    payload dla RSA_KEYS: b"RSA_KEYS:<enc_aes_hex>:<enc_hmac_hex>\\n"
    payload dla MSG:      b"MSG:" + binary_data
"""

import socket
import threading
import logging
import datetime
from typing import Optional, Callable

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SERWER] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

DOMYSLNY_HOST: str = '127.0.0.1'
DOMYSLNY_PORT: int = 9999
NAGLOWEK_DLUGOSCI: int = 4
_MAX_KOLEJKA: int = 50          # max pakietów na klienta w kolejce offline


class SerwerRoutera:
    """
    Serwer TCP przekazujący pakiety między Alice i Bobem.
    Opcjonalnie: tryb Eve (MITM + Replay) sterowany z GUI.
    """

    def __init__(
        self,
        host: str = DOMYSLNY_HOST,
        port: int = DOMYSLNY_PORT,
        on_log: Optional[Callable[[str], None]] = None,
        on_klienci: Optional[Callable[[list], None]] = None,
        on_pakiet_przechwycony: Optional[Callable[[], None]] = None,
        on_kolejka: Optional[Callable[[str, int], None]] = None,
    ):
        self.host = host
        self.port = port

        # Callbacki dla GUI serwera (wywoływane z wątków sieciowych)
        self._on_log = on_log or (lambda m: None)
        self._on_klienci = on_klienci or (lambda lst: None)
        self._on_pakiet_przechwycony = on_pakiet_przechwycony or (lambda: None)

        self._socket: Optional[socket.socket] = None
        self._klienci: dict[str, socket.socket] = {}
        self._blokada = threading.Lock()
        self._dziala = threading.Event()

        # Kolejkowanie wiadomości gdy odbiorca offline
        self._on_kolejka = on_kolejka or (lambda n, i: None)
        self._kolejka: dict[str, list[bytes]] = {}

        # Stan Eve (MITM + Replay)
        self._mitm_wlaczony: bool = False
        self._replay_wlaczony: bool = False
        self._eve_klucze_rsa = None                          # KluczeRSA Eve
        self._bob_klucz_pub: Optional[tuple[int, int]] = None  # przechwycony
        self._eve_klucz_aes: Optional[bytes] = None
        self._eve_klucz_hmac: Optional[bytes] = None
        self._przechwycony_pakiet: Optional[tuple[str, bytes]] = None  # (cel, dane)

    # ------------------------------------------------------------------
    # LOGOWANIE
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        logger.info(msg)
        self._on_log(f"[{ts}] {msg}")

    def _powiadom_klientow(self) -> None:
        with self._blokada:
            lista = list(self._klienci.keys())
        self._on_klienci(lista)

    # ------------------------------------------------------------------
    # TRYB EVE — sterowanie z GUI
    # ------------------------------------------------------------------

    def ustaw_mitm(self, wlaczony: bool) -> None:
        """Włącza/wyłącza tryb MITM. Generuje klucze Eve przy włączeniu."""
        self._mitm_wlaczony = wlaczony
        if wlaczony:
            from secure_messenger.crypto.rsa import generuj_klucze_rsa
            self._log("EVE: generuje klucze RSA-512 (klucz do podstawienia)...")
            self._eve_klucze_rsa = generuj_klucze_rsa(512)
            self._log("EVE gotowa! Czekam na wymiane kluczy Alice↔Bob aby je przejac...")
        else:
            self._eve_klucze_rsa = None
            self._bob_klucz_pub = None
            self._eve_klucz_aes = None
            self._eve_klucz_hmac = None
            self._log("Tryb MITM wylaczony")

    def ustaw_replay(self, wlaczony: bool) -> None:
        """Włącza/wyłącza tryb Replay — przechwytuje pierwszy MSG."""
        self._replay_wlaczony = wlaczony
        if wlaczony:
            self._przechwycony_pakiet = None
            self._log("Tryb Replay wlaczony — czekam na pierwszy pakiet MSG...")
        else:
            self._przechwycony_pakiet = None
            self._log("Tryb Replay wylaczony")

    def wyslij_replay(self) -> bool:
        """Wysyła przechwycony pakiet MSG ponownie → odbiorca wykrywa stary nonce."""
        if self._przechwycony_pakiet is None:
            return False
        cel, dane = self._przechwycony_pakiet
        self._log(f"EVE REPLAY: wysylam stary pakiet do '{cel}' ({len(dane)} B) !")
        self._wyslij_do(cel, dane)
        return True

    @property
    def przechwycony_pakiet_gotowy(self) -> bool:
        return self._przechwycony_pakiet is not None

    # ------------------------------------------------------------------
    # URUCHAMIANIE I ZATRZYMYWANIE
    # ------------------------------------------------------------------

    def uruchom(self, w_tle: bool = True) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.listen(5)
        self._socket.settimeout(1.0)
        self._dziala.set()
        self._log(f"Serwer nasluchuje na {self.host}:{self.port}")

        if w_tle:
            watek = threading.Thread(
                target=self._petla_nasluch, daemon=True, name="Serwer-Nasluch"
            )
            watek.start()
        else:
            self._petla_nasluch()

    def zatrzymaj(self) -> None:
        self._dziala.clear()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        with self._blokada:
            for conn in list(self._klienci.values()):
                try:
                    conn.close()
                except OSError:
                    pass
            self._klienci.clear()
        self._log("Serwer zatrzymany")

    # ------------------------------------------------------------------
    # PĘTLA NASŁUCHU
    # ------------------------------------------------------------------

    def _petla_nasluch(self) -> None:
        while self._dziala.is_set():
            try:
                conn, adres = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            watek = threading.Thread(
                target=self._obsluz_klienta,
                args=(conn, adres),
                daemon=True,
                name=f"Klient-{adres[1]}"
            )
            watek.start()

    # ------------------------------------------------------------------
    # OBSŁUGA KLIENTA
    # ------------------------------------------------------------------

    def _odbierz_dokladnie(self, conn: socket.socket, ile: int) -> Optional[bytes]:
        bufor = b''
        while len(bufor) < ile:
            try:
                fragment = conn.recv(ile - len(bufor))
            except OSError:
                return None
            if not fragment:
                return None
            bufor += fragment
        return bufor

    def _obsluz_klienta(self, conn: socket.socket, adres: tuple) -> None:
        nazwa = None
        try:
            nazwa = self._rejestruj(conn)
            if nazwa is None:
                return

            self._log(f"{nazwa.capitalize()} polaczony ({adres[0]}:{adres[1]})")
            self._powiadom_klientow()
            self._dostarcz_kolejke(nazwa)

            while self._dziala.is_set():
                naglowek = self._odbierz_dokladnie(conn, NAGLOWEK_DLUGOSCI)
                if naglowek is None:
                    break
                dlugosc = int.from_bytes(naglowek, 'big')
                if dlugosc == 0 or dlugosc > 2_000_000:
                    self._log(f"Nieprawidlowa dlugosc pakietu od '{nazwa}': {dlugosc}")
                    break
                pakiet = self._odbierz_dokladnie(conn, dlugosc)
                if pakiet is None:
                    break

                self._log(f"{nazwa}: pakiet {dlugosc} B → routing")
                self._przekaz(nazwa, naglowek + pakiet)

        except Exception as e:
            if self._dziala.is_set():
                self._log(f"Blad obslugi '{nazwa}': {e}")
        finally:
            if nazwa:
                with self._blokada:
                    self._klienci.pop(nazwa, None)
                self._log(f"{nazwa.capitalize()} rozlaczony")
                self._powiadom_klientow()
            try:
                conn.close()
            except OSError:
                pass

    def _rejestruj(self, conn: socket.socket) -> Optional[str]:
        try:
            dane = b''
            while b'\n' not in dane:
                fragment = conn.recv(64)
                if not fragment:
                    return None
                dane += fragment
            linia = dane.decode('utf-8').strip()
            if not linia.startswith('REGISTER:'):
                conn.sendall(b'BLAD:Nieznane polecenie\n')
                return None
            nazwa = linia.split(':', 1)[1].lower().strip()
            if nazwa not in ('alice', 'bob'):
                conn.sendall(b'BLAD:Nazwa musi byc alice lub bob\n')
                return None
            zajeta = False
            with self._blokada:
                if nazwa in self._klienci:
                    zajeta = True
                else:
                    self._klienci[nazwa] = conn
            # sendall poza lockiem — nie blokuje pozostalych watkow serwera
            if zajeta:
                conn.sendall(b'BLAD:Nazwa zajeta\n')
                return None
            conn.sendall(b'OK\n')
            return nazwa
        except Exception as e:
            self._log(f"Blad rejestracji: {e}")
            return None

    # ------------------------------------------------------------------
    # ROUTING Z TRYBEM EVE
    # ------------------------------------------------------------------

    def _przekaz(self, od: str, dane: bytes) -> None:
        """Przekazuje pakiet — opcjonalnie przez Eve (MITM/Replay)."""
        cel = 'bob' if od == 'alice' else 'alice'
        payload = dane[NAGLOWEK_DLUGOSCI:]

        # MITM: przechwytuj klucz publiczny Boba
        if self._mitm_wlaczony and od == 'bob' and payload.startswith(b'RSA_PUB:'):
            self._mitm_przechwyc_klucz_pub(payload, cel)
            return

        # MITM: przechwytuj zaszyfrowane klucze sesji od Alice
        if self._mitm_wlaczony and od == 'alice' and payload.startswith(b'RSA_KEYS:'):
            self._mitm_przechwyc_klucze_sesji(payload, cel)
            return

        # MITM: czytaj wiadomosci przez Eve (jesli ma klucze)
        if self._mitm_wlaczony and payload.startswith(b'MSG:') and self._eve_klucz_aes:
            self._mitm_deszyfruj_msg(od, payload[4:])

        # Replay: zapamietaj pierwszy pakiet MSG
        if self._replay_wlaczony and payload.startswith(b'MSG:'):
            if self._przechwycony_pakiet is None:
                self._przechwycony_pakiet = (cel, dane)
                self._log(
                    f"EVE: przechwycono pakiet MSG od '{od}' ({len(dane)} B) "
                    f"— gotowy do replay!"
                )
                self._on_pakiet_przechwycony()

        self._wyslij_do(cel, dane)

    def _wyslij_do(self, cel: str, dane: bytes) -> None:
        log_msg = None
        rozm = None
        conn_cel = None

        with self._blokada:
            conn_cel = self._klienci.get(cel)
            if conn_cel is None:
                kolejka = self._kolejka.setdefault(cel, [])
                if len(kolejka) < _MAX_KOLEJKA:
                    kolejka.append(dane)
                    rozm = len(kolejka)
                    log_msg = (
                        f"Cel '{cel}' offline — pakiet zakolejkowany "
                        f"({rozm}/{_MAX_KOLEJKA})"
                    )
                else:
                    log_msg = (
                        f"Kolejka '{cel}' pelna ({_MAX_KOLEJKA}) — pakiet odrzucony"
                    )

        if log_msg:
            self._log(log_msg)
        if rozm is not None:
            self._on_kolejka(cel, rozm)
        if conn_cel is None:
            return

        try:
            conn_cel.sendall(dane)
        except OSError as e:
            self._log(f"Blad wysylania do '{cel}': {e}")

    def _dostarcz_kolejke(self, nazwa: str) -> None:
        """Dostarcza zakolejkowane pakiety po ponownym połączeniu klienta."""
        with self._blokada:
            pakiety = self._kolejka.pop(nazwa, [])

        if not pakiety:
            return

        self._log(
            f"{nazwa.capitalize()}: dostarczam {len(pakiety)} zakolejkowanych "
            f"pakiet(ow) z okresu rozlaczenia..."
        )
        for pakiet in pakiety:
            self._wyslij_do(nazwa, pakiet)
        self._log(f"{nazwa.capitalize()}: kolejka wyczyszczona")
        self._on_kolejka(nazwa, 0)

    def _opakuj(self, dane: bytes) -> bytes:
        return len(dane).to_bytes(NAGLOWEK_DLUGOSCI, 'big') + dane

    # ------------------------------------------------------------------
    # MITM — pomocnicze
    # ------------------------------------------------------------------

    def _mitm_przechwyc_klucz_pub(self, payload: bytes, cel: str) -> None:
        """Eve przechwytuje klucz pub Boba i wysyła Alice swój własny."""
        try:
            tekst = payload.decode().strip()
            czesc = tekst[len('RSA_PUB:'):]
            n_hex, e_hex = czesc.split(':', 1)
            self._bob_klucz_pub = (int(n_hex, 16), int(e_hex, 16))
            bity = self._bob_klucz_pub[0].bit_length()
            self._log(f"EVE: PRZECHWYCONO klucz pub Boba RSA-{bity}!")

            # Wyslij Alice KLUCZ EVE zamiast Boba
            n_eve, e_eve = self._eve_klucze_rsa.klucz_publiczny
            nowy = f"RSA_PUB:{hex(n_eve)}:{hex(e_eve)}\n".encode()
            self._wyslij_do(cel, self._opakuj(nowy))
            self._log("EVE: wyslano Alice SWOJ klucz pub (podszywanie pod Boba)")
        except Exception as e:
            self._log(f"MITM blad klucza pub: {e}")

    def _mitm_przechwyc_klucze_sesji(self, payload: bytes, cel: str) -> None:
        """Eve odczytuje klucze AES+HMAC, re-szyfruje kluczem Boba i przesyla."""
        try:
            from secure_messenger.crypto.rsa import deszyfruj_klucze_sesji, szyfruj_klucze_sesji
            tekst = payload.decode().strip()
            czesc = tekst[len('RSA_KEYS:'):]
            enc_aes_hex, enc_hmac_hex = czesc.split(':', 1)

            # Odszyfruj kluczem prywatnym Eve
            k_aes, k_hmac = deszyfruj_klucze_sesji(
                bytes.fromhex(enc_aes_hex),
                bytes.fromhex(enc_hmac_hex),
                self._eve_klucze_rsa.klucz_prywatny,
            )
            self._eve_klucz_aes = k_aes
            self._eve_klucz_hmac = k_hmac
            self._log(
                f"EVE: ODCZYTANO klucze sesji! "
                f"AES={k_aes.hex()[:16]}... HMAC={k_hmac.hex()[:16]}..."
            )

            # Re-zaszyfruj kluczem pub Boba i wyslij dalej
            if self._bob_klucz_pub:
                enc_aes_new, enc_hmac_new = szyfruj_klucze_sesji(k_aes, k_hmac, self._bob_klucz_pub)
                nowy = f"RSA_KEYS:{enc_aes_new.hex()}:{enc_hmac_new.hex()}\n".encode()
                self._wyslij_do(cel, self._opakuj(nowy))
                self._log("EVE: przekazano klucze Bobowi (re-zaszyfrowane jego kluczem pub)")
                self._log(">>> MITM ZAKONCZONY SUKCESEM — Eve zna AES i HMAC! <<<")
        except Exception as e:
            self._log(f"MITM blad kluczy sesji: {e}")

    def _mitm_deszyfruj_msg(self, od: str, pakiet: bytes) -> None:
        """Eve odczytuje plaintext wiadomosci (dzieki skradzionym kluczom)."""
        try:
            from secure_messenger.crypto.aes_cbc import rozpakuj_pakiet
            _, _, plaintext = rozpakuj_pakiet(pakiet, self._eve_klucz_aes, self._eve_klucz_hmac)
            self._log(f"EVE czyta [{od.upper()}]: \"{plaintext.decode('utf-8', errors='replace')}\"")
        except Exception:
            pass  # moze sie nie udac przy pierwszym pakiecie (rozne session_id)

    # ------------------------------------------------------------------
    # WŁAŚCIWOŚCI
    # ------------------------------------------------------------------

    @property
    def czy_dziala(self) -> bool:
        return self._dziala.is_set()

    @property
    def polaczeni_klienci(self) -> list[str]:
        with self._blokada:
            return list(self._klienci.keys())
