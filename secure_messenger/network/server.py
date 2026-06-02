"""
Serwer-router wiadomości — prosty przekaźnik TCP dla Alice i Boba.

Architektura:
    - Serwer nasłuchuje na jednym porcie TCP
    - Dwaj klienci łączą się i rejestrują jako "alice" lub "bob"
    - Każda wiadomość od Alice → przekazana do Boba (i odwrotnie)
    - Serwer NIE deszyfruje wiadomości — widzi tylko zaszyfrowane pakiety

Protokół rejestracji (tekst):
    Klient po połączeniu wysyła: "REGISTER:<nazwa>\n"  (np. "REGISTER:alice\n")
    Serwer odpowiada:            "OK\n"

Protokół wiadomości (binarny):
    Każdy pakiet poprzedzony 4-bajtowym nagłówkiem długości (big-endian):
    [4 B dlugosc_pakietu | N B pakiet]
    Serwer odczytuje nagłówek, następnie N bajtów i przekazuje do drugiej strony.

Serwer działa w osobnym wątku (threading.Thread), aby nie blokować GUI.
"""

import socket
import threading
import logging
from typing import Optional

# Konfiguracja logowania po polsku
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SERWER] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

DOMYSLNY_HOST: str = '127.0.0.1'
DOMYSLNY_PORT: int = 9999
ROZMIAR_BUFORA: int = 4096
NAGLOWEK_DLUGOSCI: int = 4  # 4 bajty big-endian na długość pakietu


class SerwerRoutera:
    """
    Prosty serwer TCP przekazujący wiadomości między Alice i Bobem.

    Obsługuje dokładnie 2 klientów jednocześnie.
    Po rozłączeniu jednego — sesja kończy się, obaj mogą połączyć ponownie.
    """

    def __init__(self, host: str = DOMYSLNY_HOST, port: int = DOMYSLNY_PORT):
        self.host = host
        self.port = port
        self._socket: Optional[socket.socket] = None
        self._watki: list[threading.Thread] = []

        # Słownik aktywnych połączeń: nazwa -> socket
        self._klienci: dict[str, socket.socket] = {}
        self._blokada = threading.Lock()

        # Flaga sterująca pętlą nasłuchu
        self._dziala = threading.Event()

    # ------------------------------------------------------------------
    # URUCHAMIANIE I ZATRZYMYWANIE
    # ------------------------------------------------------------------

    def uruchom(self, w_tle: bool = True) -> None:
        """
        Uruchamia serwer na skonfigurowanym hoście i porcie.

        Parametry:
            w_tle — True: serwer działa w osobnym wątku (domyślnie)
                    False: blokuje bieżący wątek (tryb deweloperski)
        """
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.listen(5)
        self._dziala.set()
        logger.info(f"Serwer nasłuchuje na {self.host}:{self.port}")

        if w_tle:
            watek = threading.Thread(target=self._petla_nasluch, daemon=True, name="Serwer-Nasluch")
            watek.start()
            self._watki.append(watek)
        else:
            self._petla_nasluch()

    def zatrzymaj(self) -> None:
        """Zatrzymuje serwer i zamyka wszystkie połączenia."""
        self._dziala.clear()
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        with self._blokada:
            for nazwa, conn in list(self._klienci.items()):
                try:
                    conn.close()
                except OSError:
                    pass
            self._klienci.clear()
        logger.info("Serwer zatrzymany")

    # ------------------------------------------------------------------
    # PĘTLA NASŁUCHU
    # ------------------------------------------------------------------

    def _petla_nasluch(self) -> None:
        """Główna pętla akceptująca nowe połączenia."""
        while self._dziala.is_set():
            try:
                self._socket.settimeout(1.0)  # timeout, żeby móc sprawdzić flagę
                try:
                    conn, adres = self._socket.accept()
                except socket.timeout:
                    continue
                logger.info(f"Nowe połączenie od {adres}")
                watek = threading.Thread(
                    target=self._obsluz_klienta,
                    args=(conn, adres),
                    daemon=True,
                    name=f"Klient-{adres}"
                )
                watek.start()
                self._watki.append(watek)
            except OSError:
                break  # socket zamknięty — czas na wyjście

    # ------------------------------------------------------------------
    # OBSŁUGA KLIENTA
    # ------------------------------------------------------------------

    def _odbierz_dokladnie(self, conn: socket.socket, ile: int) -> Optional[bytes]:
        """
        Odbiera dokładnie `ile` bajtów z gniazda.
        Zwraca None przy zerwaniu połączenia.
        """
        bufor = b''
        while len(bufor) < ile:
            try:
                fragment = conn.recv(ile - len(bufor))
            except OSError:
                return None
            if not fragment:
                return None  # połączenie zerwane
            bufor += fragment
        return bufor

    def _obsluz_klienta(self, conn: socket.socket, adres: tuple) -> None:
        """
        Obsługuje jednego klienta: rejestracja, a następnie pętla przekazywania pakietów.
        """
        nazwa = None
        try:
            # Krok 1: Rejestracja klienta
            nazwa = self._rejestruj(conn)
            if nazwa is None:
                return

            logger.info(f"Klient '{nazwa}' zarejestrowany ({adres})")

            # Krok 2: Pętla odbioru i przekazywania pakietów
            while self._dziala.is_set():
                # Odczytaj 4-bajtowy nagłówek długości
                naglowek = self._odbierz_dokladnie(conn, NAGLOWEK_DLUGOSCI)
                if naglowek is None:
                    break

                dlugosc = int.from_bytes(naglowek, 'big')
                if dlugosc == 0 or dlugosc > 65536:
                    logger.warning(f"Nieprawidłowa długość pakietu od '{nazwa}': {dlugosc}")
                    break

                # Odczytaj właściwy pakiet
                pakiet = self._odbierz_dokladnie(conn, dlugosc)
                if pakiet is None:
                    break

                logger.info(f"Pakiet od '{nazwa}': {dlugosc} B — przekazuję")
                self._przekaz(nazwa, naglowek + pakiet)

        except Exception as e:
            logger.error(f"Błąd obsługi klienta '{nazwa}': {e}")
        finally:
            if nazwa:
                with self._blokada:
                    self._klienci.pop(nazwa, None)
                logger.info(f"Klient '{nazwa}' rozłączony")
            try:
                conn.close()
            except OSError:
                pass

    def _rejestruj(self, conn: socket.socket) -> Optional[str]:
        """
        Obsługuje rejestrację klienta: oczekuje "REGISTER:<nazwa>\n".
        Zwraca nazwę klienta lub None przy błędzie.
        """
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

            with self._blokada:
                if nazwa in self._klienci:
                    conn.sendall(b'BLAD:Nazwa zajeta\n')
                    return None
                self._klienci[nazwa] = conn

            conn.sendall(b'OK\n')
            return nazwa

        except Exception as e:
            logger.error(f"Błąd rejestracji: {e}")
            return None

    def _przekaz(self, od: str, dane: bytes) -> None:
        """
        Przekazuje pakiet do drugiego klienta (alice→bob lub bob→alice).
        """
        cel = 'bob' if od == 'alice' else 'alice'
        with self._blokada:
            conn_cel = self._klienci.get(cel)

        if conn_cel is None:
            logger.warning(f"Cel '{cel}' niedostępny — pakiet odrzucony")
            return

        try:
            conn_cel.sendall(dane)
        except OSError as e:
            logger.error(f"Błąd wysyłania do '{cel}': {e}")

    @property
    def czy_dziala(self) -> bool:
        """Zwraca True gdy serwer jest aktywny."""
        return self._dziala.is_set()

    @property
    def polaczeni_klienci(self) -> list[str]:
        """Lista aktualnie połączonych klientów."""
        with self._blokada:
            return list(self._klienci.keys())
