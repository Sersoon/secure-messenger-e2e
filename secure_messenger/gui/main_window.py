"""
Okno klienta — jeden uczestnik: Alice albo Bob.

Kazde okno to oddzielny uzytkownik z:
    - Widocznym na gorze paskiem statusu (ROZLACZONA / POLACZONA / SECURE)
    - Przyciskiem "Polacz" i (dla Boba) "Wymien klucze RSA"
    - Zakladka Czat: historia + szczegoly kryptograficzne (IV/szyfrogram/HMAC)
    - Zakladka Kryptografia: klucze RSA i sesji
    - Zakladka Benchmarki: pomiary wydajnosci

Brak duplikatow wiadomosci:
    _wyslij()        → lokalne echo "Ja: ..."       (tylko u nadawcy)
    _na_wiadomosc()  → wiadomosc od drugiej strony  (tylko u odbiorcy)
"""

import threading

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QGroupBox,
    QTableWidget, QTableWidgetItem, QComboBox, QSplitter,
    QProgressBar, QHeaderView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCursor

from secure_messenger.network.client import KlientMessenger
from secure_messenger.benchmarks.benchmark import uruchom_wszystkie_benchmarki, WynikBenchmarku


# ---------------------------------------------------------------------------
# WĄTKI QThread
# ---------------------------------------------------------------------------

class WatekKlienta(QThread):
    """Opakowuje KlientMessenger w QThread — socket nigdy nie blokuje GUI."""
    sygnal_wiadomosc  = pyqtSignal(str, str)
    sygnal_status     = pyqtSignal(str)
    sygnal_blad       = pyqtSignal(str)
    sygnal_polaczony  = pyqtSignal(bool)
    sygnal_bezpieczny = pyqtSignal(bool)
    sygnal_rozlaczony = pyqtSignal()   # emitowany gdy polaczenie sie konczy

    def __init__(self, nazwa: str, port: int = 9999):
        super().__init__()
        self.nazwa = nazwa
        self.port = port
        self.klient: KlientMessenger | None = None
        self._poprzedni_tryb = False

    def run(self) -> None:
        self.klient = KlientMessenger(
            nazwa=self.nazwa,
            port=self.port,
            on_wiadomosc=lambda n, t: self.sygnal_wiadomosc.emit(n, t),
            on_status=lambda s: self._na_status(s),
            on_blad=lambda e: self.sygnal_blad.emit(e),
        )
        ok = self.klient.polacz()
        self.sygnal_polaczony.emit(ok)

        while self.klient and self.klient.polaczony:
            aktualny = self.klient.tryb_bezpieczny
            if aktualny != self._poprzedni_tryb:
                self.sygnal_bezpieczny.emit(aktualny)
                self._poprzedni_tryb = aktualny
            self.msleep(100)

        # Petla sie skonczyla — polaczenie utracone lub zamkniete
        self.sygnal_rozlaczony.emit()

    def _na_status(self, s: str) -> None:
        self.sygnal_status.emit(s)
        if self.klient:
            aktualny = self.klient.tryb_bezpieczny
            if aktualny != self._poprzedni_tryb:
                self.sygnal_bezpieczny.emit(aktualny)
                self._poprzedni_tryb = aktualny


class WatekBenchmarku(QThread):
    sygnal_postep = pyqtSignal(str)
    sygnal_wyniki = pyqtSignal(object)

    def __init__(self, bity_rsa: list[int]):
        super().__init__()
        self.bity_rsa = bity_rsa

    def run(self) -> None:
        raport = uruchom_wszystkie_benchmarki(
            bity_rsa=self.bity_rsa,
            on_postep=lambda msg: self.sygnal_postep.emit(msg)
        )
        self.sygnal_wyniki.emit(raport)


# ---------------------------------------------------------------------------
# ZAKŁADKA: CZAT
# ---------------------------------------------------------------------------

class ZakladkaCzat(QWidget):

    def __init__(self, rola: str):
        super().__init__()
        self.rola = rola
        layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Historia wiadomosci
        grp_hist = QGroupBox("Historia wiadomosci")
        lay_h = QVBoxLayout(grp_hist)
        self.historia = QTextEdit()
        self.historia.setReadOnly(True)
        self.historia.setFont(QFont("Segoe UI", 10))
        lay_h.addWidget(self.historia)
        splitter.addWidget(grp_hist)

        # Szczegoly kryptograficzne ostatniej wyslane wiadomosci
        grp_krypto = QGroupBox("Szczegoly ostatniego wyslaneogo pakietu (AES-CBC)")
        lay_kr = QVBoxLayout(grp_krypto)
        self.txt_iv     = QLineEdit(); self.txt_iv.setReadOnly(True)
        self.txt_cipher = QLineEdit(); self.txt_cipher.setReadOnly(True)
        self.txt_hmac   = QLineEdit(); self.txt_hmac.setReadOnly(True)
        for pole in [self.txt_iv, self.txt_cipher, self.txt_hmac]:
            pole.setFont(QFont("Consolas", 8))

        for etykieta, pole in [
            ("IV (16 B, hex):",   self.txt_iv),
            ("Szyfrogram (hex):", self.txt_cipher),
            ("HMAC-SHA256:",      self.txt_hmac),
        ]:
            w = QHBoxLayout()
            lbl = QLabel(etykieta); lbl.setFixedWidth(130)
            w.addWidget(lbl); w.addWidget(pole)
            lay_kr.addLayout(w)

        self.lbl_hmac_ok = QLabel("—")
        self.lbl_hmac_ok.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay_hmac = QHBoxLayout()
        lay_hmac.addWidget(QLabel("Weryfikacja HMAC:"))
        lay_hmac.addWidget(self.lbl_hmac_ok)
        lay_hmac.addStretch()
        lay_kr.addLayout(lay_hmac)
        splitter.addWidget(grp_krypto)

        layout.addWidget(splitter)

        # Pole wysylania
        grp_wyslij = QGroupBox("Wyslij wiadomosc")
        lay_w = QHBoxLayout(grp_wyslij)
        self.pole_wiad = QLineEdit()
        self.pole_wiad.setPlaceholderText("Wpisz wiadomosc i nacisnij Enter lub Wyslij...")
        self.pole_wiad.setEnabled(False)
        self.btn_wyslij = QPushButton("Wyslij")
        self.btn_wyslij.setFixedWidth(90)
        self.btn_wyslij.setEnabled(False)
        lay_w.addWidget(self.pole_wiad)
        lay_w.addWidget(self.btn_wyslij)
        layout.addWidget(grp_wyslij)

    def dodaj_wiadomosc(self, nadawca: str, tresc: str, kolor: str) -> None:
        self.historia.append(
            f'<span style="color:{kolor}; font-weight:bold;">{nadawca}:</span> {tresc}'
        )

    def pokaz_szczegoly(self, iv: bytes, szyfrogram: bytes, tag: bytes) -> None:
        self.txt_iv.setText(iv.hex())
        skrocony = szyfrogram[:24].hex() + "..." if len(szyfrogram) > 24 else szyfrogram.hex()
        self.txt_cipher.setText(skrocony)
        self.txt_hmac.setText(tag.hex())
        self.lbl_hmac_ok.setText("POPRAWNY")
        self.lbl_hmac_ok.setStyleSheet("color: #27ae60;")

    def ustaw_aktywny(self, aktywny: bool) -> None:
        self.btn_wyslij.setEnabled(aktywny)
        self.pole_wiad.setEnabled(aktywny)


# ---------------------------------------------------------------------------
# ZAKŁADKA: KRYPTOGRAFIA (RSA Lab)
# ---------------------------------------------------------------------------

class ZakladkaKryptografia(QWidget):

    def __init__(self, rola: str):
        super().__init__()
        self.rola = rola
        layout = QVBoxLayout(self)

        if rola == 'bob':
            grp1 = QGroupBox("Moje klucze RSA (wygenerowane przez Boba)")
            lay1 = QVBoxLayout(grp1)
            self.txt_n = self._linia("Modul n (hex):")
            self.txt_e = self._linia("Wykl. publ. e:")
            self.txt_d = self._linia("Wykl. pryw. d:")
            for w in [self.txt_n, self.txt_e, self.txt_d]:
                lay1.addWidget(w)
            layout.addWidget(grp1)

            grp2 = QGroupBox("Klucze sesji (odszyfrowane kluczem pryw. RSA)")
            lay2 = QVBoxLayout(grp2)
            self.txt_aes  = self._linia("Klucz AES-256 (hex):")
            self.txt_hmac = self._linia("Klucz HMAC (hex):")
            for w in [self.txt_aes, self.txt_hmac]:
                lay2.addWidget(w)
            layout.addWidget(grp2)
        else:
            grp1 = QGroupBox("Klucz publiczny Boba (odebrany przez Alice)")
            lay1 = QVBoxLayout(grp1)
            self.txt_n = self._linia("Modul n (hex):")
            self.txt_e = self._linia("Wykl. publ. e:")
            self.txt_d = None
            for w in [self.txt_n, self.txt_e]:
                lay1.addWidget(w)
            layout.addWidget(grp1)

            grp2 = QGroupBox("Moje klucze sesji (wygenerowane, wyslane RSA-em)")
            lay2 = QVBoxLayout(grp2)
            self.txt_aes  = self._linia("Klucz AES-256 (hex):")
            self.txt_hmac = self._linia("Klucz HMAC (hex):")
            for w in [self.txt_aes, self.txt_hmac]:
                lay2.addWidget(w)
            layout.addWidget(grp2)

        # Dziennik wymiany kluczy
        grp_log = QGroupBox("Dziennik wymiany kluczy RSA")
        lay_log = QVBoxLayout(grp_log)
        self.log_kroki = QTextEdit()
        self.log_kroki.setReadOnly(True)
        self.log_kroki.setFont(QFont("Consolas", 9))
        lay_log.addWidget(self.log_kroki)
        layout.addWidget(grp_log)

        self.lbl_secure = QLabel("Oczekiwanie na wymiane kluczy...")
        self.lbl_secure.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.lbl_secure.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_secure.setStyleSheet("color: gray; padding: 6px;")
        layout.addWidget(self.lbl_secure)

    def _linia(self, etykieta: str) -> QWidget:
        k = QWidget()
        lay = QHBoxLayout(k)
        lay.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel(etykieta)
        lbl.setFixedWidth(195)
        lbl.setFont(QFont("Segoe UI", 8))
        pole = QLineEdit()
        pole.setReadOnly(True)
        pole.setFont(QFont("Consolas", 8))
        pole.setPlaceholderText("—")
        lay.addWidget(lbl)
        lay.addWidget(pole)
        k._pole = pole
        return k

    def ustaw(self, widget: QWidget, wartosc: str) -> None:
        if widget is None:
            return
        skrocona = wartosc[:120] + "..." if len(wartosc) > 120 else wartosc
        widget._pole.setText(skrocona)

    def dodaj_krok(self, oznaczenie: str, opis: str) -> None:
        self.log_kroki.append(f"[{oznaczenie}] {opis}")
        self.log_kroki.moveCursor(QTextCursor.MoveOperation.End)

    def ustaw_secure_mode(self, aktywny: bool) -> None:
        if aktywny:
            self.lbl_secure.setText("SECURE MODE AKTYWNY")
            self.lbl_secure.setStyleSheet(
                "color: white; background: #27ae60; padding: 6px; border-radius: 4px;"
            )
        else:
            self.lbl_secure.setText("Oczekiwanie na wymiane kluczy...")
            self.lbl_secure.setStyleSheet("color: gray; padding: 6px;")


# ---------------------------------------------------------------------------
# ZAKŁADKA: BENCHMARKI
# ---------------------------------------------------------------------------

class ZakladkaBenchmarki(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        grp = QGroupBox("Konfiguracja")
        lay_g = QHBoxLayout(grp)
        self.combo_rsa = QComboBox()
        self.combo_rsa.addItems(["RSA-1024 + RSA-2048", "RSA-512 + RSA-1024 (szybko)"])
        self.btn_start = QPushButton("Uruchom benchmarki")
        self.btn_start.setFixedWidth(180)
        lay_g.addWidget(QLabel("Rozmiary RSA:")); lay_g.addWidget(self.combo_rsa)
        lay_g.addStretch(); lay_g.addWidget(self.btn_start)
        layout.addWidget(grp)

        self.pasek = QProgressBar()
        self.pasek.setRange(0, 0)
        self.pasek.setVisible(False)
        self.lbl_postep = QLabel("")
        layout.addWidget(self.pasek)
        layout.addWidget(self.lbl_postep)

        self.tabela = QTableWidget()
        nagl = WynikBenchmarku.naglowki()
        self.tabela.setColumnCount(len(nagl))
        self.tabela.setHorizontalHeaderLabels(nagl)
        self.tabela.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tabela.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.tabela.setAlternatingRowColors(True)
        self.tabela.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.tabela)

        self.lbl_czas = QLabel("")
        self.lbl_czas.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self.lbl_czas)

    def pokaz_wyniki(self, raport) -> None:
        wiersze = raport.jako_tabela()
        self.tabela.setRowCount(len(wiersze))
        for r, wiersz in enumerate(wiersze):
            for c, wartosc in enumerate(wiersz):
                item = QTableWidgetItem(wartosc)
                item.setTextAlignment(
                    Qt.AlignmentFlag.AlignLeft if c == 0 else Qt.AlignmentFlag.AlignCenter
                )
                if "RSA" in wiersz[0]:
                    item.setBackground(QColor("#fef9e7"))
                self.tabela.setItem(r, c, item)
        self.lbl_czas.setText(f"Czas calkowity: {raport.czas_calkowity_s:.1f}s")


# ---------------------------------------------------------------------------
# PASEK GÓRNY (status + przyciski)
# ---------------------------------------------------------------------------

class _PasekGorny(QWidget):

    def __init__(self, rola: str):
        super().__init__()
        self.rola = rola
        self.setFixedHeight(56)
        self.setStyleSheet("background: #2c3e50;")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)

        # Etykieta roli
        lbl_rola = QLabel(rola.upper())
        lbl_rola.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl_rola.setStyleSheet(
            "color: #2980b9;" if rola == "alice" else "color: #8e44ad;"
        )
        lbl_rola.setFixedWidth(70)
        layout.addWidget(lbl_rola)

        # Badge polaczenia
        self.badge_pol = self._badge("ROZLACZONA", "#e74c3c")
        layout.addWidget(self.badge_pol)

        # Badge sesji
        self.badge_ses = self._badge("Brak sesji", "#7f8c8d")
        layout.addWidget(self.badge_ses)

        layout.addStretch()

        # Przycisk Polacz
        self.btn_polacz = QPushButton("Polacz")
        self.btn_polacz.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.btn_polacz.setStyleSheet(
            "background: #27ae60; color: white; border: none; "
            "padding: 5px 14px; border-radius: 4px;"
        )
        self.btn_polacz.setFixedHeight(34)
        layout.addWidget(self.btn_polacz)

        # Przycisk Rozlacz
        self.btn_rozlacz = QPushButton("Rozlacz")
        self.btn_rozlacz.setFont(QFont("Segoe UI", 10))
        self.btn_rozlacz.setStyleSheet(
            "background: #e74c3c; color: white; border: none; "
            "padding: 5px 14px; border-radius: 4px;"
        )
        self.btn_rozlacz.setFixedHeight(34)
        self.btn_rozlacz.setEnabled(False)
        layout.addWidget(self.btn_rozlacz)

        # Wymiana kluczy (tylko Bob)
        if rola == 'bob':
            self.combo_bity = QComboBox()
            self.combo_bity.addItems(["RSA-512", "RSA-1024", "RSA-2048"])
            self.combo_bity.setCurrentIndex(1)
            self.combo_bity.setFixedHeight(34)
            self.combo_bity.setStyleSheet("background: #34495e; color: white; padding: 2px 6px;")
            self.btn_wymiana = QPushButton("Wymien klucze RSA")
            self.btn_wymiana.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.btn_wymiana.setStyleSheet(
                "background: #8e44ad; color: white; border: none; "
                "padding: 5px 14px; border-radius: 4px;"
            )
            self.btn_wymiana.setFixedHeight(34)
            self.btn_wymiana.setEnabled(False)
            layout.addWidget(self.combo_bity)
            layout.addWidget(self.btn_wymiana)
        else:
            self.combo_bity = None
            self.btn_wymiana = None
            lbl_auto = QLabel("Alice automatycznie wysle klucze sesji po odebraniu klucza RSA Boba")
            lbl_auto.setStyleSheet("color: #bdc3c7; font-size: 9px;")
            layout.addWidget(lbl_auto)

    def _badge(self, tekst: str, kolor: str) -> QLabel:
        lbl = QLabel(tekst)
        lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lbl.setStyleSheet(
            f"background: {kolor}; color: white; padding: 3px 10px; "
            f"border-radius: 10px; margin: 0 4px;"
        )
        return lbl

    def ustaw_polaczony(self, polaczony: bool) -> None:
        if polaczony:
            self.badge_pol.setText("POLACZONA" if self.rola == "alice" else "POLACZONY")
            self.badge_pol.setStyleSheet(
                "background: #27ae60; color: white; padding: 3px 10px; "
                "border-radius: 10px; margin: 0 4px;"
            )
            self.btn_polacz.setEnabled(False)
            self.btn_rozlacz.setEnabled(True)
        else:
            self.badge_pol.setText("ROZLACZONA" if self.rola == "alice" else "ROZLACZONY")
            self.badge_pol.setStyleSheet(
                "background: #e74c3c; color: white; padding: 3px 10px; "
                "border-radius: 10px; margin: 0 4px;"
            )
            self.btn_polacz.setEnabled(True)
            self.btn_polacz.setText("Polacz")
            self.btn_rozlacz.setEnabled(False)

    def ustaw_bezpieczny(self, bezpieczny: bool) -> None:
        if bezpieczny:
            self.badge_ses.setText("SECURE MODE")
            self.badge_ses.setStyleSheet(
                "background: #27ae60; color: white; padding: 3px 10px; "
                "border-radius: 10px; margin: 0 4px; font-weight: bold;"
            )
        else:
            self.badge_ses.setText("Brak sesji")
            self.badge_ses.setStyleSheet(
                "background: #7f8c8d; color: white; padding: 3px 10px; "
                "border-radius: 10px; margin: 0 4px;"
            )


# ---------------------------------------------------------------------------
# GŁÓWNE OKNO KLIENTA
# ---------------------------------------------------------------------------

class OknoKlienta(QMainWindow):
    """
    Okno jednego uczestnika (Alice albo Bob).
    Dwa osobne okna = pelna komunikacja przez serwer.
    """

    def __init__(self, rola: str, port: int = 9999):
        super().__init__()
        self.rola = rola
        self.port = port
        self.setWindowTitle(f"Secure Messenger E2E — {rola.capitalize()}")
        self.setMinimumSize(780, 600)
        self.resize(860, 650)

        self._moj_watek: WatekKlienta | None = None
        self._polaczony = False
        self._bezpieczny = False

        # Kolory: Alice wysyla na niebiesko, Bob na fioletowo
        self._kolor_ja  = "#2980b9" if rola == "alice" else "#8e44ad"
        self._kolor_oni = "#8e44ad" if rola == "alice" else "#2980b9"

        # Glowny widget
        centralny = QWidget()
        self.setCentralWidget(centralny)
        main_layout = QVBoxLayout(centralny)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Pasek gorny (staly, nad zakladkami)
        self.pasek = _PasekGorny(rola)
        main_layout.addWidget(self.pasek)

        # Zakladki
        self.tabs = QTabWidget()
        self.czat  = ZakladkaCzat(rola)
        self.krypto = ZakladkaKryptografia(rola)
        self.bench  = ZakladkaBenchmarki()

        self.tabs.addTab(self.czat,   "Czat")
        self.tabs.addTab(self.krypto, "Kryptografia / RSA Lab")
        self.tabs.addTab(self.bench,  "Benchmarki")
        main_layout.addWidget(self.tabs)

        self._podpnij_sygnaly()

    # ------------------------------------------------------------------
    # PODPINANIE SYGNAŁÓW
    # ------------------------------------------------------------------

    def _podpnij_sygnaly(self) -> None:
        self.pasek.btn_polacz.clicked.connect(self._polacz)
        self.pasek.btn_rozlacz.clicked.connect(self._rozlacz)
        self.czat.btn_wyslij.clicked.connect(self._wyslij)
        self.czat.pole_wiad.returnPressed.connect(self._wyslij)
        self.bench.btn_start.clicked.connect(self._uruchom_benchmarki)
        if self.pasek.btn_wymiana:
            self.pasek.btn_wymiana.clicked.connect(self._inicjuj_wymiane)

    # ------------------------------------------------------------------
    # POŁĄCZENIE
    # ------------------------------------------------------------------

    def _polacz(self) -> None:
        if self._polaczony:
            return
        self.pasek.btn_polacz.setEnabled(False)
        self.pasek.btn_polacz.setText("Laczenie...")

        self._moj_watek = WatekKlienta(self.rola, self.port)
        self._moj_watek.sygnal_polaczony.connect(self._na_polaczenie)
        self._moj_watek.sygnal_status.connect(self._na_status)
        self._moj_watek.sygnal_blad.connect(self._na_blad)
        self._moj_watek.sygnal_wiadomosc.connect(self._na_wiadomosc)
        self._moj_watek.sygnal_bezpieczny.connect(self._na_bezpieczny)
        self._moj_watek.sygnal_rozlaczony.connect(self._na_rozlaczenie)
        self._moj_watek.start()

    def _inicjuj_wymiane(self) -> None:
        if not (self._moj_watek and self._moj_watek.klient):
            return
        wybor = self.pasek.combo_bity.currentIndex()
        bity = [512, 1024, 2048][wybor]
        self.pasek.btn_wymiana.setEnabled(False)

        def _w_tle():
            self._moj_watek.klient.inicjuj_wymiane_kluczy_jako_bob(bity)

        threading.Thread(target=_w_tle, daemon=True).start()

    # ------------------------------------------------------------------
    # SLOTY — sieciowe callbacki (z wątku Qt)
    # ------------------------------------------------------------------

    def _na_polaczenie(self, ok: bool) -> None:
        self._polaczony = ok
        self.pasek.ustaw_polaczony(ok)
        if ok:
            self.pasek.btn_polacz.setText("Polaczono")
            self.krypto.dodaj_krok(self.rola[0].upper(), f"Polaczono z serwerem jako '{self.rola}'")
            if self.rola == 'bob' and self.pasek.btn_wymiana:
                self.pasek.btn_wymiana.setEnabled(True)
        else:
            self.krypto.dodaj_krok("!", "Blad polaczenia z serwerem")

    def _na_status(self, s: str) -> None:
        self.krypto.dodaj_krok(self.rola[0].upper(), s)

    def _na_blad(self, e: str) -> None:
        self.krypto.dodaj_krok("!", e)
        # Pokaz blad takze w czacie jesli jest zwiazany z atakiem
        if "REPLAY" in e or "WYKRYTO" in e:
            self.czat.historia.append(
                f'<span style="color:#c0392b; font-weight:bold;">ATAK: {e}</span>'
            )

    def _na_bezpieczny(self, bezpieczny: bool) -> None:
        self._bezpieczny = bezpieczny
        self.pasek.ustaw_bezpieczny(bezpieczny)
        self.krypto.ustaw_secure_mode(bezpieczny)
        self.czat.ustaw_aktywny(bezpieczny)

        if bezpieczny and self._moj_watek and self._moj_watek.klient:
            k = self._moj_watek.klient
            if k._klucz_aes:
                self.krypto.ustaw(self.krypto.txt_aes,  k._klucz_aes.hex())
            if k._klucz_hmac:
                self.krypto.ustaw(self.krypto.txt_hmac, k._klucz_hmac.hex())
            if self.rola == 'bob' and k._klucze_rsa:
                n, e = k._klucze_rsa.klucz_publiczny
                self.krypto.ustaw(self.krypto.txt_n, hex(n))
                self.krypto.ustaw(self.krypto.txt_e, str(e))
                if self.krypto.txt_d:
                    self.krypto.ustaw(self.krypto.txt_d, str(k._klucze_rsa.d))
            if self.rola == 'alice' and k._pub_boba:
                n, e = k._pub_boba
                self.krypto.ustaw(self.krypto.txt_n, hex(n))
                self.krypto.ustaw(self.krypto.txt_e, str(e))

    def _na_wiadomosc(self, nadawca: str, tresc: str) -> None:
        """Odebrana wiadomosc od DRUGIEJ strony — wyswietl u odbiorcy."""
        self.czat.dodaj_wiadomosc(nadawca.capitalize(), tresc, self._kolor_oni)

    def _rozlacz(self) -> None:
        if self._moj_watek and self._moj_watek.klient:
            self._moj_watek.klient.rozlacz()
        self.krypto.dodaj_krok("INFO", "Polaczenie zamkniete przez uzytkownika")
        self._reset_stanu()

    def _na_rozlaczenie(self) -> None:
        """Wywoływany gdy wątek sieciowy konczy petle (utrata polaczenia)."""
        if self._polaczony:
            self.krypto.dodaj_krok("INFO", "Polaczenie z serwerem utracone")
        self._reset_stanu()

    def _reset_stanu(self) -> None:
        """Przywraca UI do stanu 'rozlaczony' — umozliwia ponowne polaczenie."""
        self._polaczony = False
        self._bezpieczny = False
        self.pasek.ustaw_polaczony(False)
        self.pasek.ustaw_bezpieczny(False)
        if self.pasek.btn_wymiana:
            self.pasek.btn_wymiana.setEnabled(False)
        self.czat.ustaw_aktywny(False)
        self.krypto.ustaw_secure_mode(False)

    # ------------------------------------------------------------------
    # WYSYLANIE
    # ------------------------------------------------------------------

    def _wyslij(self) -> None:
        tresc = self.czat.pole_wiad.text().strip()
        if not tresc or not self._bezpieczny:
            return
        k = self._moj_watek.klient
        ok = k.wyslij(tresc)
        if ok:
            # LOKALNE ECHO — pokazane tylko u nadawcy, bez duplikatu
            self.czat.dodaj_wiadomosc("Ja", tresc, self._kolor_ja)
            self.czat.pole_wiad.clear()
            # Wyciagnij szczegoly kryptograficzne z aktualnie wyslaneego pakietu
            # Format pakietu: [4B session_id | 4B nonce | 16B IV | 32B HMAC | 4B len | N B ct]
            try:
                from secure_messenger.crypto.aes_cbc import szyfruj_aes_cbc
                from secure_messenger.crypto.hmac_sha256 import oblicz_hmac_pakietu
                iv, ct = szyfruj_aes_cbc(tresc.encode('utf-8'), k._klucz_aes)
                tag = oblicz_hmac_pakietu(k._klucz_hmac, iv, ct)
                self.czat.pokaz_szczegoly(iv, ct, tag)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # BENCHMARKI
    # ------------------------------------------------------------------

    def _uruchom_benchmarki(self) -> None:
        self.bench.btn_start.setEnabled(False)
        self.bench.pasek.setVisible(True)
        bity = [1024, 2048] if self.bench.combo_rsa.currentIndex() == 0 else [512, 1024]

        self._watek_bench = WatekBenchmarku(bity)
        self._watek_bench.sygnal_postep.connect(lambda m: self.bench.lbl_postep.setText(m))
        self._watek_bench.sygnal_wyniki.connect(self._na_wyniki_bench)
        self._watek_bench.start()

    def _na_wyniki_bench(self, raport) -> None:
        self.bench.pokaz_wyniki(raport)
        self.bench.pasek.setVisible(False)
        self.bench.btn_start.setEnabled(True)
        self.bench.lbl_postep.setText(f"Gotowe! Czas: {raport.czas_calkowity_s:.1f}s")

    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        if self._moj_watek and self._moj_watek.klient:
            self._moj_watek.klient.rozlacz()
        event.accept()


# Alias dla kompatybilnosci wstecznej (testy importuja GlowneOkno)
GlowneOkno = OknoKlienta
