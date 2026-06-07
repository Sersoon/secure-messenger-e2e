"""
Okno klienta — jeden uczestnik: Alice albo Bob.

Kazde okno to oddzielny uzytkownik z:
    - Widocznym na gorze paskiem statusu (ROZLĄCZONA / POŁĄCZONA / SECURE)
    - Przyciskiem "Połącz" i (dla Boba) "Wymień klucze RSA"
    - Zakładka Czat: historia + szczegóły kryptograficzne (IV/szyfrogram/HMAC)
    - Zakładka Kryptografia: klucze RSA i sesji
    - Zakładka Benchmarki: pomiary wydajności

Brak duplikatów wiadomości:
    _wyslij()        → lokalne echo "Ja: ..."       (tylko u nadawcy)
    _na_wiadomosc()  → wiadomość od drugiej strony  (tylko u odbiorcy)
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
from secure_messenger.benchmarks.benchmark import uruchom_wszystkie_benchmarki, WynikBenchmarku, generuj_interpretacje
from secure_messenger.security.attacks import DemoECBvsCBC, DemoBezNonce, DemoManipulacjaSzyfrogramu



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
    sygnal_rozlaczony = pyqtSignal()

    def __init__(
        self,
        nazwa: str,
        port: int = 9999,
        istniejacy_klient: "KlientMessenger | None" = None,
    ):
        super().__init__()
        self.nazwa = nazwa
        self.port = port
        self._istniejacy_klient = istniejacy_klient
        self.klient: KlientMessenger | None = None
        self._poprzedni_tryb = False

    def run(self) -> None:
        if self._istniejacy_klient is not None:
            # Reconnect — reuzywamy tego samego KlientMessenger (zachowane klucze sesji).
            # Podpinamy callbacki pod sygnaly TEGO watku, zeby wiadomosci trafialy
            # do aktualnego okna.
            self.klient = self._istniejacy_klient
            self.klient._on_wiadomosc = lambda n, t: self.sygnal_wiadomosc.emit(n, t)
            self.klient._on_status    = lambda s: self._na_status(s)
            self.klient._on_blad      = lambda e: self.sygnal_blad.emit(e)
        else:
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

        # Historia wiadomości
        grp_hist = QGroupBox("Historia wiadomości")
        lay_h = QVBoxLayout(grp_hist)
        self.historia = QTextEdit()
        self.historia.setReadOnly(True)
        self.historia.setFont(QFont("Segoe UI", 10))
        lay_h.addWidget(self.historia)
        splitter.addWidget(grp_hist)

        # Szczegóły kryptograficzne ostatniego wysłanego pakietu
        grp_krypto = QGroupBox("Szczegóły ostatniego wysłanego pakietu (AES-CBC)")
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

        # Pole wysyłania
        grp_wyslij = QGroupBox("Wyślij wiadomość")
        lay_w = QHBoxLayout(grp_wyslij)
        self.pole_wiad = QLineEdit()
        self.pole_wiad.setPlaceholderText("Wpisz wiadomość i naciśnij Enter lub Wyślij...")
        self.pole_wiad.setEnabled(False)
        self.btn_wyslij = QPushButton("Wyślij")
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
            self.txt_n = self._linia("Moduł n (hex):")
            self.txt_e = self._linia("Wykł. publ. e:")
            self.txt_d = self._linia("Wykł. pryw. d:")
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
            self.txt_n = self._linia("Moduł n (hex):")
            self.txt_e = self._linia("Wykł. publ. e:")
            self.txt_d = None
            for w in [self.txt_n, self.txt_e]:
                lay1.addWidget(w)
            layout.addWidget(grp1)

            grp2 = QGroupBox("Moje klucze sesji (wygenerowane, wysłane RSA-em)")
            lay2 = QVBoxLayout(grp2)
            self.txt_aes  = self._linia("Klucz AES-256 (hex):")
            self.txt_hmac = self._linia("Klucz HMAC (hex):")
            for w in [self.txt_aes, self.txt_hmac]:
                lay2.addWidget(w)
            layout.addWidget(grp2)

        # Fingerprint klucza publicznego — weryfikacja MITM
        grp_fp = QGroupBox("Fingerprint klucza publicznego (SHA-256) — weryfikacja MITM")
        grp_fp.setStyleSheet("""
            QGroupBox {
                font-weight: bold; color: #fbbf24;
                border: 2px solid #92400e;
                border-radius: 8px;
                margin-top: 8px; padding-top: 8px;
                background: #1c1100;
            }
            QGroupBox::title { color: #fbbf24; left: 10px; padding: 0 5px; background: #1c1100; }
        """)
        lay_fp = QVBoxLayout(grp_fp)

        opis_fp = (
            "SHA-256(n ∥ e) własnego klucza pub RSA — Bob"
            if rola == 'bob' else
            "SHA-256(n ∥ e) klucza odebranego przez sieć — Alice"
        )
        lbl_fp_opis = QLabel(opis_fp)
        lbl_fp_opis.setStyleSheet("color: #9ca3af; font-size: 9px;")
        lbl_fp_opis.setWordWrap(True)
        lay_fp.addWidget(lbl_fp_opis)

        self.lbl_fingerprint = QLabel("—  (oczekiwanie na wymianę kluczy)")
        self.lbl_fingerprint.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
        self.lbl_fingerprint.setStyleSheet("color: #fbbf24; padding: 4px; letter-spacing: 1px;")
        self.lbl_fingerprint.setWordWrap(True)
        self.lbl_fingerprint.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        lay_fp.addWidget(self.lbl_fingerprint)

        self.lbl_fp_uwaga = QLabel(
            "Porównaj fingerprint z rozmówcą przez inny kanał (telefon, osobiście).\n"
            "Jeśli się różnią → aktywny atak MITM lub skompromitowany CA."
        )
        self.lbl_fp_uwaga.setStyleSheet("color: #9ca3af; font-size: 9px;")
        self.lbl_fp_uwaga.setWordWrap(True)
        lay_fp.addWidget(self.lbl_fp_uwaga)

        if rola == 'bob':
            cert_tekst = "Certyfikat PKI: weryfikacja po stronie Alice (Bob nie weryfikuje)"
        else:
            cert_tekst = "Certyfikat PKI: nie sprawdzany (PKI wyłączone)"
        self.lbl_cert_status = QLabel(cert_tekst)
        self.lbl_cert_status.setStyleSheet("color: #6b7280; font-size: 9px; font-weight: bold;")
        lay_fp.addWidget(self.lbl_cert_status)

        layout.addWidget(grp_fp)

        # Dziennik wymiany kluczy
        grp_log = QGroupBox("Dziennik wymiany kluczy RSA")
        lay_log = QVBoxLayout(grp_log)
        self.log_kroki = QTextEdit()
        self.log_kroki.setReadOnly(True)
        self.log_kroki.setFont(QFont("Consolas", 9))
        lay_log.addWidget(self.log_kroki)
        layout.addWidget(grp_log)

        self.lbl_secure = QLabel("Oczekiwanie na wymianę kluczy...")
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

    def ustaw_fingerprint(self, fingerprint: str) -> None:
        bloki = [fingerprint[i:i+8] for i in range(0, len(fingerprint), 8)]
        self.lbl_fingerprint.setText('  '.join(bloki))

    def ustaw_cert_status(self, zweryfikowany: bool | None) -> None:
        if zweryfikowany is None:
            self.lbl_cert_status.setText("Certyfikat PKI: nie sprawdzany (PKI wyłączone)")
            self.lbl_cert_status.setStyleSheet("color: #6b7280; font-size: 9px; font-weight: bold;")
        elif zweryfikowany:
            self.lbl_cert_status.setText(
                "Certyfikat PKI: ZWERYFIKOWANY — podpis CA poprawny ✓\n"
                "  ⚠ Cert potwierdza tylko autentyczność klucza CA, nie brak MITM.\n"
                "  Porównaj fingerprint z rozmówcą poza kanałem!"
            )
            self.lbl_cert_status.setStyleSheet("color: #4ade80; font-size: 9px; font-weight: bold;")
        else:
            self.lbl_cert_status.setText("Certyfikat PKI: BŁĄD WERYFIKACJI — możliwy MITM!")
            self.lbl_cert_status.setStyleSheet("color: #ef4444; font-size: 9px; font-weight: bold;")

    def ustaw_secure_mode(self, aktywny: bool) -> None:
        if aktywny:
            self.lbl_secure.setText("SECURE MODE AKTYWNY")
            self.lbl_secure.setStyleSheet(
                "color: white; background: #27ae60; padding: 6px; border-radius: 4px;"
            )
        else:
            self.lbl_secure.setText("Oczekiwanie na wymianę kluczy...")
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

        # Tabela wyników
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

        # Analiza interpretacyjna (generowana automatycznie z wyników)
        from PyQt6.QtWidgets import QTextEdit as _QTE
        grp_analiza = QGroupBox("Analiza kompromisów: bezpieczeństwo / wydajność")
        grp_analiza.setStyleSheet("""
            QGroupBox {
                font-weight: bold; color: #93c5fd;
                border: 2px solid #1e3a5f;
                border-radius: 6px; margin-top: 10px; padding-top: 8px;
                background: #0a1628;
            }
            QGroupBox::title { color: #93c5fd; left: 8px; padding: 0 4px; }
        """)
        lay_a = QVBoxLayout(grp_analiza)
        self.txt_analiza = _QTE()
        self.txt_analiza.setReadOnly(True)
        self.txt_analiza.setFont(QFont("Consolas", 8))
        self.txt_analiza.setMaximumHeight(220)
        self.txt_analiza.setStyleSheet(
            "background: #0a1628; color: #93c5fd; border: none;"
        )
        self.txt_analiza.setPlaceholderText(
            "Uruchom benchmarki aby wygenerować analizę wydajności..."
        )
        lay_a.addWidget(self.txt_analiza)
        layout.addWidget(grp_analiza)

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
                    item.setBackground(QColor("#292103"))
                    item.setForeground(QColor("#fbbf24"))
                else:
                    item.setForeground(QColor("#e5e7eb"))
                self.tabela.setItem(r, c, item)
        self.lbl_czas.setText(f"Czas całkowity: {raport.czas_calkowity_s:.1f}s")
        self.txt_analiza.setPlainText(generuj_interpretacje(raport))


# ZAKŁADKA: ATAKI (ECB vs CBC + Replay bez nonce)
# ---------------------------------------------------------------------------

class ZakladkaAtaki(QWidget):
    """Demonstracje podatności kryptograficznych — offline, bez serwera."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        tytul = QLabel("Analiza Bezpieczenstwa — Eksperymenty Kryptograficzne")
        tytul.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        layout.addWidget(tytul)

        # --- ECB vs CBC ---
        grp_ecb = QGroupBox("Demo 1: ECB vs CBC — ujawnianie wzorcow w szyfrogramie")
        lay_ecb = QVBoxLayout(grp_ecb)

        opis_ecb = QLabel(
            "ECB szyfruje kazdy 16-bajtowy blok niezaleznie tym samym kluczem.\n"
            "Identyczne bloki plaintextu => identyczne bloki szyfrogramu => wzorzec widoczny bez klucza.\n"
            "CBC XOR-uje kazdy blok z poprzednim szyfrogramem + losowy IV => brak wzorcow."
        )
        opis_ecb.setStyleSheet("color: #9ca3af; font-size: 9px;")
        opis_ecb.setWordWrap(True)
        lay_ecb.addWidget(opis_ecb)

        row_ecb = QHBoxLayout()
        self.combo_bloki = QComboBox()
        self.combo_bloki.addItems(["4 bloki (64 B)", "8 blokow (128 B)", "16 blokow (256 B)"])
        self.btn_ecb = QPushButton("Uruchom demo ECB vs CBC")
        self.btn_ecb.setFixedWidth(210)
        self.btn_ecb.setStyleSheet(
            "QPushButton { background:#b45309; color:white; border:none; "
            "padding:5px 12px; border-radius:5px; font-weight:bold; } "
            "QPushButton:hover { background:#d97706; } "
            "QPushButton:pressed { background:#92400e; }"
        )
        row_ecb.addWidget(QLabel("Liczba blokow:"))
        row_ecb.addWidget(self.combo_bloki)
        row_ecb.addStretch()
        row_ecb.addWidget(self.btn_ecb)
        lay_ecb.addLayout(row_ecb)

        self.txt_ecb = QTextEdit()
        self.txt_ecb.setReadOnly(True)
        self.txt_ecb.setFont(QFont("Consolas", 9))
        self.txt_ecb.setMaximumHeight(200)
        self.txt_ecb.setPlaceholderText("Wyniki pojawia sie tutaj po kliknieciu przycisku...")
        lay_ecb.addWidget(self.txt_ecb)
        layout.addWidget(grp_ecb)

        # --- Replay bez nonce ---
        grp_replay = QGroupBox(
            "Demo 2: Replay Attack — ten sam zaszyfrowany pakiet wyslany 3x"
        )
        lay_replay = QVBoxLayout(grp_replay)

        opis_replay = QLabel(
            "Atakujacy przechwytuje pakiet i wysyla go ponownie.\n"
            "HMAC jest poprawny (pakiet nie byl modyfikowany), wiec BEZ nonce odbiorca akceptuje.\n"
            "Z nonce: drugi odbior wykryty => pakiet odrzucony."
        )
        opis_replay.setStyleSheet("color: #9ca3af; font-size: 9px;")
        opis_replay.setWordWrap(True)
        lay_replay.addWidget(opis_replay)

        row_replay = QHBoxLayout()
        self.pole_wiad_replay = QLineEdit("Przelej 1000 zl na konto 12345")
        self.btn_replay = QPushButton("Uruchom demo Replay")
        self.btn_replay.setFixedWidth(180)
        self.btn_replay.setStyleSheet(
            "QPushButton { background:#7c3aed; color:white; border:none; "
            "padding:5px 12px; border-radius:5px; font-weight:bold; } "
            "QPushButton:hover { background:#6d28d9; } "
            "QPushButton:pressed { background:#5b21b6; }"
        )
        row_replay.addWidget(QLabel("Wiadomosc:"))
        row_replay.addWidget(self.pole_wiad_replay)
        row_replay.addWidget(self.btn_replay)
        lay_replay.addLayout(row_replay)

        self.txt_replay = QTextEdit()
        self.txt_replay.setReadOnly(True)
        self.txt_replay.setFont(QFont("Consolas", 9))
        self.txt_replay.setMaximumHeight(160)
        self.txt_replay.setPlaceholderText("Wyniki pojawia sie tutaj po kliknieciu przycisku...")
        lay_replay.addWidget(self.txt_replay)
        layout.addWidget(grp_replay)

        # --- Manipulacja szyfrogramem (bit-flip + HMAC) ---
        grp_bitflip = QGroupBox(
            "Demo 3: Manipulacja szyfrogramem — bit-flip i rola HMAC"
        )
        lay_bf = QVBoxLayout(grp_bitflip)

        opis_bf = QLabel(
            "Atakujący zmienia 1 bajt szyfrogramu w trakcie transmisji.\n"
            "Z HMAC (Encrypt-then-MAC): pakiet odrzucony — modyfikacja wykryta.\n"
            "Bez HMAC: deszyfrowanie powiedzie się, ale plaintext będzie uszkodzony "
            "bez żadnego ostrzeżenia. Właściwość CBC: zmiana bajtu w bloku i niszczy "
            "cały blok i i pozwala kontrolować bit w bloku i+1."
        )
        opis_bf.setStyleSheet("color: #9ca3af; font-size: 9px;")
        opis_bf.setWordWrap(True)
        lay_bf.addWidget(opis_bf)

        row_bf = QHBoxLayout()
        self.pole_wiad_bf = QLineEdit("Przelej 1000 zl na konto 12345")
        self.btn_bitflip = QPushButton("Uruchom demo Bit-flip")
        self.btn_bitflip.setFixedWidth(180)
        self.btn_bitflip.setStyleSheet(
            "QPushButton { background:#b45309; color:white; border:none; "
            "padding:5px 12px; border-radius:5px; font-weight:bold; } "
            "QPushButton:hover { background:#92400e; } "
            "QPushButton:disabled { background:#374151; color:#6b7280; }"
        )
        row_bf.addWidget(QLabel("Wiadomosc:"))
        row_bf.addWidget(self.pole_wiad_bf)
        row_bf.addWidget(self.btn_bitflip)
        lay_bf.addLayout(row_bf)

        self.txt_bitflip = QTextEdit()
        self.txt_bitflip.setReadOnly(True)
        self.txt_bitflip.setFont(QFont("Consolas", 9))
        self.txt_bitflip.setMaximumHeight(175)
        self.txt_bitflip.setPlaceholderText("Wyniki pojawia sie tutaj po kliknieciu przycisku...")
        lay_bf.addWidget(self.txt_bitflip)
        layout.addWidget(grp_bitflip)

        layout.addStretch()

        self.btn_ecb.clicked.connect(self._uruchom_ecb)
        self.btn_replay.clicked.connect(self._uruchom_replay)
        self.btn_bitflip.clicked.connect(self._uruchom_bitflip)

    def _uruchom_ecb(self) -> None:
        liczba_blokow = [4, 8, 16][self.combo_bloki.currentIndex()]
        self.btn_ecb.setEnabled(False)
        self.txt_ecb.setPlaceholderText("Trwa szyfrowanie...")
        try:
            demo = DemoECBvsCBC()
            wynik = demo.uruchom(liczba_blokow)
            self.txt_ecb.setPlainText(demo.formatuj(wynik))
            self._koloruj_wynik_ecb(wynik.identyczne_bloki_ecb, wynik.identyczne_bloki_cbc)
        except Exception as e:
            self.txt_ecb.setPlainText(f"Blad: {e}")
        finally:
            self.btn_ecb.setEnabled(True)

    def _koloruj_wynik_ecb(self, ecb: int, cbc: int) -> None:
        kursor = self.txt_ecb.textCursor()
        kursor.movePosition(QTextCursor.MoveOperation.End)
        self.txt_ecb.setTextCursor(kursor)

    def _uruchom_replay(self) -> None:
        wiad = self.pole_wiad_replay.text().strip() or "Przelej 1000 zl"
        self.btn_replay.setEnabled(False)
        try:
            demo = DemoBezNonce()
            wynik = demo.uruchom(wiad, powtorzenia=3)
            self.txt_replay.setPlainText(demo.formatuj(wynik))
        except Exception as e:
            self.txt_replay.setPlainText(f"Blad: {e}")
        finally:
            self.btn_replay.setEnabled(True)

    def _uruchom_bitflip(self) -> None:
        wiad = self.pole_wiad_bf.text().strip() or "Przelej 1000 zl na konto 12345"
        self.btn_bitflip.setEnabled(False)
        try:
            demo = DemoManipulacjaSzyfrogramu()
            wynik = demo.uruchom(wiad)
            self.txt_bitflip.setPlainText(demo.formatuj(wynik))
        except Exception as e:
            self.txt_bitflip.setPlainText(f"Blad: {e}")
        finally:
            self.btn_bitflip.setEnabled(True)


# ---------------------------------------------------------------------------
# PASEK GÓRNY (status + przyciski)
# ---------------------------------------------------------------------------

class _PasekGorny(QWidget):

    def __init__(self, rola: str):
        super().__init__()
        self.rola = rola
        self.setFixedHeight(56)
        self.setStyleSheet("background: #0f172a; border-bottom: 1px solid #374151;")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)

        # Etykieta roli
        lbl_rola = QLabel(rola.upper())
        lbl_rola.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl_rola.setStyleSheet(
            "color: #60a5fa; background: transparent;" if rola == "alice" else "color: #c084fc; background: transparent;"
        )
        lbl_rola.setFixedWidth(70)
        layout.addWidget(lbl_rola)

        # Badge połączenia
        self.badge_pol = self._badge("ROZŁĄCZONA", "#e74c3c")
        layout.addWidget(self.badge_pol)

        # Badge sesji
        self.badge_ses = self._badge("Brak sesji", "#7f8c8d")
        layout.addWidget(self.badge_ses)

        layout.addStretch()

        # Przycisk Połącz
        self.btn_polacz = QPushButton("Połącz")
        self.btn_polacz.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.btn_polacz.setStyleSheet("""
            QPushButton          { background:#16a34a; color:white; border:none;
                                   padding:5px 14px; border-radius:5px; font-weight:bold; }
            QPushButton:hover    { background:#15803d; }
            QPushButton:pressed  { background:#166534; }
            QPushButton:disabled { background:#4b5563; color:#9ca3af; }
        """)
        self.btn_polacz.setFixedHeight(34)
        layout.addWidget(self.btn_polacz)

        # Przycisk Rozłącz
        self.btn_rozlacz = QPushButton("Rozłącz")
        self.btn_rozlacz.setFont(QFont("Segoe UI", 10))
        self.btn_rozlacz.setStyleSheet("""
            QPushButton          { background:#dc2626; color:white; border:none;
                                   padding:5px 14px; border-radius:5px; }
            QPushButton:hover    { background:#b91c1c; }
            QPushButton:pressed  { background:#991b1b; }
            QPushButton:disabled { background:#4b5563; color:#9ca3af; }
        """)
        self.btn_rozlacz.setFixedHeight(34)
        self.btn_rozlacz.setEnabled(False)
        layout.addWidget(self.btn_rozlacz)

        # Wymiana kluczy (tylko Bob)
        if rola == 'bob':
            self.combo_bity = QComboBox()
            self.combo_bity.addItems(["RSA-512", "RSA-1024", "RSA-2048"])
            self.combo_bity.setCurrentIndex(1)
            self.combo_bity.setFixedHeight(34)
            self.combo_bity.setStyleSheet("""
                QComboBox {
                    background: #374151; color: #f9fafb;
                    border: 1px solid #4b5563; border-radius: 5px;
                    padding: 2px 8px;
                }
                QComboBox:hover { background: #4b5563; border-color: #6b7280; }
                QComboBox::drop-down { width: 16px; border-left: 1px solid #4b5563; }
                QComboBox QAbstractItemView {
                    background: #1f2937; color: #f9fafb;
                    border: 1px solid #4b5563;
                    selection-background-color: #374151;
                    selection-color: #f9fafb;
                    outline: none;
                }
            """)
            self.btn_wymiana = QPushButton("Wymień klucze RSA")
            self.btn_wymiana.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.btn_wymiana.setStyleSheet("""
                QPushButton          { background:#7c3aed; color:white; border:none;
                                       padding:5px 14px; border-radius:5px; font-weight:bold; }
                QPushButton:hover    { background:#6d28d9; }
                QPushButton:pressed  { background:#5b21b6; }
                QPushButton:disabled { background:#4b5563; color:#9ca3af; }
            """)
            self.btn_wymiana.setFixedHeight(34)
            self.btn_wymiana.setEnabled(False)
            layout.addWidget(self.combo_bity)
            layout.addWidget(self.btn_wymiana)
        else:
            self.combo_bity = None
            self.btn_wymiana = None

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
            self.badge_pol.setText("POŁĄCZONA" if self.rola == "alice" else "POŁĄCZONY")
            self.badge_pol.setStyleSheet(
                "background: #27ae60; color: white; padding: 3px 10px; "
                "border-radius: 10px; margin: 0 4px;"
            )
            self.btn_polacz.setEnabled(False)
            self.btn_rozlacz.setEnabled(True)
        else:
            self.badge_pol.setText("ROZŁĄCZONA" if self.rola == "alice" else "ROZŁĄCZONY")
            self.badge_pol.setStyleSheet(
                "background: #e74c3c; color: white; padding: 3px 10px; "
                "border-radius: 10px; margin: 0 4px;"
            )
            self.btn_polacz.setEnabled(True)
            self.btn_polacz.setText("Połącz")
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
    Dwa osobne okna = pełna komunikacja przez serwer.
    """

    def __init__(self, rola: str, port: int = 9999):
        super().__init__()
        self.rola = rola
        self.port = port
        self.setWindowTitle(f"Secure Messenger E2E — {rola.capitalize()}")
        self.setMinimumSize(560, 560)
        self.resize(720, 640)

        self._moj_watek: WatekKlienta | None = None
        self._zachowany_klient: KlientMessenger | None = None  # reuzywany przy reconnect
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
        self.czat     = ZakladkaCzat(rola)
        self.krypto   = ZakladkaKryptografia(rola)
        self.bench    = ZakladkaBenchmarki()
        self.ataki    = ZakladkaAtaki()

        self.tabs.addTab(self.czat,   "Czat")
        self.tabs.addTab(self.krypto, "Kryptografia / RSA Lab")
        self.tabs.addTab(self.bench,  "Benchmarki")
        self.tabs.addTab(self.ataki,  "Ataki / Analiza")
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
        self.pasek.btn_polacz.setText("Łączenie...")

        # Odlacz sygnaly starego watku przed zastapnieniem.
        # Bez tego stary WatekKlienta moze pozniej wyemitowac sygnal_rozlaczony
        # i przypadkowo zresetowac UI juz po uruchomieniu nowego polaczenia.
        if self._moj_watek is not None:
            try:
                self._moj_watek.sygnal_polaczony.disconnect()
                self._moj_watek.sygnal_status.disconnect()
                self._moj_watek.sygnal_blad.disconnect()
                self._moj_watek.sygnal_wiadomosc.disconnect()
                self._moj_watek.sygnal_bezpieczny.disconnect()
                self._moj_watek.sygnal_rozlaczony.disconnect()
            except (RuntimeError, TypeError):
                pass  # sygnaly juz odlaczone lub obiekt zniszczony

        self._moj_watek = WatekKlienta(self.rola, self.port, self._zachowany_klient)
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
            self.pasek.btn_polacz.setText("Połączono")
            self.krypto.dodaj_krok(self.rola[0].upper(), f"Połączono z serwerem jako '{self.rola}'")
            if self.rola == 'bob' and self.pasek.btn_wymiana:
                self.pasek.btn_wymiana.setEnabled(True)
        else:
            self.krypto.dodaj_krok("!", "Błąd połączenia z serwerem")

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
            # Fingerprint klucza pub — widoczny po wymianie kluczy RSA
            from secure_messenger.crypto.rsa import fingerprint_klucza
            if self.rola == 'bob' and k._klucze_rsa:
                n, e = k._klucze_rsa.klucz_publiczny
                fp = fingerprint_klucza(n, e)
                self.krypto.ustaw_fingerprint(fp)
                self.krypto.dodaj_krok("FP", f"Fingerprint własnego klucza pub: {fp[:16]}...")
                # Pozwol Bobowi wymienic klucze ponownie (np. zmiana rozmiaru RSA)
                if self.pasek.btn_wymiana:
                    self.pasek.btn_wymiana.setEnabled(True)
            elif self.rola == 'alice' and k._pub_boba:
                n, e = k._pub_boba
                fp = fingerprint_klucza(n, e)
                self.krypto.ustaw_fingerprint(fp)
                self.krypto.dodaj_krok("FP", f"Fingerprint odebranego klucza pub: {fp[:16]}...")
                # Status certyfikatu PKI (None = PKI wyłączone, True/False = wynik weryfikacji)
                cert_ok = k.certyfikat_zweryfikowany if k._klucz_pub_ca is not None else None
                self.krypto.ustaw_cert_status(cert_ok)

    def _na_wiadomosc(self, nadawca: str, tresc: str) -> None:
        """Odebrana wiadomość od drugiej strony — wyświetl u odbiorcy."""
        self.czat.dodaj_wiadomosc(nadawca.capitalize(), tresc, self._kolor_oni)

    def _rozlacz(self) -> None:
        if self._moj_watek and self._moj_watek.klient:
            self._moj_watek.klient.rozlacz()
        self.krypto.dodaj_krok("INFO", "Połączenie zamknięte przez użytkownika")
        self._reset_stanu()

    def _na_rozlaczenie(self) -> None:
        """Wywoływany gdy wątek sieciowy kończy pętlę (utrata połączenia)."""
        if self._polaczony:
            self.krypto.dodaj_krok("INFO", "Połączenie z serwerem utracone")
        self._reset_stanu()

    def _reset_stanu(self) -> None:
        """Przywraca UI do stanu 'rozłączony' — umożliwia ponowne połączenie."""
        # Zachowaj KlientMessenger — klucze sesji przezyja reconnect i pozwola
        # odszyfrować wiadomości zakolejkowane na serwerze podczas offline.
        if self._moj_watek and self._moj_watek.klient:
            self._zachowany_klient = self._moj_watek.klient

        self._polaczony = False
        self._bezpieczny = False
        self.pasek.ustaw_polaczony(False)
        self.pasek.ustaw_bezpieczny(False)
        if self.pasek.btn_wymiana:
            self.pasek.btn_wymiana.setEnabled(False)
        self.czat.ustaw_aktywny(False)
        self.krypto.ustaw_secure_mode(False)
        # Wyczysc fingerprint i status PKI — zapobiega pokazywaniu danych ze starej sesji
        self.krypto.lbl_fingerprint.setText("—  (oczekiwanie na wymianę kluczy)")
        if self.rola == 'alice':
            self.krypto.ustaw_cert_status(None)

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
            # Wyciagnij PRAWDZIWE IV/HMAC/szyfrogram z pakietu ktory faktycznie wyslano
            # Format: [4B session_id | 4B nonce | 16B IV | 32B HMAC | 4B len | N B ct]
            p = k.ostatni_pakiet_krypto
            if p and len(p) >= 60:
                iv  = p[8:24]
                tag = p[24:56]
                ct_len = int.from_bytes(p[56:60], 'big')
                ct  = p[60:60 + ct_len]
                self.czat.pokaz_szczegoly(iv, ct, tag)

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
        self.bench.lbl_postep.setText(f"Gotowe. Czas: {raport.czas_calkowity_s:.1f}s")

    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        if self._moj_watek and self._moj_watek.klient:
            self._moj_watek.klient.rozlacz()
        event.accept()


# Alias dla kompatybilnosci wstecznej (testy importuja GlowneOkno)
GlowneOkno = OknoKlienta
