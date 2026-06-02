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
import os
import tempfile

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QGroupBox,
    QTableWidget, QTableWidgetItem, QComboBox, QSplitter,
    QProgressBar, QHeaderView, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QTextCursor

from secure_messenger.network.client import KlientMessenger
from secure_messenger.benchmarks.benchmark import uruchom_wszystkie_benchmarki, WynikBenchmarku
from secure_messenger.security.attacks import AtakMITM, AtakReplay, DemoBezNonce


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
    sygnal_steg_image = pyqtSignal(str, bytes)   # (nadawca, bajty_ppm)

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
            self.klient._on_wiadomosc  = lambda n, t: self.sygnal_wiadomosc.emit(n, t)
            self.klient._on_status     = lambda s: self._na_status(s)
            self.klient._on_blad       = lambda e: self.sygnal_blad.emit(e)
            self.klient._on_steg_image = lambda n, d: self.sygnal_steg_image.emit(n, d)
        else:
            self.klient = KlientMessenger(
                nazwa=self.nazwa,
                port=self.port,
                on_wiadomosc=lambda n, t: self.sygnal_wiadomosc.emit(n, t),
                on_status=lambda s: self._na_status(s),
                on_blad=lambda e: self.sygnal_blad.emit(e),
                on_steg_image=lambda n, d: self.sygnal_steg_image.emit(n, d),
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


class WatekAtaku(QThread):
    """Uruchamia symulacje atakow w tle (nie blokuje GUI)."""
    sygnal_krok   = pyqtSignal(str, str)   # (numer, opis kroku)
    sygnal_gotowy = pyqtSignal(str)        # podsumowanie wynikow

    def __init__(self, rodzaj: str, parametry: dict):
        super().__init__()
        self.rodzaj = rodzaj
        self.parametry = parametry

    def run(self) -> None:
        def postep(nr, opis):
            self.sygnal_krok.emit(str(nr), opis)

        if self.rodzaj == 'mitm':
            atak = AtakMITM()
            wynik = atak.symuluj(
                wiadomosci_alice=self.parametry.get('wiadomosci', ['Test']),
                modyfikacja=self.parametry.get('modyfikacja'),
                bity_rsa=self.parametry.get('bity', 512),
                on_postep=postep,
            )
            self.sygnal_gotowy.emit(
                f"Wiadomosci Eve: {len(wynik.wiadomosci_eve)} | "
                f"Modyfikacje: {len(wynik.wiadomosci_zmodyfikowane)} | "
                f"MITM: {'UDANY' if wynik.sukces else 'NIEUDANY'}"
            )
        elif self.rodzaj == 'replay':
            atak = AtakReplay()
            wynik = atak.symuluj(
                wiadomosc=self.parametry.get('wiadomosc', 'Test'),
                ile_replay=self.parametry.get('ile_replay', 3),
                on_postep=postep,
            )
            self.sygnal_gotowy.emit(
                f"Replay prob: {wynik.pakiety_replay} | "
                f"Wykryte: {wynik.pakiety_wykryte} | "
                f"Ochrona: {'SKUTECZNA' if not wynik.sukces_ataku else 'NARUSZONA'}"
            )
        elif self.rodzaj == 'demo_bez_nonce':
            demo = DemoBezNonce()
            wynik = demo.symuluj_bez_ochrony(
                wiadomosc=self.parametry.get('wiadomosc', 'Przelej 500 zl'),
                on_postep=postep,
            )
            self.sygnal_gotowy.emit(
                f"Replay BEZ nonce: {wynik['replay_udane']}/3 przeszly — "
                f"{'BRAK OCHRONY!' if wynik['replay_udane'] > 0 else 'OK'}"
            )


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
                    item.setBackground(QColor("#292103"))
                    item.setForeground(QColor("#fbbf24"))
                else:
                    item.setForeground(QColor("#e5e7eb"))
                self.tabela.setItem(r, c, item)
        self.lbl_czas.setText(f"Czas calkowity: {raport.czas_calkowity_s:.1f}s")


# ---------------------------------------------------------------------------
# ZAKŁADKA: SECURITY LAB (symulacje standalone z attacks.py)
# ---------------------------------------------------------------------------

class ZakladkaSecurityLab(QWidget):
    """
    Prezentuje trzy standalone symulacje z attacks.py:
      1. Replay z nonce  — 0/3 przechodzi (ochrona dziala)
      2. Replay bez nonce — 3/3 przechodzi (brak ochrony)
      3. MITM standalone  — krok-po-kroku z logami
    Uzupelnia live demos w oknie serwera.
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        tytul = QLabel("Security Lab — Symulacje Algorytmiczne")
        tytul.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        layout.addWidget(tytul)

        opis = QLabel(
            "Symulacje standalone (bez sieci TCP). "
            "Live ataki MITM i Replay sa dostepne w oknie Serwera."
        )
        opis.setStyleSheet("color: #7f8c8d; font-size: 9px;")
        layout.addWidget(opis)

        # --- Replay z nonce ---
        grp_replay = QGroupBox("Replay Attack — z ochrona nonce (powinno byc 0/3)")
        lay_r = QVBoxLayout(grp_replay)
        ktrle_r = QHBoxLayout()
        self.pole_wiad_replay = QLineEdit("Przelej 1000 zl na konto Ewy")
        self.btn_replay = QPushButton("Uruchom Replay")
        self.btn_replay.setFixedWidth(140)
        ktrle_r.addWidget(QLabel("Wiadomosc:")); ktrle_r.addWidget(self.pole_wiad_replay)
        ktrle_r.addWidget(self.btn_replay)
        lay_r.addLayout(ktrle_r)
        self.log_replay = QTextEdit()
        self.log_replay.setReadOnly(True)
        self.log_replay.setMaximumHeight(100)
        self.log_replay.setFont(QFont("Consolas", 8))
        lay_r.addWidget(self.log_replay)
        self.lbl_wynik_replay = QLabel("")
        self.lbl_wynik_replay.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay_r.addWidget(self.lbl_wynik_replay)
        layout.addWidget(grp_replay)

        # --- Demo bez nonce ---
        grp_demo = QGroupBox("Demo: Replay BEZ nonce — 3/3 przechodzi (dlaczego nonce jest konieczny)")
        grp_demo.setStyleSheet("""
            QGroupBox {
                font-weight: bold; color: #fca5a5;
                border: 2px solid #7f1d1d;
                border-radius: 8px;
                margin-top: 12px; padding-top: 10px;
                background: #1a0808;
            }
            QGroupBox::title {
                color: #fca5a5; left: 8px;
                padding: 0 5px; background: #1a0808;
            }
        """)
        lay_d = QVBoxLayout(grp_demo)
        self.btn_bez_nonce = QPushButton("Uruchom demo — pokazuje atak ktory by przeszedl bez nonce")
        lay_d.addWidget(self.btn_bez_nonce)
        self.log_bez_nonce = QTextEdit()
        self.log_bez_nonce.setReadOnly(True)
        self.log_bez_nonce.setMaximumHeight(90)
        self.log_bez_nonce.setFont(QFont("Consolas", 8))
        lay_d.addWidget(self.log_bez_nonce)
        self.lbl_wynik_demo = QLabel("")
        self.lbl_wynik_demo.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay_d.addWidget(self.lbl_wynik_demo)
        layout.addWidget(grp_demo)

        # --- MITM standalone ---
        grp_mitm = QGroupBox("MITM — symulacja krok po kroku (standalone)")
        lay_m = QVBoxLayout(grp_mitm)
        ktrle_m = QHBoxLayout()
        self.combo_bity_mitm = QComboBox()
        self.combo_bity_mitm.addItems(["RSA-512 (szybki)", "RSA-1024"])
        self.combo_tryb = QComboBox()
        self.combo_tryb.addItems(["Tylko podsluch", "Podsluch + modyfikacja"])
        self.btn_mitm = QPushButton("Uruchom MITM")
        self.btn_mitm.setFixedWidth(130)
        ktrle_m.addWidget(QLabel("RSA:")); ktrle_m.addWidget(self.combo_bity_mitm)
        ktrle_m.addWidget(QLabel("Tryb:")); ktrle_m.addWidget(self.combo_tryb)
        ktrle_m.addStretch(); ktrle_m.addWidget(self.btn_mitm)
        lay_m.addLayout(ktrle_m)
        self.log_mitm = QTextEdit()
        self.log_mitm.setReadOnly(True)
        self.log_mitm.setMaximumHeight(150)
        self.log_mitm.setFont(QFont("Consolas", 8))
        lay_m.addWidget(self.log_mitm)
        self.lbl_wynik_mitm = QLabel("")
        self.lbl_wynik_mitm.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay_m.addWidget(self.lbl_wynik_mitm)
        layout.addWidget(grp_mitm)

    def _kolor(self, opis: str) -> str:
        if any(s in opis for s in ("WYKRY", "SKUTECZNA", "POPRAWNY", "ochrona")):
            return "#4ade80"
        if any(s in opis for s in ("UDANY", "Eve", "REPLAY", "przeszl", "BRAK", "MITM")):
            return "#f87171"
        return "#9ca3af"

    def dodaj_krok(self, log: QTextEdit, nr: str, opis: str) -> None:
        kolor = self._kolor(opis)
        log.append(f'<span style="color:{kolor};">[{nr}] {opis}</span>')
        log.moveCursor(QTextCursor.MoveOperation.End)


# ---------------------------------------------------------------------------
# ZAKŁADKA: STEGANOGRAFIA LSB
# ---------------------------------------------------------------------------

class ZakladkaSteganografia(QWidget):
    """Demo steganografii LSB — ukrywanie tekstu w obrazie PPM krok po kroku."""

    sygnal_wyslij_steg = pyqtSignal(bytes)  # emitowany gdy user kliknie "Ukryj i wyslij"

    def __init__(self):
        super().__init__()
        self._sciezka_oryg: str | None = None
        self._sciezka_stego: str | None = None
        self._odebrany_ppm: bytes | None = None   # ostatnio odebrany obraz przez siec
        self._odebrany_od:  str   | None = None   # nadawca odebranego obrazu

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        tytul = QLabel("Steganografia LSB — Ukrywanie danych w obrazach PPM")
        tytul.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        layout.addWidget(tytul)

        opis = QLabel(
            "Każdy piksel (R, G, B) = 3 bajty. Zmieniamy wyłącznie ostatni bit (LSB) "
            "każdego bajtu — różnica wartości o ±1 jest niewidoczna gołym okiem."
        )
        opis.setStyleSheet("color: #7f8c8d; font-size: 9px;")
        opis.setWordWrap(True)
        layout.addWidget(opis)

        # Krok 1 — tworzenie obrazu
        grp1 = QGroupBox("Krok 1 — Obraz nośny (format PPM P6, bez kompresji)")
        lay1 = QVBoxLayout(grp1)
        row1 = QHBoxLayout()
        self.combo_rozmiar = QComboBox()
        self.combo_rozmiar.addItems([
            "64×64 px  (pojemność ~1.5 KB)",
            "128×128 px  (~6 KB)",
            "256×256 px  (~24 KB)",
        ])
        self.btn_stworz = QPushButton("Stwórz losowy obraz")
        self.btn_stworz.setFixedWidth(170)
        row1.addWidget(QLabel("Rozmiar:"))
        row1.addWidget(self.combo_rozmiar)
        row1.addStretch()
        row1.addWidget(self.btn_stworz)
        lay1.addLayout(row1)
        self.lbl_info_obrazu = QLabel("— kliknij 'Stwórz losowy obraz' —")
        self.lbl_info_obrazu.setStyleSheet("color: #9ca3af; font-size: 9px;")
        lay1.addWidget(self.lbl_info_obrazu)
        layout.addWidget(grp1)

        # Krok 2 — ukrywanie
        grp2 = QGroupBox("Krok 2 — Ukryj wiadomość w obrazie")
        lay2 = QVBoxLayout(grp2)
        row2 = QHBoxLayout()
        self.pole_wiad = QLineEdit("Tajna wiadomosc: klucz_AES=1A2B3C4D5E6F7890")
        self.btn_ukryj = QPushButton("Ukryj w obrazie")
        self.btn_ukryj.setFixedWidth(140)
        self.btn_ukryj.setEnabled(False)
        row2.addWidget(QLabel("Wiadomosc:"))
        row2.addWidget(self.pole_wiad)
        row2.addWidget(self.btn_ukryj)
        lay2.addLayout(row2)
        self.lbl_wynik_ukrycia = QLabel("")
        self.lbl_wynik_ukrycia.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay2.addWidget(self.lbl_wynik_ukrycia)
        layout.addWidget(grp2)

        # Krok 3 — odczyt
        grp3 = QGroupBox("Krok 3 — Odczytaj wiadomosc ze steganogramu")
        lay3 = QVBoxLayout(grp3)
        row3 = QHBoxLayout()
        self.btn_odczytaj = QPushButton("Odczytaj wiadomosc")
        self.btn_odczytaj.setFixedWidth(160)
        self.btn_odczytaj.setEnabled(False)
        self.pole_odczyt = QLineEdit()
        self.pole_odczyt.setReadOnly(True)
        self.pole_odczyt.setFont(QFont("Consolas", 9))
        self.pole_odczyt.setPlaceholderText("— tutaj pojawi sie odczytana wiadomosc —")
        row3.addWidget(self.btn_odczytaj)
        row3.addWidget(self.pole_odczyt)
        lay3.addLayout(row3)
        self.lbl_wynik_odczytu = QLabel("")
        self.lbl_wynik_odczytu.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay3.addWidget(self.lbl_wynik_odczytu)
        layout.addWidget(grp3)

        # Krok 4 — wizualizacja LSB
        grp4 = QGroupBox("Krok 4 — Wizualizacja LSB (pierwsze 16 bajtow pikseli w formacie binarnym)")
        lay4 = QVBoxLayout(grp4)
        opis4 = QLabel(
            "Ostatni bit (LSB) każdego bajtu zaznaczony kolorem — "
            "<span style='color:#ef4444; font-weight:bold;'>czerwony = 1</span> &nbsp; "
            "<span style='color:#9ca3af;'>szary = 0</span> &nbsp; "
            "Pozostałe 7 bitów jest niezmienione."
        )
        opis4.setStyleSheet("font-size: 9px;")
        lay4.addWidget(opis4)

        row4 = QHBoxLayout()

        grp_przed = QGroupBox("Oryginal (przed ukryciem)")
        lay_przed = QVBoxLayout(grp_przed)
        self.txt_przed = QTextEdit()
        self.txt_przed.setReadOnly(True)
        self.txt_przed.setMaximumHeight(115)
        self.txt_przed.setFont(QFont("Consolas", 8))
        lay_przed.addWidget(self.txt_przed)

        grp_po = QGroupBox("Steganogram (po ukryciu)")
        lay_po = QVBoxLayout(grp_po)
        self.txt_po = QTextEdit()
        self.txt_po.setReadOnly(True)
        self.txt_po.setMaximumHeight(115)
        self.txt_po.setFont(QFont("Consolas", 8))
        lay_po.addWidget(self.txt_po)

        row4.addWidget(grp_przed)
        row4.addWidget(grp_po)
        lay4.addLayout(row4)

        self.lbl_diff = QLabel("")
        self.lbl_diff.setFont(QFont("Segoe UI", 9))
        lay4.addWidget(self.lbl_diff)
        layout.addWidget(grp4)

        # Krok 5 — wysyłanie i odbieranie przez sieć TCP
        grp5 = QGroupBox("Krok 5 — Wysylanie i odbieranie przez siec TCP")
        lay5 = QVBoxLayout(grp5)

        row5a = QHBoxLayout()
        self.lbl_polaczenie_steg = QLabel("Brak polaczenia z serwerem")
        self.lbl_polaczenie_steg.setStyleSheet("color: #9ca3af; font-size: 9px;")
        row5a.addWidget(self.lbl_polaczenie_steg)
        row5a.addStretch()
        lay5.addLayout(row5a)

        row5b = QHBoxLayout()
        self.btn_ukryj_i_wyslij = QPushButton("Ukryj i wyslij do drugiej strony")
        self.btn_ukryj_i_wyslij.setFixedWidth(240)
        self.btn_ukryj_i_wyslij.setEnabled(False)
        self.btn_ukryj_i_wyslij.setStyleSheet("""
            QPushButton          { background:#0369a1; color:white; border:none;
                                   padding:5px 12px; border-radius:5px; font-weight:bold; }
            QPushButton:hover    { background:#0284c7; }
            QPushButton:pressed  { background:#075985; }
            QPushButton:disabled { background:#4b5563; color:#9ca3af; }
        """)
        self.lbl_wynik_wysylki = QLabel("")
        self.lbl_wynik_wysylki.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        row5b.addWidget(self.btn_ukryj_i_wyslij)
        row5b.addWidget(self.lbl_wynik_wysylki)
        row5b.addStretch()
        lay5.addLayout(row5b)

        row5c = QHBoxLayout()
        self.btn_odczytaj_odebrany = QPushButton("Odczytaj odebrany obraz")
        self.btn_odczytaj_odebrany.setFixedWidth(190)
        self.btn_odczytaj_odebrany.setEnabled(False)
        self.pole_odczyt_odebrany = QLineEdit()
        self.pole_odczyt_odebrany.setReadOnly(True)
        self.pole_odczyt_odebrany.setFont(QFont("Consolas", 9))
        self.pole_odczyt_odebrany.setPlaceholderText("— odczytana wiadomosc z odebranego obrazu —")
        row5c.addWidget(self.btn_odczytaj_odebrany)
        row5c.addWidget(self.pole_odczyt_odebrany)
        lay5.addLayout(row5c)

        self.lbl_odebrany_status = QLabel("")
        self.lbl_odebrany_status.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        lay5.addWidget(self.lbl_odebrany_status)
        layout.addWidget(grp5)

        layout.addStretch()

        self.btn_stworz.clicked.connect(self._stworz_obraz)
        self.btn_ukryj.clicked.connect(self._ukryj)
        self.btn_odczytaj.clicked.connect(self._odczytaj)
        self.btn_ukryj_i_wyslij.clicked.connect(self._ukryj_i_wyslij)
        self.btn_odczytaj_odebrany.clicked.connect(self._odczytaj_odebrany_steg)

    # ------------------------------------------------------------------

    def _stworz_obraz(self) -> None:
        from secure_messenger.steganography.lsb import stworz_ppm, oblicz_pojemnosc

        rozmiary = [(64, 64), (128, 128), (256, 256)]
        w, h = rozmiary[self.combo_rozmiar.currentIndex()]
        tmpdir = tempfile.mkdtemp(prefix="stego_")
        self._sciezka_oryg = os.path.join(tmpdir, "oryg.ppm")
        self._sciezka_stego = os.path.join(tmpdir, "stego.ppm")

        stworz_ppm(self._sciezka_oryg, w, h)
        info = oblicz_pojemnosc(self._sciezka_oryg)

        self.lbl_info_obrazu.setText(
            f"Obraz {info['szerokosc']}×{info['wysokosc']} px  |  "
            f"Piksele: {info['piksele']:,}  |  "
            f"Pojemnosc: {info['pojemnosc_opis']}  "
            f"({info['pojemnosc_bajtow'] * 8:,} bitow nosnych)"
        )
        self.lbl_info_obrazu.setStyleSheet("color: #4ade80; font-size: 9px;")
        self.btn_ukryj.setEnabled(True)
        self.btn_odczytaj.setEnabled(False)
        for lbl in (self.lbl_wynik_ukrycia, self.lbl_wynik_odczytu, self.lbl_diff):
            lbl.clear()
        self.pole_odczyt.clear()
        self.txt_po.clear()
        self._wypelnij_wizualizacje(self._sciezka_oryg, self.txt_przed)

    def _ukryj(self) -> None:
        if not self._sciezka_oryg:
            return
        from secure_messenger.steganography.lsb import ukryj_wiadomosc

        wiad = self.pole_wiad.text().encode('utf-8')
        try:
            bity = ukryj_wiadomosc(self._sciezka_oryg, self._sciezka_stego, wiad)
            rozmiar_obrazu = os.path.getsize(self._sciezka_stego)
            self.lbl_wynik_ukrycia.setText(
                f"Ukryto {len(wiad)} B ({len(wiad) * 8} bitow)  |  "
                f"Zmodyfikowano {bity} LSB z {rozmiar_obrazu} bajtow obrazu  "
                f"({bity / rozmiar_obrazu * 100:.2f}% bajtow tknietych)"
            )
            self.lbl_wynik_ukrycia.setStyleSheet("color: #4ade80; font-weight: bold;")
            self.btn_odczytaj.setEnabled(True)
            self._wypelnij_wizualizacje(self._sciezka_stego, self.txt_po)
            self._pokaz_diff()
        except (ValueError, FileNotFoundError) as e:
            self.lbl_wynik_ukrycia.setText(f"Blad: {e}")
            self.lbl_wynik_ukrycia.setStyleSheet("color: #f87171;")

    def _odczytaj(self) -> None:
        if not self._sciezka_stego:
            return
        from secure_messenger.steganography.lsb import odczytaj_wiadomosc

        try:
            dane = odczytaj_wiadomosc(self._sciezka_stego)
            tekst = dane.decode('utf-8', errors='replace')
            self.pole_odczyt.setText(tekst)
            ok = tekst == self.pole_wiad.text()
            self.lbl_wynik_odczytu.setText(
                "Wiadomosc odczytana poprawnie — identyczna z oryginalem!"
                if ok else "Uwaga: roznica miedzy oryginalem a odczytem"
            )
            self.lbl_wynik_odczytu.setStyleSheet(
                "color: #4ade80;" if ok else "color: #f87171;"
            )
        except Exception as e:
            self.lbl_wynik_odczytu.setText(f"Blad odczytu: {e}")
            self.lbl_wynik_odczytu.setStyleSheet("color: #f87171;")

    def _fragment_pikseli(self, sciezka: str, n: int) -> bytes | None:
        try:
            with open(sciezka, 'rb') as f:
                f.readline()        # P6
                linia = f.readline()
                while linia.startswith(b'#'):
                    linia = f.readline()
                f.readline()        # 255
                return f.read(n)
        except Exception:
            return None

    def _wypelnij_wizualizacje(self, sciezka: str, widget: QTextEdit) -> None:
        dane = self._fragment_pikseli(sciezka, 16)
        if dane is None:
            return
        parts = ['<div style="font-family:Consolas; font-size:8pt; line-height:1.9;">']
        for i, b in enumerate(dane):
            bity_str = format(b, '08b')
            kolor = '#ef4444' if bity_str[-1] == '1' else '#9ca3af'
            parts.append(
                f'<span style="color:#d1d5db;">{bity_str[:7]}</span>'
                f'<span style="color:{kolor}; font-weight:bold;">{bity_str[7]}</span>'
            )
            parts.append('<br>' if (i + 1) % 4 == 0 else '&nbsp;')
        parts.append('</div>')
        widget.setHtml(''.join(parts))

    # ------------------------------------------------------------------
    # SIEĆ — sterowanie z OknoKlienta
    # ------------------------------------------------------------------

    def ustaw_polaczony(self, polaczony: bool) -> None:
        """Włącza/wyłącza przycisk wysyłania w zależności od stanu połączenia."""
        if polaczony:
            self.lbl_polaczenie_steg.setText(
                "Polaczono z serwerem — mozesz wyslac obraz steganograficzny"
            )
            self.lbl_polaczenie_steg.setStyleSheet("color: #4ade80; font-size: 9px;")
            self.btn_ukryj_i_wyslij.setEnabled(True)
        else:
            self.lbl_polaczenie_steg.setText("Brak polaczenia z serwerem")
            self.lbl_polaczenie_steg.setStyleSheet("color: #9ca3af; font-size: 9px;")
            self.btn_ukryj_i_wyslij.setEnabled(False)

    def na_odebrany_steg(self, nadawca: str, ppm_dane: bytes) -> None:
        """Wywoływana przez OknoKlienta gdy przyszedł pakiet STEG_IMAGE."""
        self._odebrany_ppm = ppm_dane
        self._odebrany_od  = nadawca
        self.lbl_odebrany_status.setText(
            f"[STEG] Odebrano obraz od {nadawca.capitalize()} "
            f"({len(ppm_dane)} B) — kliknij 'Odczytaj odebrany obraz'"
        )
        self.lbl_odebrany_status.setStyleSheet("color: #60a5fa; font-weight: bold;")
        self.btn_odczytaj_odebrany.setEnabled(True)
        self.pole_odczyt_odebrany.clear()

    def _ukryj_i_wyslij(self) -> None:
        """Tworzy obraz 128×128, ukrywa wiadomość z Kroku 2 i emituje sygnał wysyłania."""
        wiad = self.pole_wiad.text().strip()
        if not wiad:
            self.lbl_wynik_wysylki.setText("Wpisz wiadomosc w polu powyzej (Krok 2)")
            self.lbl_wynik_wysylki.setStyleSheet("color: #f87171;")
            return

        from secure_messenger.steganography.lsb import stworz_ppm, ukryj_wiadomosc

        self.lbl_wynik_wysylki.setText("[STEG] Tworzenie obrazu z ukryta wiadomoscia...")
        self.lbl_wynik_wysylki.setStyleSheet("color: #9ca3af;")
        try:
            tmpdir = tempfile.mkdtemp(prefix="steg_siec_")
            sc_oryg  = os.path.join(tmpdir, "oryg.ppm")
            sc_stego = os.path.join(tmpdir, "stego.ppm")
            stworz_ppm(sc_oryg, 128, 128)
            ukryj_wiadomosc(sc_oryg, sc_stego, wiad.encode('utf-8'))
            with open(sc_stego, 'rb') as f:
                ppm_dane = f.read()
            self.lbl_wynik_wysylki.setText(
                f"[STEG] Obraz wysylany ({len(ppm_dane)} B, "
                f"ukrytych {len(wiad.encode())} B)..."
            )
            self.lbl_wynik_wysylki.setStyleSheet("color: #4ade80; font-weight: bold;")
            self.sygnal_wyslij_steg.emit(ppm_dane)
        except Exception as e:
            self.lbl_wynik_wysylki.setText(f"[STEG] Blad: {e}")
            self.lbl_wynik_wysylki.setStyleSheet("color: #f87171;")

    def _odczytaj_odebrany_steg(self) -> None:
        """Odczytuje ukrytą wiadomość z ostatnio odebranego obrazu."""
        if self._odebrany_ppm is None:
            return
        from secure_messenger.steganography.lsb import odczytaj_wiadomosc

        try:
            tmpdir = tempfile.mkdtemp(prefix="steg_odb_")
            sc = os.path.join(tmpdir, "odebrany.ppm")
            with open(sc, 'wb') as f:
                f.write(self._odebrany_ppm)
            dane = odczytaj_wiadomosc(sc)
            tekst = dane.decode('utf-8', errors='replace')
            self.pole_odczyt_odebrany.setText(tekst)
            nadawca = (self._odebrany_od or '?').capitalize()
            self.lbl_odebrany_status.setText(
                f"[STEG] Odczytano ukryta wiadomosc od {nadawca}: \"{tekst[:60]}\""
            )
            self.lbl_odebrany_status.setStyleSheet("color: #4ade80; font-weight: bold;")
        except Exception as e:
            self.lbl_odebrany_status.setText(f"[STEG] Blad odczytu: {e}")
            self.lbl_odebrany_status.setStyleSheet("color: #f87171;")

    # ------------------------------------------------------------------

    def _pokaz_diff(self) -> None:
        if not (self._sciezka_oryg and self._sciezka_stego):
            return
        oryg  = self._fragment_pikseli(self._sciezka_oryg,  256)
        stego = self._fragment_pikseli(self._sciezka_stego, 256)
        if oryg is None or stego is None:
            return
        zmienione = sum(1 for a, b in zip(oryg, stego) if a != b)
        tylko_lsb = all((a & 0xFE) == (b & 0xFE) for a, b in zip(oryg, stego))
        if tylko_lsb:
            self.lbl_diff.setText(
                f"Analiza pierwszych {len(oryg)} bajtow: {zmienione} bajtow zmienionych, "
                f"kazda zmiana wylacznie w bicie LSB (±1) — obraz wyglada identycznie"
            )
            self.lbl_diff.setStyleSheet("color: #4ade80;")
        else:
            self.lbl_diff.setText("Wykryto zmiany powyzej LSB!")
            self.lbl_diff.setStyleSheet("color: #f87171;")


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
        self.btn_polacz.setStyleSheet("""
            QPushButton          { background:#16a34a; color:white; border:none;
                                   padding:5px 14px; border-radius:5px; font-weight:bold; }
            QPushButton:hover    { background:#15803d; }
            QPushButton:pressed  { background:#166534; }
            QPushButton:disabled { background:#4b5563; color:#9ca3af; }
        """)
        self.btn_polacz.setFixedHeight(34)
        layout.addWidget(self.btn_polacz)

        # Przycisk Rozlacz
        self.btn_rozlacz = QPushButton("Rozlacz")
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
            self.btn_wymiana = QPushButton("Wymien klucze RSA")
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
        self.sec_lab  = ZakladkaSecurityLab()
        self.bench    = ZakladkaBenchmarki()
        self.stego    = ZakladkaSteganografia()
        # Zakładka steganografii w QScrollArea — zawartość jest wyższa niż minimalne okno
        _stego_scroll = QScrollArea()
        _stego_scroll.setWidgetResizable(True)
        _stego_scroll.setWidget(self.stego)

        self.tabs.addTab(self.czat,     "Czat")
        self.tabs.addTab(self.krypto,   "Kryptografia / RSA Lab")
        self.tabs.addTab(self.sec_lab,  "Security Lab")
        self.tabs.addTab(self.bench,    "Benchmarki")
        self.tabs.addTab(_stego_scroll, "Steganografia")
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
        # Security Lab
        self.sec_lab.btn_replay.clicked.connect(self._uruchom_replay)
        self.sec_lab.btn_bez_nonce.clicked.connect(self._uruchom_demo_bez_nonce)
        self.sec_lab.btn_mitm.clicked.connect(self._uruchom_mitm)
        # Steganografia — sygnał wysyłania z zakładki do klienta sieciowego
        self.stego.sygnal_wyslij_steg.connect(self._wyslij_steg)

    # ------------------------------------------------------------------
    # POŁĄCZENIE
    # ------------------------------------------------------------------

    def _polacz(self) -> None:
        if self._polaczony:
            return
        self.pasek.btn_polacz.setEnabled(False)
        self.pasek.btn_polacz.setText("Laczenie...")

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
        self._moj_watek.sygnal_steg_image.connect(self._na_steg_image)
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
        self.stego.ustaw_polaczony(ok)
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
        # Zachowaj KlientMessenger — klucze sesji przezyja reconnect i pozwola
        # odszyfrować wiadomości zakolejkowane na serwerze podczas offline.
        if self._moj_watek and self._moj_watek.klient:
            self._zachowany_klient = self._moj_watek.klient

        self._polaczony = False
        self._bezpieczny = False
        self.pasek.ustaw_polaczony(False)
        self.pasek.ustaw_bezpieczny(False)
        self.stego.ustaw_polaczony(False)
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
    # STEGANOGRAFIA — wysyłanie i odbieranie
    # ------------------------------------------------------------------

    def _wyslij_steg(self, ppm_dane: bytes) -> None:
        """Wysyła obraz PPM przez klienta sieciowego po emisji sygnału z zakładki."""
        if not (self._moj_watek and self._moj_watek.klient):
            return
        cel = 'bob' if self.rola == 'alice' else 'alice'
        ok = self._moj_watek.klient.wyslij_steg_image(ppm_dane)
        if ok:
            self.krypto.dodaj_krok(
                "STEG",
                f"[STEG] Obraz wysłany do {cel.capitalize()} ({len(ppm_dane)} B)"
            )

    def _na_steg_image(self, nadawca: str, ppm_dane: bytes) -> None:
        """Wywoływany gdy wątek Qt odbierze sygnał sygnal_steg_image."""
        self.stego.na_odebrany_steg(nadawca, ppm_dane)
        self.krypto.dodaj_krok(
            "STEG",
            f"[STEG] Odebrano obraz od {nadawca.capitalize()} ({len(ppm_dane)} B)"
        )

    # ------------------------------------------------------------------
    # SECURITY LAB
    # ------------------------------------------------------------------

    def _uruchom_replay(self) -> None:
        self.sec_lab.log_replay.clear()
        self.sec_lab.btn_replay.setEnabled(False)
        wiad = self.sec_lab.pole_wiad_replay.text() or "Przelej 1000 zl"

        self._watek_replay = WatekAtaku("replay", {"wiadomosc": wiad, "ile_replay": 3})
        self._watek_replay.sygnal_krok.connect(
            lambda nr, op: self.sec_lab.dodaj_krok(self.sec_lab.log_replay, nr, op)
        )
        self._watek_replay.sygnal_gotowy.connect(lambda p: self._na_koniec_ataku(
            self.sec_lab.lbl_wynik_replay, self.sec_lab.btn_replay, p, kolor_sukces="#27ae60"
        ))
        self._watek_replay.start()

    def _uruchom_demo_bez_nonce(self) -> None:
        self.sec_lab.log_bez_nonce.clear()
        self.sec_lab.btn_bez_nonce.setEnabled(False)
        wiad = "Przelej 500 zl na konto Ewy"

        self._watek_demo = WatekAtaku("demo_bez_nonce", {"wiadomosc": wiad})
        self._watek_demo.sygnal_krok.connect(
            lambda nr, op: self.sec_lab.dodaj_krok(self.sec_lab.log_bez_nonce, nr, op)
        )
        self._watek_demo.sygnal_gotowy.connect(lambda p: self._na_koniec_ataku(
            self.sec_lab.lbl_wynik_demo, self.sec_lab.btn_bez_nonce, p, kolor_sukces="#c0392b"
        ))
        self._watek_demo.start()

    def _uruchom_mitm(self) -> None:
        self.sec_lab.log_mitm.clear()
        self.sec_lab.btn_mitm.setEnabled(False)
        bity = 512 if self.sec_lab.combo_bity_mitm.currentIndex() == 0 else 1024
        modyfikuj = self.sec_lab.combo_tryb.currentIndex() == 1

        self._watek_mitm = WatekAtaku("mitm", {
            "wiadomosci": ["Przelej 1000 zl na konto 123", "Haslo: SuperSecret"],
            "modyfikacja": (lambda t: t.replace("1000", "9999")) if modyfikuj else None,
            "bity": bity,
        })
        self._watek_mitm.sygnal_krok.connect(
            lambda nr, op: self.sec_lab.dodaj_krok(self.sec_lab.log_mitm, nr, op)
        )
        self._watek_mitm.sygnal_gotowy.connect(lambda p: self._na_koniec_ataku(
            self.sec_lab.lbl_wynik_mitm, self.sec_lab.btn_mitm, p, kolor_sukces="#c0392b"
        ))
        self._watek_mitm.start()

    def _na_koniec_ataku(self, lbl: QLabel, btn: QPushButton, podsum: str, kolor_sukces: str) -> None:
        lbl.setText(podsum)
        lbl.setStyleSheet(f"color: {kolor_sukces}; font-weight: bold;")
        btn.setEnabled(True)

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
