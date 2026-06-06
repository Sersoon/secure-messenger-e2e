"""
Okno serwera — panel administracyjny i centrum sterowania Eve.

Pokazuje:
    - Status serwera (port, czy dziala)
    - Liste polaczonych klientow (Alice, Bob)
    - Logi w czasie rzeczywistym
    - Tryb Eve: checkboxy MITM i Replay, przycisk "Wyslij Replay"

Serwer startuje AUTOMATYCZNIE przy otwarciu okna.
Wszystkie callbacki serwera trafiaja przez Qt sygnaly (thread-safe).
"""

import threading

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QGroupBox, QCheckBox, QFrame
)
from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor

from secure_messenger.network.server import SerwerRoutera


# ---------------------------------------------------------------------------
# Pomocnicze sygnaly Qt — potrzebne do bezpiecznej komunikacji wątek→GUI
# ---------------------------------------------------------------------------

class _Sygnaly(QObject):
    sygnal_log                 = pyqtSignal(str)
    sygnal_klienci             = pyqtSignal(list)
    sygnal_pakiet_przechwycony = pyqtSignal()
    sygnal_kolejka             = pyqtSignal(str, int)   # (nazwa_klienta, rozmiar)


# ---------------------------------------------------------------------------
# OKNO SERWERA
# ---------------------------------------------------------------------------

class OknoSerwera(QMainWindow):
    """
    Maly panel serwera: widoczny przez caly czas trwania sesji demo.
    Steruje trybem Eve (MITM i Replay) przez checkboxy.
    """

    def __init__(self, port: int = 9999):
        super().__init__()
        self.port = port
        self.setWindowTitle("Secure Messenger — Serwer / Eve")
        self.setMinimumSize(360, 500)

        self._sygnaly = _Sygnaly()
        self._sygnaly.sygnal_log.connect(self._na_log)
        self._sygnaly.sygnal_klienci.connect(self._na_klienci)
        self._sygnaly.sygnal_pakiet_przechwycony.connect(self._na_pakiet_przechwycony)
        self._sygnaly.sygnal_kolejka.connect(self._na_kolejka)

        # Stan odznaki klientów (połączenie + kolejka)
        self._polaczeni: list = []
        self._kolejka_alice: int = 0
        self._kolejka_bob:   int = 0

        self._serwer = SerwerRoutera(
            port=port,
            on_log=lambda m: self._sygnaly.sygnal_log.emit(m),
            on_klienci=lambda k: self._sygnaly.sygnal_klienci.emit(k),
            on_pakiet_przechwycony=lambda: self._sygnaly.sygnal_pakiet_przechwycony.emit(),
            on_kolejka=lambda n, i: self._sygnaly.sygnal_kolejka.emit(n, i),
        )

        self._buduj_ui()
        self._uruchom_serwer()

    # ------------------------------------------------------------------
    # BUDOWANIE UI
    # ------------------------------------------------------------------

    def _buduj_ui(self) -> None:
        centralny = QWidget()
        self.setCentralWidget(centralny)
        layout = QVBoxLayout(centralny)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        # Naglowek
        tytul = QLabel("Serwer TCP — Router / Eve")
        tytul.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        tytul.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(tytul)

        # Status serwera
        self.lbl_status = QLabel(f"Nasluchuję na 127.0.0.1:{self.port}")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_status.setStyleSheet(
            "background: #27ae60; color: white; font-weight: bold; "
            "padding: 5px; border-radius: 4px;"
        )
        layout.addWidget(self.lbl_status)

        # Lista klientow
        grp_klienci = QGroupBox("Polaczeni klienci")
        lay_k = QHBoxLayout(grp_klienci)
        self.lbl_alice = self._badge("Alice", "#7f8c8d")
        self.lbl_bob   = self._badge("Bob",   "#7f8c8d")
        lay_k.addWidget(self.lbl_alice)
        lay_k.addWidget(self.lbl_bob)
        lay_k.addStretch()
        layout.addWidget(grp_klienci)

        # Separtor
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #374151;")
        layout.addWidget(sep)

        # Tryb Eve
        grp_eve = QGroupBox("Tryb Eve (ataki)")
        grp_eve.setStyleSheet("""
            QGroupBox {
                font-weight: bold; color: #fca5a5;
                border: 2px solid #7f1d1d;
                border-radius: 8px;
                margin-top: 12px; padding-top: 10px;
                background: #1a0808;
            }
            QGroupBox::title {
                color: #fca5a5; left: 10px;
                padding: 0 5px; background: #1a0808;
            }
        """)
        lay_e = QVBoxLayout(grp_eve)

        # MITM checkbox
        self.chk_mitm = QCheckBox(
            "Włącz MITM — Eve przechwytuje klucze RSA i czyta wiadomosci"
        )
        self.chk_mitm.setStyleSheet("""
            QCheckBox          { font-weight: bold; color: #fca5a5; }
            QCheckBox:disabled { color: #6b7280; }
            QCheckBox::indicator:checked { background: #dc2626; border-color: #dc2626; }
        """)
        self.chk_mitm.toggled.connect(self._na_mitm)
        lay_e.addWidget(self.chk_mitm)

        lbl_mitm_opis = QLabel(
            "  Eve podstawia swój klucz pub zamiast Boba.\n"
            "  Alice szyfruje klucze AES+HMAC dla Eve (nie Boba).\n"
            "  Eve re-szyfruje i przekazuje — Alice i Bob nie wiedzą."
        )
        lbl_mitm_opis.setStyleSheet("color: #6b7280; font-size: 9px; margin-left: 20px;")
        lay_e.addWidget(lbl_mitm_opis)

        # Linia oddzielajaca
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("color: #7f1d1d;")
        lay_e.addWidget(sep2)

        # Replay checkbox + przycisk
        self.chk_replay = QCheckBox("Włącz Replay — przechwytuj pakiety MSG")
        self.chk_replay.setStyleSheet("""
            QCheckBox          { font-weight: bold; color: #fca5a5; }
            QCheckBox:disabled { color: #6b7280; }
            QCheckBox::indicator:checked { background: #dc2626; border-color: #dc2626; }
        """)
        self.chk_replay.toggled.connect(self._na_replay)
        lay_e.addWidget(self.chk_replay)

        lay_replay_btn = QHBoxLayout()
        lbl_replay_opis = QLabel("  Po przechwyceniu: kliknie Wyslij Replay →")
        lbl_replay_opis.setStyleSheet("color: #7f8c8d; font-size: 9px;")
        self.btn_replay = QPushButton("Wyslij Replay!")
        self.btn_replay.setEnabled(False)
        self._STYL_REPLAY_OFF = """
            QPushButton {
                background: #6b7280; color: #d1d5db;
                font-weight: bold; padding: 4px 10px;
                border: 1px solid #4b5563; border-radius: 5px;
            }
        """
        self._STYL_REPLAY_ON = """
            QPushButton {
                background: #dc2626; color: white;
                font-weight: bold; padding: 4px 10px;
                border: 2px solid #991b1b; border-radius: 5px;
            }
            QPushButton:hover   { background: #b91c1c; }
            QPushButton:pressed { background: #991b1b; }
        """
        self.btn_replay.setStyleSheet(self._STYL_REPLAY_OFF)
        self.btn_replay.clicked.connect(self._na_wyslij_replay)
        lay_replay_btn.addWidget(lbl_replay_opis)
        lay_replay_btn.addStretch()
        lay_replay_btn.addWidget(self.btn_replay)
        lay_e.addLayout(lay_replay_btn)

        layout.addWidget(grp_eve)

        # Log
        grp_log = QGroupBox("Dziennik serwera")
        lay_log = QVBoxLayout(grp_log)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("Consolas", 8))
        self.log.setMinimumHeight(200)
        lay_log.addWidget(self.log)
        layout.addWidget(grp_log)

    def _badge(self, tekst: str, kolor: str) -> QLabel:
        lbl = QLabel(f"● {tekst}")
        lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {kolor}; padding: 4px 10px;")
        return lbl

    # ------------------------------------------------------------------
    # URUCHAMIANIE SERWERA
    # ------------------------------------------------------------------

    def _uruchom_serwer(self) -> None:
        try:
            self._serwer.uruchom(w_tle=True)
        except Exception as e:
            self.lbl_status.setText(f"BLAD: {e}")
            self.lbl_status.setStyleSheet(
                "background: #c0392b; color: white; padding: 5px; border-radius: 4px;"
            )

    # ------------------------------------------------------------------
    # SLOTY
    # ------------------------------------------------------------------

    def _na_log(self, msg: str) -> None:
        kolor = "#f87171" if "EVE" in msg or "MITM" in msg or "REPLAY" in msg or "ATAK" in msg else "#9ca3af"
        self.log.append(f'<span style="color:{kolor};">{msg}</span>')
        self.log.moveCursor(QTextCursor.MoveOperation.End)

    def _na_klienci(self, lista: list) -> None:
        self._polaczeni = lista
        self._odswiezBadge('alice')
        self._odswiezBadge('bob')

    def _na_kolejka(self, nazwa: str, rozmiar: int) -> None:
        if nazwa == 'alice':
            self._kolejka_alice = rozmiar
        else:
            self._kolejka_bob = rozmiar
        self._odswiezBadge(nazwa)

    def _odswiezBadge(self, nazwa: str) -> None:
        lbl = self.lbl_alice if nazwa == 'alice' else self.lbl_bob
        polaczony = nazwa in self._polaczeni
        kolejka   = self._kolejka_alice if nazwa == 'alice' else self._kolejka_bob

        if polaczony:
            tekst = f"● {nazwa.capitalize()}"
            kolor = "#27ae60"
        elif kolejka > 0:
            tekst = f"● {nazwa.capitalize()} ({kolejka} oczekuje)"
            kolor = "#e67e22"
        else:
            tekst = f"● {nazwa.capitalize()}"
            kolor = "#7f8c8d"

        lbl.setText(tekst)
        lbl.setStyleSheet(f"color: {kolor}; padding: 4px 10px; font-weight: bold;")

    def _na_pakiet_przechwycony(self) -> None:
        self.btn_replay.setEnabled(True)
        self.btn_replay.setStyleSheet(self._STYL_REPLAY_ON)

    def _na_mitm(self, wlaczony: bool) -> None:
        self.chk_mitm.setEnabled(False)
        threading.Thread(
            target=self._ustaw_mitm_w_tle,
            args=(wlaczony,),
            daemon=True
        ).start()

    def _ustaw_mitm_w_tle(self, wlaczony: bool) -> None:
        try:
            self._serwer.ustaw_mitm(wlaczony)
        except Exception as e:
            self._sygnaly.sygnal_log.emit(f"[BLAD] ustaw_mitm: {e}")
        finally:
            self.chk_mitm.setEnabled(True)

    def _na_replay(self, wlaczony: bool) -> None:
        self._serwer.ustaw_replay(wlaczony)
        if not wlaczony:
            self.btn_replay.setEnabled(False)
            self.btn_replay.setStyleSheet(self._STYL_REPLAY_OFF)

    def _na_wyslij_replay(self) -> None:
        ok = self._serwer.wyslij_replay()
        if not ok:
            self._na_log("[??:??:??] Brak przechwyconeho pakietu do replay")

    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        self._serwer.zatrzymaj()
        event.accept()
