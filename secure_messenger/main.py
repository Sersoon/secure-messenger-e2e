"""
Punkt wejscia aplikacji Secure Messenger E2E.

Uruchamia 3 okna jednoczesnie:
    1. Serwer (OknoSerwera) — router TCP + tryb Eve (MITM / Replay)
    2. Alice (OknoKlienta)  — klient po lewej
    3. Bob   (OknoKlienta)  — klient po prawej

Uzycie:
    python -m secure_messenger.main
    python -m secure_messenger.main --port 8888

Demo krok po kroku:
    1. Okno Serwera pojawia sie pierwsze — widac "Nasluchuję..."
    2. W oknie Alice kliknij "Polacz"
    3. W oknie Bob kliknij "Polacz", potem "Wymien klucze RSA"
    4. Oba okna przejda w SECURE MODE — mozna chatowac
    5. MITM demo: zaznacz checkbox w Serwerze PRZED krokiem 3
    6. Replay demo: zaznacz checkbox, wyslij wiadomosc, kliknij "Wyslij Replay"
"""

import sys
import argparse

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont, QScreen
from PyQt6.QtCore import QRect


def _rozmies_okna(okna: list, ekran: QScreen) -> None:
    """Ustawia okna obok siebie na srodku ekranu."""
    geo: QRect = ekran.availableGeometry()
    laczona_szerokosc = sum(o.width() for o in okna) + 20 * (len(okna) - 1)

    start_x = max(0, (geo.width() - laczona_szerokosc) // 2)
    y = max(50, (geo.height() - max(o.height() for o in okna)) // 2)

    x = start_x
    for okno in okna:
        okno.move(geo.x() + x, geo.y() + y)
        x += okno.width() + 20


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Messenger E2E")
    parser.add_argument("--port", type=int, default=9999, help="Port serwera (domyslnie: 9999)")
    args = parser.parse_args()
    port = args.port

    app = QApplication(sys.argv)
    app.setApplicationName("Secure Messenger E2E")
    app.setFont(QFont("Segoe UI", 10))

    app.setStyleSheet("""
        QGroupBox {
            font-weight: bold;
            border: 1px solid #bdc3c7;
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 8px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 8px;
            padding: 0 4px;
        }
        QPushButton {
            padding: 5px 14px;
            border: 1px solid #bdc3c7;
            border-radius: 3px;
            background-color: #ecf0f1;
        }
        QPushButton:hover    { background-color: #d5dbdb; }
        QPushButton:disabled { color: #aab; }
        QTextEdit, QLineEdit {
            border: 1px solid #bdc3c7;
            border-radius: 3px;
            padding: 2px;
        }
        QTabWidget::pane { border: 1px solid #bdc3c7; }
    """)

    from secure_messenger.gui.server_window import OknoSerwera
    from secure_messenger.gui.main_window import OknoKlienta

    okno_serwera = OknoSerwera(port=port)
    okno_alice   = OknoKlienta("alice", port=port)
    okno_bob     = OknoKlienta("bob",   port=port)

    okno_serwera.show()
    okno_alice.show()
    okno_bob.show()

    # Rozmiesc okna obok siebie
    ekran = app.primaryScreen()
    _rozmies_okna([okno_serwera, okno_alice, okno_bob], ekran)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
