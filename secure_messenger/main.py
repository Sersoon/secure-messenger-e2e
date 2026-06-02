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
        QMainWindow, QDialog { background: #111827; }
        QWidget               { background: #111827; color: #f9fafb; }
        QLabel                { background: transparent; color: #e5e7eb; }

        QGroupBox {
            font-weight: bold;
            color: #e5e7eb;
            border: 1px solid #374151;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 10px;
            background: #1f2937;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 6px;
            background: #1f2937;
            color: #9ca3af;
        }

        QPushButton {
            padding: 5px 14px;
            border: 1px solid #4b5563;
            border-radius: 6px;
            background: #374151;
            color: #f9fafb;
        }
        QPushButton:hover    { background: #4b5563; border-color: #6b7280; }
        QPushButton:pressed  { background: #1f2937; border-color: #374151; }
        QPushButton:disabled { background: #1f2937; color: #4b5563; border-color: #1f2937; }

        QLineEdit {
            border: 1px solid #374151;
            border-radius: 6px;
            padding: 5px 9px;
            background: #0f172a;
            color: #f9fafb;
            selection-background-color: #3b82f6;
            selection-color: #ffffff;
        }
        QLineEdit:focus     { border-color: #3b82f6; }
        QLineEdit:read-only { background: #0f172a; color: #6b7280; border-color: #1f2937; }
        QLineEdit:disabled  { background: #0f172a; color: #4b5563; border-color: #1f2937; }

        QTextEdit {
            border: 1px solid #374151;
            border-radius: 6px;
            padding: 6px 8px;
            background: #0f172a;
            color: #e5e7eb;
        }

        QTabWidget::pane {
            border: 1px solid #374151;
            border-radius: 0 8px 8px 8px;
            background: #1f2937;
            top: -1px;
        }
        QTabBar::tab {
            background: #111827;
            color: #6b7280;
            border: 1px solid #374151;
            border-bottom: none;
            padding: 8px 18px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
            min-width: 60px;
        }
        QTabBar::tab:selected        { background: #1f2937; color: #f9fafb; font-weight: bold; border-bottom: 1px solid #1f2937; }
        QTabBar::tab:hover:!selected { background: #1f2937; color: #d1d5db; }

        QComboBox {
            border: 1px solid #374151;
            border-radius: 6px;
            padding: 5px 9px;
            background: #1f2937;
            color: #f9fafb;
            min-width: 80px;
        }
        QComboBox:hover { border-color: #6b7280; }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 20px;
            border-left: 1px solid #374151;
            border-top-right-radius: 6px;
            border-bottom-right-radius: 6px;
        }
        QComboBox QAbstractItemView {
            border: 1px solid #374151;
            background: #1f2937;
            color: #f9fafb;
            selection-background-color: #374151;
            selection-color: #f9fafb;
            outline: none;
        }

        QTableWidget {
            border: 1px solid #374151;
            gridline-color: #374151;
            background: #1f2937;
            color: #e5e7eb;
            alternate-background-color: #111827;
        }
        QTableWidget::item          { padding: 5px 8px; color: #e5e7eb; }
        QTableWidget::item:selected { background: #374151; color: #f9fafb; }
        QHeaderView::section {
            background: #0f172a;
            border: none;
            border-right: 1px solid #374151;
            border-bottom: 1px solid #374151;
            padding: 7px 10px;
            font-weight: bold;
            color: #9ca3af;
        }

        QProgressBar {
            border: 1px solid #374151;
            border-radius: 4px;
            background: #0f172a;
            text-align: center;
            color: #9ca3af;
            max-height: 14px;
        }
        QProgressBar::chunk { background: #3b82f6; border-radius: 3px; }

        QScrollBar:vertical {
            border: none; background: #0f172a;
            width: 8px; border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #374151; border-radius: 4px; min-height: 24px;
        }
        QScrollBar::handle:vertical:hover { background: #4b5563; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

        QScrollBar:horizontal {
            border: none; background: #0f172a;
            height: 8px; border-radius: 4px;
        }
        QScrollBar::handle:horizontal {
            background: #374151; border-radius: 4px; min-width: 24px;
        }
        QScrollBar::handle:horizontal:hover { background: #4b5563; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

        QCheckBox { spacing: 6px; color: #e5e7eb; }
        QCheckBox::indicator {
            width: 15px; height: 15px;
            border: 1px solid #4b5563;
            border-radius: 3px; background: #1f2937;
        }
        QCheckBox::indicator:checked  { background: #3b82f6; border-color: #3b82f6; }
        QCheckBox::indicator:hover    { border-color: #6b7280; }
        QCheckBox::indicator:disabled { background: #111827; border-color: #374151; }
        QCheckBox:disabled            { color: #4b5563; }

        QSplitter::handle            { background: #374151; }
        QSplitter::handle:horizontal { width: 3px; }
        QSplitter::handle:vertical   { height: 3px; }
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
