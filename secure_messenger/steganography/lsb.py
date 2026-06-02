"""
Steganografia LSB (Least Significant Bit) — ukrywanie danych w obrazach BMP/PPM.

Metoda LSB:
    Każdy piksel obrazu składa się z kanałów R, G, B (po 8 bitów).
    Zastępujemy najniższy bit (LSB) każdego bajtu jednym bitem ukrytej wiadomości.
    Zmiana wartości piksela o ±1 jest niewidoczna dla ludzkiego oka.

Pojemność:
    Obraz W×H pikseli → W*H*3 dostępnych bitów → W*H*3/8 bajtów danych.

Format pliku:
    Używamy czystego formatu PPM (P6 binary) — prosty, bez kompresji,
    bez konieczności instalowania dodatkowych bibliotek (brak PIL/Pillow).

Protokół ukrywania:
    [4 B długość wiadomości big-endian] + [bajty wiadomości]
    Wszystko kodowane LSB kolejnych bajtów pikseli.
"""

import os
import struct


# ---------------------------------------------------------------------------
# FORMAT PPM (Portable PixMap)
# ---------------------------------------------------------------------------

def _wczytaj_ppm(sciezka: str) -> tuple[int, int, bytes]:
    """
    Wczytuje obraz PPM binarny (format P6).

    Zwraca:
        (szerokosc, wysokosc, dane_pikseli)

    Zgłasza:
        ValueError — gdy plik nie jest prawidłowym PPM P6
        FileNotFoundError — gdy plik nie istnieje
    """
    with open(sciezka, 'rb') as f:
        # Nagłówek PPM (linie tekstowe, dane binarne po \n)
        magic = f.readline().strip()
        if magic != b'P6':
            raise ValueError(f"Plik nie jest obrazem PPM P6 (magic: {magic})")

        # Pomijamy komentarze
        linia = f.readline()
        while linia.startswith(b'#'):
            linia = f.readline()

        wymiary = linia.split()
        if len(wymiary) < 2:
            raise ValueError("Nieprawidłowy nagłówek PPM — brak wymiarów")

        szerokosc = int(wymiary[0])
        wysokosc = int(wymiary[1])

        maks = int(f.readline().strip())
        if maks != 255:
            raise ValueError(f"PPM musi mieć maxval=255, mamy: {maks}")

        dane = f.read()

    oczekiwana = szerokosc * wysokosc * 3
    if len(dane) != oczekiwana:
        raise ValueError(
            f"Nieprawidłowy rozmiar danych pikseli: {len(dane)} B "
            f"(oczekiwano {oczekiwana} B)"
        )
    return szerokosc, wysokosc, dane


def _zapisz_ppm(sciezka: str, szerokosc: int, wysokosc: int, dane: bytes) -> None:
    """Zapisuje dane pikselowe jako plik PPM P6."""
    with open(sciezka, 'wb') as f:
        f.write(f"P6\n{szerokosc} {wysokosc}\n255\n".encode())
        f.write(dane)


def stworz_ppm(sciezka: str, szerokosc: int = 100, wysokosc: int = 100) -> None:
    """
    Tworzy testowy obraz PPM wypełniony losowymi kolorami.
    Przydatne do testów gdy brak prawdziwego obrazu.

    Parametry:
        sciezka   — ścieżka do zapisania pliku
        szerokosc — szerokość w pikselach
        wysokosc  — wysokość w pikselach
    """
    dane = os.urandom(szerokosc * wysokosc * 3)
    _zapisz_ppm(sciezka, szerokosc, wysokosc, dane)


# ---------------------------------------------------------------------------
# STEGANOGRAFIA LSB — UKRYWANIE
# ---------------------------------------------------------------------------

def ukryj_wiadomosc(
    sciezka_wejsciowa: str,
    sciezka_wyjsciowa: str,
    wiadomosc: bytes
) -> int:
    """
    Ukrywa wiadomość w obrazie PPM metodą LSB.

    Algorytm:
        1. Wczytaj obraz → bajty pikseli
        2. Oblicz payload = 4 bajty długości + wiadomość
        3. Dla każdego bitu payload: ustaw LSB kolejnego bajtu piksela
        4. Zapisz zmodyfikowany obraz

    Parametry:
        sciezka_wejsciowa  — oryginalna grafika PPM
        sciezka_wyjsciowa  — grafika z ukrytą wiadomością
        wiadomosc          — dane do ukrycia (bytes)

    Zwraca:
        Liczbę zmodyfikowanych bitów

    Zgłasza:
        ValueError — gdy wiadomość jest za długa dla danego obrazu
        FileNotFoundError — gdy plik wejściowy nie istnieje
    """
    if not isinstance(wiadomosc, (bytes, bytearray)):
        raise TypeError(f"Wiadomosc musi być bytes, otrzymano: {type(wiadomosc).__name__}")

    szerokosc, wysokosc, piksele = _wczytaj_ppm(sciezka_wejsciowa)
    pojemnosc_bajtow = (len(piksele) // 8) - 4  # -4 na nagłówek długości

    if len(wiadomosc) > pojemnosc_bajtow:
        raise ValueError(
            f"Wiadomość za długa: {len(wiadomosc)} B > "
            f"pojemność obrazu {pojemnosc_bajtow} B "
            f"(obraz {szerokosc}×{wysokosc})"
        )

    # Payload = [4 B długości big-endian] + wiadomość
    payload = struct.pack('>I', len(wiadomosc)) + bytes(wiadomosc)

    # Konwertuj bajty na bity (lista 0/1, MSB first)
    bity = []
    for bajt in payload:
        for przesuniecie in range(7, -1, -1):
            bity.append((bajt >> przesuniecie) & 1)

    # Modyfikacja LSB pikseli
    piksele_zm = bytearray(piksele)
    for i, bit in enumerate(bity):
        piksele_zm[i] = (piksele_zm[i] & 0xFE) | bit  # zeruj LSB, wstaw bit

    _zapisz_ppm(sciezka_wyjsciowa, szerokosc, wysokosc, bytes(piksele_zm))
    return len(bity)


# ---------------------------------------------------------------------------
# STEGANOGRAFIA LSB — ODCZYTYWANIE
# ---------------------------------------------------------------------------

def odczytaj_wiadomosc(sciezka: str) -> bytes:
    """
    Odczytuje wiadomość ukrytą w obrazie PPM metodą LSB.

    Algorytm:
        1. Wczytaj obraz → bajty pikseli
        2. Odczytaj pierwsze 32 LSB → 4 bajty → długość wiadomości
        3. Odczytaj kolejne (długość * 8) LSB → bajty wiadomości

    Parametry:
        sciezka — obraz PPM z ukrytą wiadomością

    Zwraca:
        Odczytane bajty wiadomości

    Zgłasza:
        ValueError — gdy obraz jest za mały lub dane są uszkodzone
    """
    _, _, piksele = _wczytaj_ppm(sciezka)

    if len(piksele) < 32:
        raise ValueError("Obraz za mały — brak miejsca nawet na nagłówek długości")

    def lsb_na_bajt(poczatek: int) -> int:
        """Odczytuje 8 LSB i zwraca je jako bajt (MSB first)."""
        wartość = 0
        for i in range(8):
            wartość = (wartość << 1) | (piksele[poczatek + i] & 1)
        return wartość

    # Odczytaj 4 bajty długości
    dlugosc = 0
    for i in range(4):
        dlugosc = (dlugosc << 8) | lsb_na_bajt(i * 8)

    if dlugosc < 0 or dlugosc * 8 + 32 > len(piksele):
        raise ValueError(
            f"Nieprawidłowa długość wiadomości: {dlugosc} B "
            f"(pojemność obrazu: {(len(piksele) - 32) // 8} B)"
        )

    # Odczytaj bajty wiadomości
    wynik = bytearray()
    for i in range(dlugosc):
        bajt = lsb_na_bajt(32 + i * 8)
        wynik.append(bajt)

    return bytes(wynik)


# ---------------------------------------------------------------------------
# POJEMNOŚĆ OBRAZU
# ---------------------------------------------------------------------------

def oblicz_pojemnosc(sciezka: str) -> dict:
    """
    Oblicza pojemność steganograficzną obrazu PPM.

    Zwraca słownik z informacjami o pojemności:
        {
            'szerokosc': int,
            'wysokosc': int,
            'piksele': int,
            'pojemnosc_bitow': int,
            'pojemnosc_bajtow': int,  # po odjęciu 4 B nagłówka
            'pojemnosc_opis': str,
        }
    """
    szerokosc, wysokosc, piksele = _wczytaj_ppm(sciezka)
    pojemnosc_b = len(piksele) // 8 - 4
    return {
        'szerokosc': szerokosc,
        'wysokosc': wysokosc,
        'piksele': szerokosc * wysokosc,
        'pojemnosc_bitow': len(piksele),
        'pojemnosc_bajtow': pojemnosc_b,
        'pojemnosc_opis': _formatuj_rozmiar(pojemnosc_b),
    }


def _formatuj_rozmiar(bajty: int) -> str:
    if bajty < 1024:
        return f"{bajty} B"
    if bajty < 1024 * 1024:
        return f"{bajty / 1024:.1f} KB"
    return f"{bajty / (1024 * 1024):.1f} MB"
