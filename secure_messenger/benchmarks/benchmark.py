"""
Moduł benchmarków kryptograficznych.

Mierzy i porównuje wydajność:
    1. Generowanie kluczy RSA (512 / 1024 / 2048 bitów)
    2. Szyfrowanie/deszyfrowanie RSA
    3. AES-256-CBC (różne rozmiary danych)
    4. HMAC-SHA256 (różne rozmiary danych)
    5. Kompletny cykl: zbuduj_pakiet + rozpakuj_pakiet

Wyniki zwracane jako lista WynikBenchmarku — gotowe do wyświetlenia w GUI.
"""

import os
import time
from dataclasses import dataclass, field
from typing import Callable

from secure_messenger.crypto.rsa import (
    generuj_klucze_rsa, szyfruj_rsa, deszyfruj_rsa, deszyfruj_rsa_crt,
    podpisz_rsa, weryfikuj_podpis_rsa,
)
from secure_messenger.crypto.aes_cbc import szyfruj_aes_cbc, deszyfruj_aes_cbc, zbuduj_pakiet, rozpakuj_pakiet
from secure_messenger.crypto.hmac_sha256 import oblicz_hmac


# ---------------------------------------------------------------------------
# STRUKTURY DANYCH
# ---------------------------------------------------------------------------

@dataclass
class WynikBenchmarku:
    """Wynik pojedynczego pomiaru — jeden wiersz tabeli w GUI."""
    operacja: str          # opis operacji, np. "RSA-1024 keygen"
    sredni_czas_ms: float  # średni czas w milisekundach
    odch_std_ms: float     # odchylenie standardowe (ms)
    min_ms: float          # najszybszy pomiar
    max_ms: float          # najwolniejszy pomiar
    liczba_powtorzen: int  # ile razy zmierzono
    przepustowosc: str     # np. "2.3 MB/s" lub "3.4 op/s" (opcjonalne)

    def jako_wiersz(self) -> list[str]:
        """Formatuje wynik jako wiersz tabeli do wyświetlenia w GUI."""
        return [
            self.operacja,
            f"{self.sredni_czas_ms:.2f} ms",
            f"{self.odch_std_ms:.2f} ms",
            f"{self.min_ms:.2f} ms",
            f"{self.max_ms:.2f} ms",
            str(self.liczba_powtorzen),
            self.przepustowosc,
        ]

    @staticmethod
    def naglowki() -> list[str]:
        """Nagłówki tabeli wyników."""
        return ["Operacja", "Śr. czas", "Odch. std", "Min", "Max", "Próby", "Przepustowość"]


@dataclass
class RaportBenchmarku:
    """Zbiór wyników benchmarków z metadanymi."""
    wyniki: list[WynikBenchmarku] = field(default_factory=list)
    czas_calkowity_s: float = 0.0

    def dodaj(self, wynik: WynikBenchmarku) -> None:
        self.wyniki.append(wynik)

    def jako_tabela(self) -> list[list[str]]:
        """Zwraca listę wierszy tabeli (gotowe do QTableWidget)."""
        return [w.jako_wiersz() for w in self.wyniki]


# ---------------------------------------------------------------------------
# NARZĘDZIE POMIARU
# ---------------------------------------------------------------------------

def _zmierz(
    funkcja: Callable,
    powtorzenia: int,
) -> tuple[float, float, float, float]:
    """Mierzy czas wykonania funkcji. Zwraca (srednia_ms, odch_std_ms, min_ms, max_ms)."""
    funkcja()

    czasy: list[float] = []
    for _ in range(powtorzenia):
        t0 = time.perf_counter()
        funkcja()
        t1 = time.perf_counter()
        czasy.append((t1 - t0) * 1000.0)  # ms

    srednia = sum(czasy) / len(czasy)
    wariancja = sum((c - srednia) ** 2 for c in czasy) / len(czasy)
    odch_std = wariancja ** 0.5

    return srednia, odch_std, min(czasy), max(czasy)


def _przepustowosc_mb(sredni_czas_ms: float, rozmiar_b: int) -> str:
    """Oblicza przepustowość w MB/s."""
    if sredni_czas_ms <= 0:
        return "—"
    mb_na_s = (rozmiar_b / 1024 / 1024) / (sredni_czas_ms / 1000)
    return f"{mb_na_s:.1f} MB/s"


def _przepustowosc_ops(sredni_czas_ms: float) -> str:
    """Oblicza liczbę operacji na sekundę."""
    if sredni_czas_ms <= 0:
        return "—"
    ops = 1000.0 / sredni_czas_ms
    return f"{ops:.1f} op/s"


# ---------------------------------------------------------------------------
# BENCHMARKI RSA
# ---------------------------------------------------------------------------

def benchmark_rsa_keygen(
    rozmiary_bitow: list[int] = None,
    powtorzenia: int = 3
) -> list[WynikBenchmarku]:
    """
    Benchmarkuje generowanie kluczy RSA dla różnych rozmiarów.

    Parametry:
        rozmiary_bitow — lista rozmiarów do przetestowania (domyślnie [512,1024,2048])
        powtorzenia    — ile razy generować klucz dla każdego rozmiaru

    Zwraca:
        Lista wyników dla każdego rozmiaru klucza
    """
    if rozmiary_bitow is None:
        rozmiary_bitow = [512, 1024, 2048]

    wyniki = []
    for bity in rozmiary_bitow:
        s, o, mn, mx = _zmierz(
            lambda b=bity: generuj_klucze_rsa(b),
            powtorzenia=powtorzenia,
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} generowanie kluczy",
            sredni_czas_ms=s,
            odch_std_ms=o,
            min_ms=mn,
            max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s),
        ))
    return wyniki


def benchmark_rsa_enc_dec(
    rozmiary_bitow: list[int] = None,
    powtorzenia: int = 10
) -> list[WynikBenchmarku]:
    """
    Benchmarkuje szyfrowanie i deszyfrowanie RSA.

    Dane wejściowe: 32 bajty (klucz AES — typowy przypadek użycia).
    """
    if rozmiary_bitow is None:
        rozmiary_bitow = [512, 1024, 2048]

    wyniki = []
    dane = os.urandom(32)  # rozmiar klucza AES

    for bity in rozmiary_bitow:
        klucze = generuj_klucze_rsa(bity)
        pub, priv = klucze.klucz_publiczny, klucze.klucz_prywatny

        # Szyfrowanie
        s, o, mn, mx = _zmierz(
            lambda p=pub, d=dane: szyfruj_rsa(d, p),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} szyfrowanie (32 B)",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s),
        ))

        # Deszyfrowanie
        szyfrogram = szyfruj_rsa(dane, pub)
        s, o, mn, mx = _zmierz(
            lambda pr=priv, c=szyfrogram: deszyfruj_rsa(c, pr),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} deszyfrowanie (32 B)",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s),
        ))

    return wyniki


# ---------------------------------------------------------------------------
# BENCHMARKI AES-CBC
# ---------------------------------------------------------------------------

def benchmark_aes_cbc(
    rozmiary_b: list[int] = None,
    powtorzenia: int = 100
) -> list[WynikBenchmarku]:
    """
    Benchmarkuje szyfrowanie AES-256-CBC dla różnych rozmiarów danych.

    Parametry:
        rozmiary_b  — rozmiary wiadomości w bajtach
        powtorzenia — liczba pomiarów dla każdego rozmiaru
    """
    if rozmiary_b is None:
        rozmiary_b = [64, 1024, 10 * 1024, 100 * 1024]

    klucz = os.urandom(32)
    wyniki = []

    for rozmiar in rozmiary_b:
        dane = os.urandom(rozmiar)
        opis_rozmiaru = _formatuj_rozmiar(rozmiar)

        # Szyfrowanie
        s, o, mn, mx = _zmierz(
            lambda k=klucz, d=dane: szyfruj_aes_cbc(d, k),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"AES-256-CBC szyfrowanie ({opis_rozmiaru})",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_mb(s, rozmiar),
        ))

        # Deszyfrowanie
        iv, c = szyfruj_aes_cbc(dane, klucz)
        s, o, mn, mx = _zmierz(
            lambda k=klucz, iv_=iv, c_=c: deszyfruj_aes_cbc(c_, k, iv_),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"AES-256-CBC deszyfrowanie ({opis_rozmiaru})",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_mb(s, rozmiar),
        ))

    return wyniki


# ---------------------------------------------------------------------------
# BENCHMARKI HMAC-SHA256
# ---------------------------------------------------------------------------

def benchmark_hmac(
    rozmiary_b: list[int] = None,
    powtorzenia: int = 100
) -> list[WynikBenchmarku]:
    """
    Benchmarkuje obliczanie HMAC-SHA256 dla różnych rozmiarów danych.
    """
    if rozmiary_b is None:
        rozmiary_b = [64, 1024, 10 * 1024, 100 * 1024]

    klucz = os.urandom(32)
    wyniki = []

    for rozmiar in rozmiary_b:
        dane = os.urandom(rozmiar)
        opis = _formatuj_rozmiar(rozmiar)

        s, o, mn, mx = _zmierz(
            lambda k=klucz, d=dane: oblicz_hmac(k, d),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"HMAC-SHA256 ({opis})",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_mb(s, rozmiar),
        ))

    return wyniki


# ---------------------------------------------------------------------------
# BENCHMARK CRT vs NAIWNE RSA
# ---------------------------------------------------------------------------

def benchmark_rsa_crt(
    rozmiary_bitow: list[int] = None,
    powtorzenia: int = 10
) -> list[WynikBenchmarku]:
    """
    Porównuje czas deszyfrowania RSA: naiwne (C^d mod n) vs CRT.

    CRT (Chinese Remainder Theorem) wykonuje dwa mniejsze potęgowania
    modularne (mod p i mod q zamiast mod n), co daje ~4× przyspieszenie.

    Parametry:
        rozmiary_bitow — rozmiary kluczy do przetestowania
        powtorzenia    — liczba pomiarów dla każdego wariantu

    Zwraca:
        Lista wyników (pary naiwne/CRT dla każdego rozmiaru)
    """
    if rozmiary_bitow is None:
        rozmiary_bitow = [1024, 2048]

    wyniki = []
    dane = os.urandom(32)

    for bity in rozmiary_bitow:
        klucze = generuj_klucze_rsa(bity)
        pub = klucze.klucz_publiczny
        priv = klucze.klucz_prywatny
        szyfrogram = szyfruj_rsa(dane, pub)

        # Naiwne: C^d mod n
        s_naiwne, o, mn, mx = _zmierz(
            lambda pr=priv, c=szyfrogram: deszyfruj_rsa(c, pr),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} decrypt naiwne (C^d mod n)",
            sredni_czas_ms=s_naiwne, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s_naiwne),
        ))

        # CRT: dwa potęgowania mod p/q
        s_crt, o, mn, mx = _zmierz(
            lambda kl=klucze, c=szyfrogram: deszyfruj_rsa_crt(c, kl),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} decrypt CRT (mod p + mod q)",
            sredni_czas_ms=s_crt, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s_crt),
        ))

        # Informacja o przyspieszeniu (zapisana jako pseudo-wiersz)
        if s_crt > 0:
            przyspieszenie = s_naiwne / s_crt
            wyniki.append(WynikBenchmarku(
                operacja=f"  -> RSA-{bity} przyspieszenie CRT",
                sredni_czas_ms=0,
                odch_std_ms=0,
                min_ms=0,
                max_ms=0,
                liczba_powtorzen=0,
                przepustowosc=f"{przyspieszenie:.1f}x szybciej",
            ))

    return wyniki


# ---------------------------------------------------------------------------
# BENCHMARKI PODPISU CYFROWEGO RSA (używane w PKI)
# ---------------------------------------------------------------------------

def benchmark_rsa_podpis(
    rozmiary_bitow: list[int] = None,
    powtorzenia: int = 10
) -> list[WynikBenchmarku]:
    """
    Benchmarkuje podpisywanie i weryfikację RSA — operacje wykonywane przez PKI.

    Podpisanie używa klucza prywatnego (C^d mod n — wolne jak deszyfrowanie).
    Weryfikacja używa klucza publicznego (C^e mod n — szybka, e=65537 jest małe).
    Asymetria jest celowa: CA podpisuje raz, klienci weryfikują wielokrotnie i szybko.
    """
    if rozmiary_bitow is None:
        rozmiary_bitow = [1024, 2048]

    wiadomosc = b"RSA_PUB:klucz_publiczny_boba"  # typowy payload certyfikowany przez CA
    wyniki = []

    for bity in rozmiary_bitow:
        klucze = generuj_klucze_rsa(bity)
        pub  = klucze.klucz_publiczny
        priv = klucze.klucz_prywatny

        # Podpisywanie (klucz prywatny CA — SHA-256 + C^d mod n)
        s, o, mn, mx = _zmierz(
            lambda pr=priv, m=wiadomosc: podpisz_rsa(m, pr),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} podpis CA  (SHA-256 + C^d mod n)",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s),
        ))

        # Weryfikacja (klucz publiczny — SHA-256 + C^e mod n, e=65537)
        podpis = podpisz_rsa(wiadomosc, priv)
        s, o, mn, mx = _zmierz(
            lambda p=pub, m=wiadomosc, sig=podpis: weryfikuj_podpis_rsa(m, sig, p),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"RSA-{bity} weryfik.  (SHA-256 + C^e mod n, e=65537)",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_ops(s),
        ))

        # Asymetria: ile razy weryfikacja jest szybsza od podpisu
        s_podpis = wyniki[-2].sredni_czas_ms
        s_weryfik = wyniki[-1].sredni_czas_ms
        if s_weryfik > 0:
            ratio = s_podpis / s_weryfik
            wyniki.append(WynikBenchmarku(
                operacja=f"  -> RSA-{bity} asymetria podpis/weryfikacja",
                sredni_czas_ms=0, odch_std_ms=0, min_ms=0, max_ms=0,
                liczba_powtorzen=0,
                przepustowosc=f"{ratio:.0f}× szybsza weryfikacja",
            ))

    return wyniki


# ---------------------------------------------------------------------------
# BENCHMARK KOMPLETNEGO PAKIETU
# ---------------------------------------------------------------------------

def benchmark_pakiet(
    rozmiary_b: list[int] = None,
    powtorzenia: int = 50
) -> list[WynikBenchmarku]:
    """
    Benchmarkuje kompletny cykl: zbuduj_pakiet + rozpakuj_pakiet.
    Odzwierciedla rzeczywisty koszt obsługi jednej wiadomości.
    """
    if rozmiary_b is None:
        rozmiary_b = [64, 512, 4096]

    k_aes  = os.urandom(32)
    k_hmac = os.urandom(32)
    wyniki = []

    for rozmiar in rozmiary_b:
        dane = os.urandom(rozmiar)
        opis = _formatuj_rozmiar(rozmiar)

        # Budowanie pakietu
        s, o, mn, mx = _zmierz(
            lambda ka=k_aes, kh=k_hmac, d=dane: zbuduj_pakiet(d, ka, kh, 1, 1),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"Zbuduj pakiet ({opis})",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_mb(s, rozmiar),
        ))

        # Rozpakowywanie pakietu
        pakiet = zbuduj_pakiet(dane, k_aes, k_hmac, 1, 1)
        s, o, mn, mx = _zmierz(
            lambda p=pakiet, ka=k_aes, kh=k_hmac: rozpakuj_pakiet(p, ka, kh),
            powtorzenia=powtorzenia
        )
        wyniki.append(WynikBenchmarku(
            operacja=f"Rozpakuj pakiet ({opis})",
            sredni_czas_ms=s, odch_std_ms=o, min_ms=mn, max_ms=mx,
            liczba_powtorzen=powtorzenia,
            przepustowosc=_przepustowosc_mb(s, rozmiar),
        ))

    return wyniki


# ---------------------------------------------------------------------------
# PEŁNY RAPORT
# ---------------------------------------------------------------------------

def uruchom_wszystkie_benchmarki(
    bity_rsa: list[int] = None,
    on_postep: Callable[[str], None] = None
) -> RaportBenchmarku:
    """
    Uruchamia wszystkie benchmarki i zwraca kompletny raport.

    Parametry:
        bity_rsa   — rozmiary kluczy RSA do przetestowania
        on_postep  — callback(opis) wywoływany przed każdą grupą testów

    Zwraca:
        RaportBenchmarku z wszystkimi wynikami
    """
    if bity_rsa is None:
        bity_rsa = [1024, 2048]

    raport = RaportBenchmarku()
    t_start = time.perf_counter()

    def postep(msg: str) -> None:
        if on_postep:
            on_postep(msg)

    postep("Benchmarkuję generowanie kluczy RSA...")
    for w in benchmark_rsa_keygen(bity_rsa, powtorzenia=3):
        raport.dodaj(w)

    postep("Benchmarkuję szyfrowanie/deszyfrowanie RSA...")
    for w in benchmark_rsa_enc_dec(bity_rsa, powtorzenia=10):
        raport.dodaj(w)

    postep("Benchmarkuję CRT vs naiwne deszyfrowanie RSA...")
    for w in benchmark_rsa_crt(bity_rsa, powtorzenia=10):
        raport.dodaj(w)

    postep("Benchmarkuję podpis cyfrowy RSA (PKI — CA sign/verify)...")
    for w in benchmark_rsa_podpis(bity_rsa, powtorzenia=10):
        raport.dodaj(w)

    postep("Benchmarkuję AES-256-CBC...")
    for w in benchmark_aes_cbc(powtorzenia=200):
        raport.dodaj(w)

    postep("Benchmarkuję HMAC-SHA256...")
    for w in benchmark_hmac(powtorzenia=200):
        raport.dodaj(w)

    postep("Benchmarkuję kompletny cykl pakietu...")
    for w in benchmark_pakiet(powtorzenia=100):
        raport.dodaj(w)

    raport.czas_calkowity_s = time.perf_counter() - t_start
    postep(f"Gotowe! Czas całkowity: {raport.czas_calkowity_s:.1f}s")
    return raport


# ---------------------------------------------------------------------------
# NARZĘDZIA
# ---------------------------------------------------------------------------

def interpretuj_raport(raport: RaportBenchmarku) -> str:
    """Zwraca tekstowe podsumowanie raportu benchmarków gotowe do wydruku."""
    linie = [
        f"Wyniki benchmarków ({len(raport.wyniki)} pomiarów,"
        f" {raport.czas_calkowity_s:.1f}s łącznie):",
        "",
    ]
    for w in raport.wyniki:
        wiersz = w.jako_wiersz()
        linie.append(f"  {wiersz[0]:<55} {wiersz[1]:>10}  {wiersz[6]}")
    return "\n".join(linie)


def generuj_interpretacje(raport: RaportBenchmarku) -> str:
    """Generuje krotki komentarz do wynikow benchmarkow."""
    idx: dict[str, WynikBenchmarku] = {w.operacja.strip(): w for w in raport.wyniki}

    def ms(nazwa: str) -> float | None:
        w = idx.get(nazwa)
        return w.sredni_czas_ms if w and w.sredni_czas_ms > 0 else None

    linie = []

    # keygen
    keygen_w = sorted(
        [w for w in raport.wyniki if "generowanie kluczy" in w.operacja and w.sredni_czas_ms > 0],
        key=lambda w: w.sredni_czas_ms
    )
    if len(keygen_w) >= 2:
        kw_m, kw_d = keygen_w[0], keygen_w[-1]
        ratio = kw_d.sredni_czas_ms / kw_m.sredni_czas_ms
        n_m = kw_m.operacja.replace("generowanie kluczy", "").strip()
        n_d = kw_d.operacja.replace("generowanie kluczy", "").strip()
        linie.append(
            f"Generowanie kluczy: {n_m} ~{kw_m.sredni_czas_ms:.0f} ms, "
            f"{n_d} ~{kw_d.sredni_czas_ms:.0f} ms (ok. {ratio:.1f}x dluzej). "
            f"Jednorazowe na sesje, wiec koszt akceptowalny."
        )
        linie.append("")

    # RSA enc/dec asymetria
    for bity in [2048, 1024]:
        enc = ms(f"RSA-{bity} szyfrowanie (32 B)")
        dec = ms(f"RSA-{bity} deszyfrowanie (32 B)")
        if enc and dec:
            ratio = dec / enc
            linie.append(
                f"RSA-{bity}: szyfrowanie (klucz pub.) {enc:.3f} ms, "
                f"deszyfrowanie (klucz pryw.) {dec:.2f} ms -- roznica {ratio:.0f}x. "
                f"Wynika z wielkosci eksponentu: e=65537 jest male, d jest duze."
            )
            linie.append("")
            break

    # hybryda RSA+AES
    for bity in [2048, 1024]:
        rsa = ms(f"RSA-{bity} deszyfrowanie (32 B)")
        aes = ms("AES-256-CBC szyfrowanie (1 KB)")
        if rsa and aes:
            ratio = rsa / aes
            linie.append(
                f"Porownanie RSA vs AES: deszyfrowanie RSA-{bity} to {rsa:.2f} ms, "
                f"szyfrowanie AES-256 1 KB to {aes:.3f} ms -- RSA jest ok. {ratio:.0f}x wolniejsze. "
                f"To uzasadnia szyfrowanie hybrydowe: RSA tylko do wymiany klucza sesji, "
                f"AES do wszystkich wiadomosci."
            )
            linie.append("")
            break

    # CRT
    for bity in [2048, 1024]:
        naive = ms(f"RSA-{bity} decrypt naiwne (C^d mod n)")
        crt = ms(f"RSA-{bity} decrypt CRT (mod p + mod q)")
        if naive and crt:
            ratio = naive / crt
            linie.append(
                f"CRT vs naiwne (RSA-{bity}): {naive:.2f} ms -> {crt:.2f} ms, "
                f"przyspieszenie {ratio:.1f}x. CRT rozklada C^d mod n na dwa mniejsze "
                f"potegowania mod p i mod q -- matematycznie rownowazne, szybciej obliczeniowo."
            )
            linie.append("")
            break

    # podpis PKI
    for bity in [2048, 1024]:
        sign = ms(f"RSA-{bity} podpis CA  (SHA-256 + C^d mod n)")
        verify = ms(f"RSA-{bity} weryfik.  (SHA-256 + C^e mod n, e=65537)")
        if sign and verify:
            ratio = sign / verify
            linie.append(
                f"Podpis cyfrowy RSA-{bity}: podpisanie {sign:.2f} ms, "
                f"weryfikacja {verify:.3f} ms ({ratio:.0f}x szybsza). "
                f"e=65537 ma tylko 17 jedynek binarnych -- square-and-multiply robi tu 17 mnozen. "
                f"CA podpisuje certyfikat raz, klienci weryfikuja wielokrotnie i szybko."
            )
            linie.append("")
            break

    # HMAC
    hmac = ms("HMAC-SHA256 (100 KB)")
    aes_big = ms("AES-256-CBC szyfrowanie (100 KB)")
    if hmac and aes_big:
        linie.append(
            f"HMAC-SHA256 vs AES-256 na 100 KB: {hmac:.2f} ms vs {aes_big:.2f} ms -- "
            f"weryfikacja integralnosci nie dodaje istotnego nakladu obliczeniowego."
        )

    return "\n".join(linie)


def _formatuj_rozmiar(bajty: int) -> str:
    """Formatuje rozmiar bajtów do czytelnej postaci."""
    if bajty < 1024:
        return f"{bajty} B"
    if bajty < 1024 * 1024:
        return f"{bajty // 1024} KB"
    return f"{bajty // (1024 * 1024)} MB"
