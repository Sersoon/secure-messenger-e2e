# Secure Messenger E2E — Dokumentacja projektu

> **Przeznaczenie tego pliku:** Szczegółowy opis projektu semestralnego z przedmiotu Kryptografia / Bezpieczeństwo Systemów, przeznaczony do wygenerowania sprawozdania. Zawiera opis wszystkich modułów, algorytmów, protokołów, testów i funkcji demonstracyjnych.

---

## 1. Informacje ogólne

**Nazwa projektu:** Secure Messenger E2E (End-to-End Encrypted Messenger)

**Język programowania:** Python 3.12+

**Cel projektu:** Implementacja edukacyjnego komunikatora z szyfrowaniem end-to-end, zrealizowanego od podstaw. Projekt demonstruje praktyczne zastosowanie algorytmów kryptograficznych (RSA, AES-CBC, HMAC-SHA256), protokołu wymiany kluczy, ochrony przed atakami (MITM, Replay Attack) oraz steganografii LSB.

**Charakter implementacji:** Wszystkie algorytmy kryptograficzne (RSA, HMAC-SHA256, padding PKCS7, steganografia LSB) są zaimplementowane ręcznie od zera, bez użycia gotowych bibliotek kryptograficznych. Jedynym wyjątkiem jest samo szyfrowanie symetryczne AES, które korzysta z biblioteki `cryptography` (dozwolone przez wymagania projektu).

---

## 2. Struktura katalogów

```
SecureMessenger E2E/
└── secure_messenger/
    ├── main.py                  # Punkt wejścia — uruchamia 3 okna Qt jednocześnie
    ├── crypto/
    │   ├── rsa.py               # Pełna ręczna implementacja RSA (keygen, enc, dec)
    │   ├── aes_cbc.py           # AES-256-CBC + padding PKCS7 + format pakietu sieciowego
    │   └── hmac_sha256.py       # Ręczna implementacja HMAC-SHA256 (RFC 2104)
    ├── network/
    │   ├── client.py            # Klient TCP (Alice lub Bob) — wymiana kluczy + send/recv
    │   └── server.py            # Serwer-router TCP — przekazuje pakiety + tryb Eve (MITM/Replay)
    ├── gui/
    │   ├── main_window.py       # Okno klienta (Alice/Bob) — chat, krypto-szczegóły, steganografia
    │   └── server_window.py     # Panel serwera / Eve — logi, checkboxy MITM/Replay
    ├── security/
    │   └── attacks.py           # Symulacje ataków: MITM i Replay Attack (cel edukacyjny)
    ├── benchmarks/
    │   └── benchmark.py         # Pomiary wydajności: RSA, AES, HMAC, cykl pakietu
    ├── steganography/
    │   └── lsb.py               # Steganografia LSB w plikach PPM (ukrywanie danych w obrazach)
    └── tests/
        └── test_crypto.py       # Testy jednostkowe i integracyjne (pytest)
```

---

## 3. Stos technologiczny

| Komponent | Technologia |
|---|---|
| Język | Python 3.12+ |
| GUI | PyQt6 |
| Sieć | TCP (socket stdlib) |
| Szyfrowanie symetryczne (rdzeń) | `cryptography` (AES-CBC) |
| RSA, HMAC, padding, steganografia | Implementacja własna (from scratch) |
| Testy | pytest |
| Styl kodu | PEP 8, type hints |

---

## 4. Moduły kryptograficzne

### 4.1 Moduł RSA — `crypto/rsa.py`

Pełna, ręczna implementacja algorytmu RSA obejmująca:

#### 4.1.1 Szybkie potęgowanie modularne (`mod_pow`)

Oblicza `(podstawa^wykładnik) mod modulus` metodą **square-and-multiply** (zwaną też binary exponentiation lub repeated squaring).

**Złożoność:** O(log(wykładnik)) mnożeń — wielokrotnie szybsza od naiwnej pętli.

**Algorytm:**
1. Inicjalizacja: wynik = 1
2. Iteracja po bitach wykładnika (od najniższego):
   - Jeśli bit = 1: wynik = (wynik × podstawa) mod modulus
   - podstawa = (podstawa²) mod modulus

**Znaczenie dla RSA:** Wykładniki `e` i `d` mają setki/tysiące bitów. Bez tej metody szyfrowanie byłoby niepraktycznie wolne.

#### 4.1.2 Rozszerzony algorytm Euklidesa (`rozszerzony_euklides`)

Rekurencyjna implementacja algorytmu XGD. Znajduje trójkę `(g, x, y)` taką że: `a·x + b·y = g = NWD(a, b)`.

**Zastosowanie:** Obliczenie odwrotności modularnej potrzebnej do wyznaczenia klucza prywatnego d.

#### 4.1.3 Odwrotność modularna (`odwrotnosc_modularna`)

Oblicza `a⁻¹ mod m` przy użyciu rozszerzonego algorytmu Euklidesa. Wymaga `NWD(a, m) = 1`. Rzuca `ValueError` gdy odwrotność nie istnieje.

**Zastosowanie:** `d = e⁻¹ mod φ(n)` — obliczenie wykładnika prywatnego RSA.

#### 4.1.4 Test pierwszości Miller-Rabin (`miller_rabin`)

Probabilistyczny test pierwszości. Parametr `k=20` rund gwarantuje `P(błąd) < 4⁻²⁰ ≈ 10⁻¹²`.

**Algorytm:**
1. Zapisz `n-1 = 2^r · d` (wyodrębnij czynniki 2)
2. Dla k losowych baz `a ∈ [2, n-2]`:
   - Oblicz `x = a^d mod n`
   - Jeśli `x == 1` lub `x == n-1` → prawdopodobnie pierwsza
   - Iteruj: `x = x² mod n` — jeśli `x == n-1` → następna runda
   - Jeśli żaden warunek — liczba złożona

**Losowość:** Używa `random.randrange` (Python stdlib). Kandydaci na liczby pierwsze generowani są przez `os.urandom` (kryptograficznie bezpieczna losowość).

**Test obejmuje:** liczby Carmichaela (np. 561 = 3×11×17), które mylą prosty test Fermata, ale Miller-Rabin je wykrywa.

#### 4.1.5 Generowanie liczb pierwszych (`generuj_liczbe_pierwsza`)

Metoda: losuj kandydatów (nieparzystych, z ustawionym najwyższym bitem) → testuj Miller-Rabin → powtarzaj do sukcesu.

**Oczekiwana liczba prób:** ~`bity × ln(2) ≈ 0.7 × bity` (twierdzenie o liczbach pierwszych).

Funkcja pomocnicza `_losowy_nieparzysty(bity)` generuje kandydatów z `os.urandom`, ustawiając najwyższy bit (właściwa długość) i najniższy bit (nieparzysta).

#### 4.1.6 Generowanie kluczy RSA (`generuj_klucze_rsa`)

**Algorytm:**
1. Generuj dwie różne liczby pierwsze `p`, `q` o długości `bity/2`
2. Oblicz `n = p × q` (moduł RSA)
3. Oblicz `φ(n) = (p-1)(q-1)` (funkcja Eulera)
4. Wykładnik publiczny: `e = 65537 = 2¹⁶ + 1` (liczba Fermata F4, tylko 2 bity ustawione — szybkie potęgowanie)
5. Oblicz `d = e⁻¹ mod φ(n)` (wykładnik prywatny)

**Obsługiwane rozmiary:** 512, 1024, 2048 bitów (minimum 512).

**Klasa `KluczeRSA`:** kontener na `n, e, d, bity`, z właściwościami `klucz_publiczny → (n, e)` i `klucz_prywatny → (n, d)`.

#### 4.1.7 Szyfrowanie i deszyfrowanie RSA

- **Szyfrowanie:** `C = M^e mod n` (klucz publiczny)
- **Deszyfrowanie:** `M = C^d mod n` (klucz prywatny)

Konwersja bytes ↔ int: big-endian (`int.from_bytes` / `.to_bytes`).

**Ograniczenie:** Wiadomość musi być krótsza niż moduł n. W projekcie szyfrowane są wyłącznie 32-bajtowe klucze AES i HMAC, więc nawet RSA-1024 (128 B moduł) jest wystarczający.

**Uwaga techniczna:** To textbook RSA (bez OAEP), dopuszczalny w celach edukacyjnych. `deszyfruj_rsa` stosuje `lstrip(b'\x00')` i `rjust(32, b'\x00')` do obsługi wiodących zer przy konwersji int→bytes.

#### 4.1.8 Szyfrowanie par kluczy sesji

- `szyfruj_klucze_sesji(klucz_aes, klucz_hmac, klucz_pub)` → `(enc_aes, enc_hmac)` — używane przez Alice
- `deszyfruj_klucze_sesji(enc_aes, enc_hmac, klucz_pryw)` → `(klucz_aes, klucz_hmac)` — używane przez Boba

---

### 4.2 Moduł AES-CBC — `crypto/aes_cbc.py`

Implementuje szyfrowanie symetryczne z paddingiem i formatem pakietu sieciowego.

#### 4.2.1 Padding PKCS7 (`pkcs7_pad`, `pkcs7_unpad`)

**Standard:** RFC 5652

**Zasada PKCS7:**
- Jeśli brakuje N bajtów do pełnego bloku → dopisz N bajtów o wartości N
- Jeśli dane są już wyrównane → dopisz pełny blok (16 bajtów o wartości 16)
- Padding jest ZAWSZE obecny (jednoznaczne usunięcie)

**Przykłady:**
- `b'ABC'` (3 B) → `b'ABC' + b'\x0d' * 13`
- `b'A' * 16` (16 B) → `b'A'*16 + b'\x10' * 16`
- `b''` (0 B) → `b'\x10' * 16`

**Weryfikacja przy usuwaniu:** sprawdza zakres wartości padding (1–16) i jednorodność bajtów. Nieprawidłowy padding → `ValueError`.

#### 4.2.2 Szyfrowanie AES-256-CBC (`szyfruj_aes_cbc`, `deszyfruj_aes_cbc`)

**Stałe:**
- `ROZMIAR_BLOKU_AES = 16` bajtów (128 bitów)
- `ROZMIAR_KLUCZA_AES = 32` bajtów (256 bitów)
- `ROZMIAR_IV = 16` bajtów

**Szyfrowanie:**
1. Losowy IV = `os.urandom(16)` — unikalny dla każdej wiadomości (powtórzenie IV z tym samym kluczem łamie CBC!)
2. Padding PKCS7
3. AES-256-CBC (biblioteka `cryptography`)
4. Zwraca `(iv, szyfrogram)`

**Deszyfrowanie:** najpierw weryfikacja HMAC (nie deszyfruj przed weryfikacją — ochrona przed padding oracle attack!), potem AES-CBC, potem usunięcie paddingu.

#### 4.2.3 Format pakietu sieciowego (`zbuduj_pakiet`, `rozpakuj_pakiet`)

**Format binarny pakietu:**
```
[4 B session_id | 4 B nonce | 16 B IV | 32 B HMAC | 4 B len | N B ciphertext]
```
Łącznie minimum 60 B nagłówka + min. 16 B szyfrogramu = 76 B.

**Schemat Encrypt-then-MAC:**
1. `IV = os.urandom(16)`
2. `ciphertext = AES_CBC(plaintext, key_aes, IV)`
3. `HMAC = HMAC_SHA256(key_hmac, IV || ciphertext)` — uwierzytelniamy IV i szyfrogram razem
4. Pakiet = `session_id || nonce || IV || HMAC || len(ciphertext) || ciphertext`

**Rozpakowywanie — kolejność weryfikacji:**
1. Sprawdź minimalną długość pakietu
2. Wyodrębnij pola nagłówka
3. Zweryfikuj HMAC (PRZED deszyfrowaniem!)
4. Odszyfruj AES-CBC

**session_id:** identyfikator sesji (32-bit int), generowany losowo przez Alice.

**nonce:** licznik wiadomości (monotonicznie rosnący), ochrona przed Replay Attack.

---

### 4.3 Moduł HMAC-SHA256 — `crypto/hmac_sha256.py`

Ręczna implementacja HMAC zgodna z **RFC 2104**, bez użycia gotowej funkcji `hmac` z biblioteki standardowej.

**Używane:**
- `hashlib.sha256` — surowa funkcja skrótu
- Operacje XOR na bajtach
- **NIE używane:** `hmac`, `cryptography`, `pycryptodome`

#### 4.3.1 Stałe (RFC 2104)

- `ROZMIAR_BLOKU = 64` B (blok wewnętrzny SHA-256, 512 bitów)
- `ROZMIAR_SKROTU = 32` B (wyjście SHA-256, 256 bitów)
- `IPAD = b'\x36' * 64` (inner padding)
- `OPAD = b'\x5C' * 64` (outer padding)

#### 4.3.2 Algorytm HMAC (`oblicz_hmac`)

```
HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
```

Gdzie:
- `H = SHA-256`
- `K' = przygotuj_klucz(K)` — dopasowanie do 64 B:
  - `len(K) > 64` → `K' = SHA256(K)`
  - `len(K) < 64` → uzupełnij zerami z prawej
  - `len(K) == 64` → bez zmian

**Kroki:**
1. `K' = przygotuj_klucz(K)`
2. `ipad_key = K' XOR IPAD`
3. `opad_key = K' XOR OPAD`
4. `inner = SHA256(ipad_key || m)`
5. `HMAC = SHA256(opad_key || inner)`

#### 4.3.3 Weryfikacja odporna na timing attack (`weryfikuj_hmac`)

**Problem naiwnego porównania `a == b`:** Python przerywa przy pierwszej różnicy → atakujący może mierzyć czas i odgadywać bajt po bajcie.

**Rozwiązanie — porównanie w stałym czasie:**
```python
roznica = 0
for a, b in zip(obliczony, oczekiwany):
    roznica |= a ^ b
return roznica == 0
```
Wszystkie bajty są zawsze przetwarzane, niezależnie od wyniku.

#### 4.3.4 HMAC pakietu sieciowego

- `oblicz_hmac_pakietu(key, iv, ciphertext)` → uwierzytelnia `IV || ciphertext` razem (nie osobno)
- `weryfikuj_hmac_pakietu(key, iv, ciphertext, tag)` → używane przez `rozpakuj_pakiet`

---

## 5. Warstwa sieciowa

### 5.1 Klient — `network/client.py`

**Klasa `KlientMessenger`** — klient Alice lub Boba.

#### 5.1.1 Architektura wątkowa

- **Wątek główny (GUI):** wywołuje `polacz()`, `wyslij()`, `rozlacz()`
- **Wątek odbiorczy (daemon):** nasłuchuje pakietów, wywołuje callbacki przy nowej wiadomości

Callbacki: `on_wiadomosc(nadawca, tresc)`, `on_status(komunikat)`, `on_blad(blad)`, `on_steg_image(nadawca, dane)`.

#### 5.1.2 Protokół rejestracji

```
Klient → Serwer: "REGISTER:alice\n" (lub "bob")
Serwer → Klient: "OK\n"
```

#### 5.1.3 Format pakietów na poziomie TCP

Wszystkie pakiety poprzedzone są 4-bajtowym nagłówkiem długości (big-endian):
```
[4 B długość | N B payload]
```

Typy payload:
- `RSA_PUB:<n_hex>:<e_hex>\n` — Bob → Alice: klucz publiczny RSA
- `RSA_KEYS:<enc_aes_hex>:<enc_hmac_hex>\n` — Alice → Bob: zaszyfrowane klucze sesji
- `MSG:` + binarny pakiet AES+HMAC — zaszyfrowana wiadomość
- `STEG_IMAGE:<nadawca>\n` + surowe bajty PPM — obraz steganograficzny

#### 5.1.4 Wymiana kluczy RSA

**Rola Boba:**
1. `inicjuj_wymiane_kluczy_jako_bob(bity=1024)` — generuje klucze RSA, wysyła klucz publiczny

**Rola Alice:**
1. Po odebraniu klucza pub Boba — automatycznie wywołuje `wyslij_klucze_sesji_jako_alice()`
2. Generuje 32 B klucza AES i 32 B klucza HMAC (`os.urandom`)
3. Szyfruje klucze RSA kluczem Boba i wysyła
4. Zachowuje lokalne klucze, aktywuje SECURE MODE

**Rola Boba (po odebraniu kluczy):**
1. Odszyfrowuje klucze AES i HMAC kluczem prywatnym RSA
2. Aktywuje SECURE MODE

#### 5.1.5 Ochrona przed Replay Attack

Licznik `_nonce_wyslany` i `_nonce_odebrany` (chroniony przez `threading.Lock`):
- Każda wysyłana wiadomość otrzymuje monotonicznie rosnący nonce
- Przy odbiorze: jeśli `nonce <= ostatni_nonce_odebrany` → REPLAY ATTACK WYKRYTY → pakiet odrzucony

#### 5.1.6 Tryb bezpieczny (`tryb_bezpieczny`)

Właściwość: `True` gdy sesja jest aktywna AND klucze AES+HMAC są dostępne.

**Odporność na rozłączenie:** Klucze sesji NIE są kasowane przy rozłączeniu — po ponownym połączeniu SECURE MODE jest przywracany automatycznie bez ponownej wymiany RSA. Serwer kolejkuje pakiety dla offline-klientów (max 50).

### 5.2 Serwer — `network/server.py`

**Klasa `SerwerRoutera`** — prosty router TCP między Alice i Bobem.

#### 5.2.1 Tryb normalny

Transparentne przekazywanie zaszyfrowanych pakietów — serwer widzi tylko bajty, nie deszyfruje nic.

#### 5.2.2 Tryb Eve — MITM (Man-in-the-Middle)

Aktywowany przez checkbox w GUI serwera.

**Przebieg ataku:**
1. Eve generuje własne klucze RSA-512
2. Przechwytuje klucz publiczny Boba (RSA_PUB) → wysyła Alice swój klucz zamiast
3. Przechwytuje zaszyfrowane klucze sesji (RSA_KEYS) → odszyfrowuje kluczem prywatnym Eve
4. Re-szyfruje klucze kluczem pub Boba i przekazuje
5. Eve zna teraz AES i HMAC → może czytać wszystkie wiadomości

**Luka, którą demonstruje:** Brak weryfikacji tożsamości (brak certyfikatów PKI / fingerprint).

#### 5.2.3 Tryb Eve — Replay Attack

Aktywowany przez checkbox. Serwer przechwytuje pierwszy pakiet MSG i przechowuje go. Przycisk "Wyślij Replay" wysyła go ponownie → klient wykrywa stary nonce.

#### 5.2.4 Kolejkowanie offline

Gdy odbiorca jest offline — serwer kolejkuje pakiety (max 50 per klient). Po ponownym połączeniu dostarcza je wszystkie naraz.

---

## 6. Interfejs graficzny (GUI)

**Framework:** PyQt6

**Styl:** ciemny motyw (dark mode), kolory w palecie Tailwind CSS (#111827, #1f2937, #374151 itd.), zaokrąglone przyciski i pola, scrollbary.

**Uruchomienie:** `python -m secure_messenger.main [--port PORT]`

Aplikacja uruchamia **3 okna jednocześnie** na jednym ekranie, rozmieszczone obok siebie:

### 6.1 Okno Serwera / Eve (`gui/server_window.py`)

- Rozmiar: 440×580 px
- Status serwera (port, aktywny)
- Lista połączonych klientów (Alice, Bob) z informacją o kolejce offline
- Log w czasie rzeczywistym (wszystkie zdarzenia sieciowe)
- Checkbox **MITM (Eve)** — włącza atak Man-in-the-Middle
- Checkbox **Replay** — włącza przechwytywanie pakietu
- Przycisk **Wyślij Replay** (aktywny po przechwyceniu pakietu)

### 6.2 Okno Klienta Alice / Bob (`gui/main_window.py`)

Taby:
1. **Chat** — okno wiadomości, pole input, przyciski: Połącz / Rozłącz, Wymień klucze RSA, Wyślij
2. **Szczegóły kryptograficzne** — ostatni pakiet: IV (hex), HMAC (hex), szyfrogram (hex), nonce, session_id
3. **Steganografia** — wgraj obraz PPM, wpisz tekst, ukryj/wyodrębnij, podgląd pojemności, wyślij do drugiej strony
4. **Benchmarki** — tabela wyników (RSA keygen, RSA enc/dec, AES-CBC, HMAC-SHA256, cykl pakietu)
5. **Ataki** (tylko demo) — symulacja MITM i Replay Attack krok po kroku

Badge **SECURE** / **NIEZABEZPIECZONY** informuje o stanie sesji.

---

## 7. Steganografia LSB — `steganography/lsb.py`

Ukrywanie danych w obrazach rastrowych metodą **Least Significant Bit**.

### 7.1 Zasada działania

Każdy piksel obrazu ma 3 kanały RGB (po 1 bajcie). Zastępujemy **najniższy bit (LSB)** każdego bajtu jednym bitem ukrytej wiadomości. Zmiana wartości piksela o ±1 jest niewidoczna dla ludzkiego oka.

**Pojemność:** obraz W×H pikseli → `W×H×3` dostępnych bitów → `W×H×3÷8` bajtów danych.

### 7.2 Format pliku

Używany format: **PPM P6 (binary)** — prosty, bezstratny, bez kompresji, bez zewnętrznych bibliotek.

### 7.3 Protokół ukrywania

**Payload:** `[4 B długości wiadomości big-endian] + [bajty wiadomości]`

**Ukrywanie (`ukryj_wiadomosc`):**
1. Wczytaj obraz PPM → bajty pikseli
2. Oblicz payload = nagłówek 4 B + wiadomość
3. Konwertuj bajty na bity (MSB first)
4. Dla każdego bitu: `piksel[i] = (piksel[i] & 0xFE) | bit` (zeruj LSB, wstaw bit)
5. Zapisz zmodyfikowany obraz

**Odczytywanie (`odczytaj_wiadomosc`):**
1. Odczytaj 32 LSB → 4 B → długość wiadomości
2. Odczytaj kolejne `(długość × 8)` LSB → bajty wiadomości

### 7.4 Dodatkowe funkcje

- `stworz_ppm(sciezka, szerokosc, wysokosc)` — generuje testowy obraz PPM z losowymi kolorami
- `oblicz_pojemnosc(sciezka)` — zwraca słownik z wymiarami i pojemnością steganograficzną

### 7.5 Kanał steganograficzny w komunikatorze

Obraz PPM ze steganogramem można wysłać do drugiej strony przez serwer (typ pakietu `STEG_IMAGE:`). Jest to **oddzielny kanał edukacyjny** — nie wymaga trybu bezpiecznego AES+HMAC, wystarczy aktywne połączenie TCP.

---

## 8. Symulacje ataków kryptograficznych — `security/attacks.py`

Cel: demonstracja mechanizmu działania ataków i skuteczności zabezpieczeń.

### 8.1 Atak MITM — `AtakMITM`

**Scenariusz (pełna symulacja bez warstwy sieciowej):**

| Etap | Akcja |
|---|---|
| 1 | Bob generuje klucze RSA |
| 2 | Bob wysyła klucz pub → Eve przechwytuje |
| 3 | Eve generuje własne klucze RSA |
| 4 | Eve wysyła Alice swój klucz zamiast Boba |
| 5 | Alice szyfruje klucze sesji kluczem Eve (myśląc że to Bob) |
| 6 | Eve odszyfrowuje → zna klucze AES i HMAC |
| 7 | Eve re-szyfruje klucze kluczem pub Boba i przekazuje |
| 8 | Eve czyta (i opcjonalnie modyfikuje) wszystkie wiadomości |

**Wynik:** `WynikAtakuMITM` z listą kroków, odczytanymi wiadomościami, zmodyfikowanymi wiadomościami, kluczami Eve.

**Obrona:** certyfikaty PKI lub ręczna weryfikacja fingerprint klucza publicznego.

### 8.2 Atak Replay — `AtakReplay`

**Scenariusz:**
1. Alice wysyła wiadomość (nonce=1) → Bob przetwarza
2. Atakujący przechwytuje zaszyfrowany pakiet (nie musi deszyfrować!)
3. Alice wysyła kolejne wiadomości (nonce=2,3,4)
4. Atakujący próbuje wysłać stary pakiet ponownie
5. Bob sprawdza nonce → `nonce_replay <= ostatni_nonce` → WYKRYTY → odrzucony

**Klasa `DemoBezNonce`:** demonstruje skuteczny atak gdy brak nonce — te same wiadomości AES+HMAC przechodzą wielokrotnie.

---

## 9. Benchmarki — `benchmarks/benchmark.py`

Mierzy i porównuje wydajność wszystkich operacji kryptograficznych.

### 9.1 Mierzone operacje

| Operacja | Rozmiary / warianty |
|---|---|
| RSA keygen | 512, 1024, 2048 bitów (3 powtórzenia) |
| RSA szyfrowanie | 512, 1024, 2048 bit (32 B danych, 10 powtórzeń) |
| RSA deszyfrowanie | 512, 1024, 2048 bit (32 B danych, 10 powtórzeń) |
| AES-256-CBC szyfrowanie | 64 B, 1 KB, 10 KB, 100 KB (100 powtórzeń) |
| AES-256-CBC deszyfrowanie | 64 B, 1 KB, 10 KB, 100 KB (100 powtórzeń) |
| HMAC-SHA256 | 64 B, 1 KB, 10 KB, 100 KB (100 powtórzeń) |
| Cykl pakietu (build+unpack) | 64 B, 512 B, 4 KB (50 powtórzeń) |

### 9.2 Metodologia pomiaru

- `time.perf_counter()` — precyzyjny timer
- Rozgrzewka przed każdą serią (cache JIT)
- Metryki: średnia, odchylenie standardowe, min, max
- Przepustowość: MB/s dla AES/HMAC, op/s dla RSA

### 9.3 Klasa wynikowa `WynikBenchmarku`

Dataclass z polami: `operacja`, `sredni_czas_ms`, `odch_std_ms`, `min_ms`, `max_ms`, `liczba_powtorzen`, `przepustowosc`. Metoda `jako_wiersz()` formatuje do tabeli QTableWidget.

---

## 10. Testy jednostkowe i integracyjne — `tests/test_crypto.py`

Uruchomienie: `pytest secure_messenger/tests/test_crypto.py -v`

### 10.1 Zakres testów

| Klasa testowa | Co testuje |
|---|---|
| `TestModPow` | Szybkie potęgowanie: podstawowe, wykładnik 0, podstawa 0, modulus 1, duże liczby, twierdzenie Fermata |
| `TestEuklides` | NWD, wzajemna pierwszość, odwrotność modularna, brak wzajemnej pierwszości |
| `TestMillerRabin` | Liczby pierwsze (parametrized), złożone, Carmichaela, duże pierwsze (2³¹−1) |
| `TestGenerowanieKluczyRSA` | Typ wyniku, długość klucza, e=65537, relacja e·d mod φ(n)=1, minimalny rozmiar |
| `TestSzyfrowanieRSA` | Roundtrip (parametrized), szyfrogram ≠ plaintext, długość szyfrogramu, za długa wiadomość, błędny szyfrogram, klucze sesji roundtrip |
| `TestHMACSHA256` | Zgodność ze stdlib hmac (parametrized), długość wyjścia, weryfikacja, błędny klucz, zmodyfikowana wiadomość, timing-safe, przygotowanie klucza, typy |
| `TestPKCS7` | Pad/unpad dla różnych długości (0,1,15,16,17,31,32,100), przypadki błędne |
| `TestAESCBC` | Roundtrip (parametrized), różny IV dla tej samej wiadomości, długość IV, wielokrotność bloku, błędne klucze |
| `TestPakietSieciowy` | Roundtrip pakietu, pusta wiadomość, za krótki pakiet, zmodyfikowany pakiet, błędny HMAC, błędny AES, różne rozmiary |
| `TestIntegracjaKryptograficzna` | Pełny przepływ Alice↔Bob, logika wykrywania replay |
| `TestSteganografiaLSB` | Roundtrip tekst, roundtrip bajty losowe, tylko LSB zmieniony, pojemność 64×64, za długa wiadomość, pusta wiadomość |

### 10.2 Filozofia testowania

Dla każdego modułu:
1. **Happy path** — poprawne działanie
2. **Przypadki brzegowe** — puste dane, graniczne wartości (0, 1, 16, 17 bajtów)
3. **Błędne dane** — nieprawidłowe typy, uszkodzone szyfrogramy, złe klucze → system rzuca wyjątek, nie crashuje

---

## 11. Protokół komunikacji — diagram przepływu

```
Alice                    Serwer (Router)              Bob
  |                           |                         |
  |--- REGISTER:alice\n ----> |                         |
  | <---- OK\n -------------- |                         |
  |                           |  <-- REGISTER:bob\n --- |
  |                           |  --- OK\n ----------->  |
  |                           |                         |
  |                           | <-- RSA_PUB:(n,e)\n --- |  Bob wysyła klucz pub
  | <-- RSA_PUB:(n,e)\n ----- |                         |  Serwer przekazuje (lub Eve podmienia)
  |                           |                         |
  |-- RSA_KEYS:(enc_a,enc_h) >|                         |  Alice szyfruje klucze
  |                           |-- RSA_KEYS:(enc_a,enc_h)>  Serwer przekazuje (lub Eve odczytuje+re-szyfruje)
  |                           |                         |  Bob odszyfrowuje klucze
  |                           |                         |
  |=== SECURE MODE AKTYWNY ===|=========================|
  |                           |                         |
  |--- MSG:[IV|HMAC|cipher]-->|                         |  Wiadomość od Alice
  |                           |--- MSG:[IV|HMAC|cipher]>|  Serwer przekazuje
  |                           |                         |  Bob weryfikuje HMAC + odszyfrowuje
  |                           |                         |
  | <-- MSG:[IV|HMAC|cipher]--|                         |  Wiadomość od Boba
  | <-- [IV|HMAC|cipher] ---- |                         |  Alice weryfikuje + odszyfrowuje
```

---

## 12. Właściwości bezpieczeństwa

| Właściwość | Implementacja |
|---|---|
| Poufność | AES-256-CBC (klucz 256-bit, losowy IV dla każdej wiadomości) |
| Integralność | HMAC-SHA256 (Encrypt-then-MAC) |
| Uwierzytelnienie klucza sesji | RSA — tylko Bob ma klucz prywatny |
| Ochrona przed Replay Attack | Monotonicznie rosnący nonce per sesja |
| Ochrona przed Padding Oracle | Weryfikacja HMAC PRZED deszyfrowaniem AES |
| Timing-safe weryfikacja | HMAC porównywany XOR-em (nie ==) |
| Kryptograficznie bezpieczna losowość | `os.urandom` dla kluczy, IV, kluczy sesji |
| Demonstracja braku PKI | Tryb Eve (MITM) w GUI serwera |

---

## 13. Znane ograniczenia (celowe — cel edukacyjny)

- RSA bez OAEP (textbook RSA) — podatny na niektóre ataki w prod
- Brak certyfikatów PKI — MITM możliwy przy braku ręcznej weryfikacji fingerprint
- Brak Perfect Forward Secrecy — klucze sesji ustalane jednokrotnie przez RSA
- Brak szyfrowania danych steganograficznych w kanale LSB — steganogram nie jest chroniony AES/HMAC

---

## 14. Uruchomienie

### Wymagania

```
pip install PyQt6 cryptography pytest
```

Python 3.12+ (projekt używa `tuple[int, int]` i innych nowoczesnych type hints).

### Uruchomienie aplikacji

```bash
python -m secure_messenger.main
python -m secure_messenger.main --port 8888
```

### Uruchomienie testów

```bash
pytest secure_messenger/tests/test_crypto.py -v
```

### Demo krok po kroku

1. Uruchom aplikację → pojawią się 3 okna: Serwer, Alice, Bob
2. W oknie Alice: kliknij **Połącz**
3. W oknie Bob: kliknij **Połącz**, potem **Wymień klucze RSA**
4. Oba okna przejdą w **SECURE MODE** — można pisać wiadomości
5. **Demo MITM:** zaznacz checkbox w Serwerze PRZED krokiem 3, powtórz
6. **Demo Replay:** zaznacz checkbox, wyślij wiadomość, kliknij **Wyślij Replay**
7. **Demo steganografii:** zakładka Steganografia → wgraj PPM, wpisz tekst, ukryj, wyślij

---

## 15. Metryki projektu

| Metryka | Wartość |
|---|---|
| Liczba modułów Python | 10 (bez `__init__.py`) |
| Łączna liczba klas | ~15 |
| Łączna liczba funkcji | ~60 |
| Liczba klas testowych | 11 |
| Liczba przypadków testowych | ~70 |
| Obsługiwane rozmiary kluczy RSA | 512, 1024, 2048 bit |
| Format obrazów steganograficznych | PPM P6 (binary) |
| Port TCP (domyślny) | 9999 |
| Maksymalna pojemność kolejki offline | 50 pakietów/klient |
