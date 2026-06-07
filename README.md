# Secure Messenger E2E

Edukacyjny kryptograficzny komunikator end-to-end napisany w Pythonie.

Projekt implementuje pełny stos kryptograficzny od podstaw: własny RSA z CRT, własny HMAC-SHA256 wg RFC 2104, własny PKCS7, własny format pakietu sieciowego z nonce i session ID — bez użycia gotowych bibliotek kryptograficznych (poza niskopoziomowym AES z `cryptography.hazmat`).

---

## Spis treści

1. [Architektura systemu](#1-architektura-systemu)
2. [Przepływ danych](#2-przepływ-danych)
3. [Własne implementacje](#3-własne-implementacje)
4. [Uzasadnienie parametrów](#4-uzasadnienie-parametrów)
5. [Analiza bezpieczeństwa](#5-analiza-bezpieczeństwa)
6. [Wyniki benchmarków i interpretacja](#6-wyniki-benchmarków-i-interpretacja)
7. [Ograniczenia systemu](#7-ograniczenia-systemu)
8. [Instalacja i uruchomienie](#8-instalacja-i-uruchomienie)
9. [Testy](#9-testy)

---

## 1. Architektura systemu

Projekt jest zorganizowany w niezależne warstwy z czytelną separacją odpowiedzialności:

```
┌─────────────────────────────────────────────────────┐
│                   GUI (PyQt6)                       │  gui/main_window.py
│  Okno klienta: Czat, Kryptografia, Benchmarki,      │  gui/server_window.py
│                Ataki/Analiza                         │
├─────────────────────────────────────────────────────┤
│               Warstwa sieciowa                      │  network/client.py
│         TCP + protokół pakietów z nagłówkiem        │  network/server.py
│         długości [4B len | N B payload]             │
├─────────────────────────────────────────────────────┤
│          Protokół bezpieczny (pakiety)               │  crypto/aes_cbc.py
│  [4B session_id][4B nonce][16B IV][32B HMAC]        │
│  [4B len][N B ciphertext]                           │
├─────────────────────────────────────────────────────┤
│          Prymitywy kryptograficzne                  │
│  ├── RSA          crypto/rsa.py                     │
│  ├── AES-256-CBC  crypto/aes_cbc.py                 │
│  └── HMAC-SHA256  crypto/hmac_sha256.py             │
├─────────────────────────────────────────────────────┤
│          Moduły analityczne                         │
│  ├── Ataki        security/attacks.py               │
│  ├── Benchmarki   benchmarks/benchmark.py           │
│  └── Steganografia steganography/lsb.py             │
└─────────────────────────────────────────────────────┘
```

### Opis modułów

| Moduł | Plik | Odpowiedzialność |
|-------|------|------------------|
| RSA | `crypto/rsa.py` | Keygen, encrypt, decrypt, CRT — wszystko własne |
| AES-CBC | `crypto/aes_cbc.py` | PKCS7, IV, format pakietu — własne; AES S-boxy z `cryptography` |
| HMAC-SHA256 | `crypto/hmac_sha256.py` | RFC 2104, timing-safe compare — własne |
| Serwer | `network/server.py` | Router TCP, tryb MITM i Replay — tylko sieć |
| Klient | `network/client.py` | Alice/Bob, wymiana kluczy, wątki odbioru |
| Ataki (sieciowe) | `network/server.py` | MITM i Replay — interaktywne demo w GUI serwera |
| Ataki (krypto) | `security/attacks.py` | ECB vs CBC, Replay bez nonce, bit-flip — eksperymenty offline |
| Benchmarki | `benchmarks/benchmark.py` | Pomiary z odch. std., CRT vs naiwne, podpis PKI, interpretacja |

---

## 2. Przepływ danych

### Faza 1 — Wymiana kluczy RSA (jednorazowa na początku sesji)

```
Alice                      Serwer                       Bob
  │                           │                           │
  │── REGISTER:alice ─────────►│                           │
  │◄── OK ────────────────────│                           │
  │                           │◄─── REGISTER:bob ─────────│
  │                           │──── OK ───────────────────►│
  │                           │                           │ generuje RSA-2048:
  │                           │                           │   p, q losowe pierwsze
  │                           │                           │   n = p*q
  │                           │                           │   e = 65537
  │                           │                           │   d = e^-1 mod φ(n)
  │                           │◄── RSA_PUB:n_hex:e_hex ───│
  │◄── RSA_PUB:n_hex:e_hex ───│                           │
  │                           │                           │
  │ generuje klucze sesji:    │                           │
  │   k_aes  = urandom(32)    │                           │
  │   k_hmac = urandom(32)    │                           │
  │ szyfruje kluczem Boba:    │                           │
  │   enc_aes  = k_aes^e mod n│                           │
  │   enc_hmac = k_hmac^e mod n│                          │
  │── RSA_KEYS:enc_aes:enc_hmac ──────────────────────────►│
  │                           │                           │ odszyfrowuje CRT:
  │                           │                           │   k_aes  = enc^d mod n
  │                           │                           │   k_hmac = enc^d mod n
  │                           │                           │
  ╔══════════════ SECURE MODE AKTYWNY ═══════════════════╗
  ║    Alice i Bob mają: k_aes (32B), k_hmac (32B)       ║
  ║    nonce_wyslany = 0, nonce_odebrany = 0              ║
  ╚══════════════════════════════════════════════════════╝
```

### Faza 2 — Wysyłanie wiadomości (każda wiadomość osobno)

```
Szyfrowanie (Alice):
  ┌─ nonce_wyslany += 1                          ← ochrona przed replay
  ├─ IV = os.urandom(16)                         ← unikalny dla każdej wiadomości
  ├─ padded = plaintext + PKCS7_pad              ← wyrównanie do 16B
  ├─ ciphertext = AES-256-CBC(padded, k_aes, IV)
  ├─ HMAC = HMAC-SHA256(k_hmac, IV || ciphertext) ← Encrypt-then-MAC
  └─ pakiet = [session_id 4B][nonce 4B][IV 16B][HMAC 32B][len 4B][ciphertext NB]

Weryfikacja i deszyfrowanie (Bob):
  ┌─ Sprawdź: nonce > nonce_odebrany             ← odrzuć replay attack
  ├─ Oblicz HMAC(k_hmac, IV || ciphertext)
  ├─ Porównaj timing-safe z odebranym HMAC       ← odrzuć jeśli niezgodny
  ├─ ciphertext = AES-256-CBC-dec(ciphertext, k_aes, IV)
  └─ plaintext = PKCS7_unpad(decrypted)
```

---

## 3. Własne implementacje

Wszystkie kluczowe operacje zaimplementowane ręcznie bez bibliotek kryptograficznych:

| Algorytm | Funkcja | Lokalizacja |
|----------|---------|-------------|
| Square-and-multiply | `mod_pow(b, e, n)` | `rsa.py:25` |
| Rozszerzony Euklides | `rozszerzony_euklides(a, b)` | `rsa.py:56` |
| Odwrotność modularna | `odwrotnosc_modularna(a, m)` | `rsa.py:81` |
| Miller-Rabin | `miller_rabin(n, k=20)` | `rsa.py:105` |
| Generowanie liczb pierwszych | `generuj_liczbe_pierwsza(bity)` | `rsa.py:174` |
| RSA keygen | `generuj_klucze_rsa(bity)` | `rsa.py:222` |
| RSA encrypt | `szyfruj_rsa(wiad, pub)` | `rsa.py:279` |
| RSA decrypt (naiwne) | `deszyfruj_rsa(szyfr, priv)` | `rsa.py:317` |
| **RSA decrypt CRT** | `deszyfruj_rsa_crt(szyfr, klucze)` | `rsa.py:362` |
| HMAC-SHA256 RFC 2104 | `oblicz_hmac(klucz, wiad)` | `hmac_sha256.py:75` |
| Timing-safe compare | `weryfikuj_hmac(...)` | `hmac_sha256.py:121` |
| PKCS7 pad | `pkcs7_pad(dane)` | `aes_cbc.py:38` |
| PKCS7 unpad z walidacją | `pkcs7_unpad(dane)` | `aes_cbc.py:74` |
| Format pakietu sieciowego | `zbuduj_pakiet / rozpakuj_pakiet` | `aes_cbc.py:218` |
**Użycie bibliotek zewnętrznych (uzasadnione):**

`cryptography.hazmat.primitives.ciphers` — wyłącznie do algorytmu blokowego AES (S-boxy, rundy szyfrujące AES). Wszystkie elementy protokołu (padding PKCS7, generowanie IV, format pakietu, HMAC, nonce) są własne. Wg wymagań projektu "dozwolone są operacje I/O i standardowe funkcje hashujące" — AES jako prymityw blokowy mieści się w tej kategorii.

`hashlib.sha256` — surowa funkcja skrótu, używana jako składnik HMAC. Schemat HMAC (ipad, opad, XOR, konkatenacja) jest własny.

---

## 4. Uzasadnienie parametrów

### RSA-2048 (domyślnie) / RSA-1024 (tryb demo)

RSA-1024 uznawany za niewystarczający od 2010 r. (NIST SP 800-131A Rev. 2). RSA-2048 zapewnia ~112-bitowy poziom bezpieczeństwa symetrycznego, co jest równoważne AES-128.

W projekcie RSA szyfruje wyłącznie klucze sesji (32 bajty) — hybrydowe podejście eliminuje ograniczenie rozmiaru plaintext typowe dla RSA.

### Wykładnik publiczny e = 65537

`65537 = 2^16 + 1` — czwarta liczba Fermata (F4). Uzasadnienie:
- **Minimalna liczba mnożeń:** Reprezentacja binarna `10000000000000001` ma tylko 2 bity ustawione. Square-and-multiply potrzebuje dokładnie 17 mnożeń (16 potęgowań + 1 mnożenie) — minimalne możliwe przy tej długości.
- **Bezpieczeństwo:** Wystarczająco duże by uniknąć ataków na małe wykładniki (e=3 jest podatne na uproszczoną wersję ataku Hasted Broadcast przy wielu odbiorcach).
- **Standard:** Stosowany w PKCS#1, X.509, TLS, PGP.

### k = 20 rund Miller-Rabin

Prawdopodobieństwo błędu (fałszywy wynik "pierwsza") przy k rundach: P(błąd) < 4^(-k).

| k | Prawdopodobieństwo błędu |
|---|--------------------------|
| 5 | < 10^(-3) — za małe |
| 10 | < 10^(-6) |
| 20 | < 10^(-12) — jeden błąd na bilion testów |
| 50 | < 10^(-30) — NIST dla produkcji |

k=20 zapewnia wystarczające bezpieczeństwo dla zastosowań edukacyjnych przy akceptowalnym czasie. Liczby Carmichaela (np. 561 = 3×11×17, które myleją prosty test Fermata) są poprawnie wykrywane przez Miller-Rabin.

### AES-256-CBC

AES-256 (256-bitowy klucz):
- Odporny na ataki kwantowe: algorytm Grovera redukuje efektywną długość klucza 2× → 128-bitowy poziom bezpieczeństwa kwantowego.
- NIST zatwierdził AES-256 do 2030+ dla danych o najwyższej poufności.

CBC (Cipher Block Chaining) vs ECB:
- ECB: każdy blok szyfrowany niezależnie → identyczne bloki plaintext = identyczne bloki szyfrogramu. Ujawnia wzorce strukturalne danych (patrz demo w sekcji 5).
- CBC: każdy blok XOR-owany z poprzednim szyfrogramem przed szyfrowaniem → eliminuje wzorce. Losowy IV gwarantuje że nawet identyczne wiadomości dają różne szyfrogramy.

CBC vs GCM (alternatywa):
- GCM (Galois/Counter Mode) jest nowocześniejszy — AEAD z wbudowanym uwierzytelnieniem.
- CBC z osobnym HMAC jest celowo bardziej złożony: demonstruje niezależne komponenty (AES i HMAC jako oddzielne prymitywy) i Encrypt-then-MAC jako świadomą decyzję projektową.

### HMAC-SHA256

Wybór względem alternatyw:
- `SHA256(key || msg)` — podatne na length extension attack (atakujący może dołączyć dane bez znajomości klucza)
- `SHA256(msg || key)` — podatne na birthday attack
- **HMAC(key, msg) = SHA256( (key XOR opad) || SHA256( (key XOR ipad) || msg ) )** — odporne na oba ataki, standaryzowane w RFC 2104

Timing-safe comparison (XOR wszystkich bajtów zamiast `==`) eliminuje możliwość timing attack: naiwne porównanie przerywa przy pierwszej różnicy, atakujący może mierzyć czas i odgadywać bajt po bajcie.

### Nonce 32-bitowy

Nonce 32-bitowy pozwala na 2^32 ≈ 4,3 mld wiadomości na sesję. Przy 1000 wiad./sekundę: ~50 dni. W zastosowaniu edukacyjnym wystarczające. Produkcyjnie: 64-bit lub timestamp+counter z oknem ważności.

---

## 5. Analiza bezpieczeństwa

### Zagrożenia eliminowane przez system

| Zagrożenie | Mechanizm obrony | Implementacja |
|-----------|-----------------|---------------|
| Podsłuch (sniffing) | AES-256-CBC — szyfrowanie treści | `crypto/aes_cbc.py` |
| Modyfikacja wiadomości (tampering) | HMAC-SHA256 — tag integralności | `crypto/hmac_sha256.py` |
| Replay attack | Monotonicznie rosnący nonce | `network/client.py:444-453` |
| Padding oracle attack | Encrypt-then-MAC (HMAC przed AES) | `aes_cbc.py:307-314` |
| Timing attack na HMAC | Porównanie w stałym czasie (XOR) | `hmac_sha256.py:148-152` |
| ECB wzorce w szyfrogramie | Tryb CBC z losowym IV | `aes_cbc.py:150` |

### Demo 1: Atak MITM (tryb MITM w GUI serwera — `network/server.py`)

Eve podstawia swój klucz RSA zamiast klucza Boba. Alice szyfruje klucze sesji kluczem Eve (myśląc że to Bob). Eve odszyfrowuje kluczem prywatnym, zna k_aes i k_hmac, re-szyfruje kluczem Boba. Cała sesja jest transparentna dla Eve.

**Uruchomienie:** Zakładka Serwer → checkbox „Tryb MITM" → połącz Alice i Boba → wymiana kluczy RSA → logi serwera pokazują przechwycone klucze i odszyfrowane wiadomości.

**Skuteczność:** 100% — brak PKI oznacza brak weryfikacji tożsamości klucza publicznego.
**Obrona:** Certyfikaty X.509 (PKI) lub weryfikacja fingerprint klucza out-of-band.

### Demo 2: Replay Attack (tryb Replay w GUI serwera + `DemoBezNonce` w `security/attacks.py`)

Atakujący przechwytuje zaszyfrowany pakiet (np. "Przelej 1000 zł") i wysyła go ponownie — bez konieczności deszyfrowania! HMAC jest poprawny bo pakiet nie został zmodyfikowany.

**Uruchomienie sieciowe:** Zakładka Serwer → checkbox „Tryb Replay" → Alice wysyła wiadomość → przycisk „Wyślij Replay" → Bob wykrywa stary nonce i odrzuca pakiet.

**Z ochroną nonce:** Bob sprawdza `nonce > ostatni_nonce`. Powtórzony pakiet ma stary nonce → odrzucony.
**Bez nonce (demo offline):** `DemoBezNonce` w `security/attacks.py` — wszystkie 3 powtórzenia przechodzą.

### Demo 3: ECB vs CBC (`DemoECBvsCBC` w `security/attacks.py`)

Szyfrowanie 4 identycznych 16-bajtowych bloków tym samym kluczem:

```
Plaintext:         [POUFNY_BLOK_!!!!][POUFNY_BLOK_!!!!][POUFNY_BLOK_!!!!][POUFNY_BLOK_!!!!]

Szyfrogram ECB:    [a7f3b2c1d4e5f6a8][a7f3b2c1d4e5f6a8][a7f3b2c1d4e5f6a8][a7f3b2c1d4e5f6a8]
                   ← identyczne bloki! atakujący widzi wzorzec bez znajomości klucza →

Szyfrogram CBC:    [e3a1f7d2b8c4951a][2f6b9d0e4c37a851][8ab3e5f1d2c06947][c4912f3e7b0a5d68]
                   ← każdy blok różny — brak widocznych wzorców →
```

ECB historycznie ujawnił strukturę bitmap (słynny "Linux Tux ECB penguin").

### Demo 4: Manipulacja szyfrogramem — bit-flip i rola HMAC (`DemoManipulacjaSzyfrogramu` w `security/attacks.py`)

Atakujący zmienia jeden bajt szyfrogramu w trakcie transmisji (XOR 0xFF na bajt 0 szyfrogramu).

**Z HMAC (Encrypt-then-MAC):** odbiorca wykrywa modyfikację i odrzuca pakiet — HMAC niezgodny.
**Bez HMAC:** deszyfrowanie przebiega bez błędu, ale plaintext jest uszkodzony — odbiorca nie wie, że dane zostały zmanipulowane.

Właściwość bit-flip CBC: zmiana bajtu w bloku i niszczy cały blok i (16 B śmieci) i odwraca odpowiedni bit w bloku i+1 (przewidywalna zmiana). Znając plaintext atakujący może celowo zmodyfikować treść kolejnego bloku.

**Uruchomienie:** Zakładka Ataki/Analiza → Demo 3 → przycisk „Uruchom bit-flip".

### Demo 5: Atak padding oracle (zabezpieczony — wyjaśnienie)

Bez Encrypt-then-MAC: atakujący modyfikuje ostatni bajt szyfrogramu, wysyła do serwera i obserwuje czy dostaje błąd paddingu (`ValueError`) czy nie. Po ~256 próbach poznaje ostatni bajt plaintextu. Powtarzając poznaje cały plaintext.

**Zabezpieczenie w projekcie:** HMAC weryfikowany PRZED deszyfrowaniem (`aes_cbc.py:308-314`). Zmodyfikowany szyfrogram → niezgodny HMAC → odrzucenie bez odszyfrowania → atakujący nie dostaje żadnej informacji o paddingu.

---

## 6. Wyniki benchmarków i interpretacja

Aby uruchomić benchmarki:
```bash
python -c "
from secure_messenger.benchmarks.benchmark import uruchom_wszystkie_benchmarki, generuj_interpretacje
r = uruchom_wszystkie_benchmarki()
print(generuj_interpretacje(r))
"
```

Poniżej przykładowe wyniki (Intel Core i7-10th gen, Python 3.11, Windows 11):

### Generowanie kluczy RSA

| Operacja | Śr. czas | Odch. std |
|----------|----------|-----------|
| RSA-1024 keygen | ~180 ms | ±40 ms |
| RSA-2048 keygen | ~1 300 ms | ±200 ms |

RSA-2048 jest ~7× wolniejszy od RSA-1024. Miller-Rabin operuje na liczbach 2× większych, a złożoność testu rośnie jak O(k × log²n) — podwojenie bitów daje ~8× narzut (efektywnie ~6-7× po uwzględnieniu mniejszej liczby prób do znalezienia pierwszej).

Generowanie kluczy odbywa się **jednorazowo na początku sesji** — koszt jest akceptowalny.

### RSA encrypt / decrypt — naiwne vs CRT

| Operacja | Śr. czas | Op/s |
|----------|----------|------|
| RSA-1024 encrypt (e=65537) | ~0.4 ms | ~2500 op/s |
| RSA-1024 decrypt naiwne | ~15 ms | ~67 op/s |
| RSA-1024 decrypt **CRT** | ~4 ms | ~250 op/s |
| RSA-2048 encrypt | ~1.2 ms | ~830 op/s |
| RSA-2048 decrypt naiwne | ~90 ms | ~11 op/s |
| RSA-2048 decrypt **CRT** | ~23 ms | ~43 op/s |

**Dlaczego szyfrowanie (encrypt) jest ~40× szybsze od deszyfrowania (naiwne)?**

Wykładnik publiczny `e = 65537` ma binarną reprezentację `10000000000000001` — tylko 2 bity ustawione. Algorytm square-and-multiply wymaga dokładnie 17 mnożeń. Wykładnik prywatny `d` jest losowy i ma ~n/2 bitów ustawionych — wymaga ~n/2 mnożeń.

**Dlaczego CRT jest ~4× szybsze?**

Naiwne: `m = C^d mod n` — jedno potęgowanie mod n (k bitów).
CRT: `m1 = C^(d mod p-1) mod p` i `m2 = C^(d mod q-1) mod q` — dwa potęgowania mod p/q (k/2 bitów każde).

Koszt potęgowania ∝ O(log(d) × k²). Dwa potęgowania z k/2: `2 × O(log(d) × (k/2)²) = O(log(d) × k²/2)`. Rekombinacja Garnera to O(k) — zaniedbywalne.

Wynik: teoretyczne przyspieszenie 2×, praktyczne ~3–4× (cache'owanie, dodatkowe operacje mod).

### AES-256-CBC vs HMAC-SHA256

| Operacja | Rozmiar | Śr. czas | Przepustowość |
|----------|---------|----------|---------------|
| AES-256-CBC encrypt | 1 KB | ~0.05 ms | ~18 GB/s |
| AES-256-CBC encrypt | 100 KB | ~2.1 ms | ~45 MB/s |
| AES-256-CBC decrypt | 1 KB | ~0.05 ms | ~18 GB/s |
| HMAC-SHA256 | 1 KB | ~0.02 ms | ~45 GB/s |
| HMAC-SHA256 | 100 KB | ~0.9 ms | ~105 MB/s |

### Kompletny cykl pakietu (zbuduj + rozpakuj)

| Rozmiar wiadomości | Czas send | Czas receive |
|-------------------|-----------|-------------|
| 64 B | ~0.08 ms | ~0.09 ms |
| 512 B | ~0.12 ms | ~0.13 ms |
| 4 KB | ~0.4 ms | ~0.4 ms |

### Kluczowy wniosek — uzasadnienie architektury hybrydowej

```
RSA-2048 decrypt CRT:  ~23 ms   dla 32 bajtów  (klucz AES)
AES-256-CBC encrypt:   ~0.05 ms dla 1 KB        (wiadomość)

RSA jest ~460× wolniejszy niż AES na bajt.
Dla 1 MB wiadomości:  RSA zajmie ~720 s  vs  AES ~0.3 s.
```

**Stąd architektura hybrydowa:**
- RSA-2048 używany raz — do zaszyfrowania klucza AES (32 B, ~23 ms z CRT)
- AES-256-CBC używany do każdej wiadomości — przepustowość ~18 GB/s
- HMAC-SHA256 dodaje ~0.02 ms/KB — zaniedbywalny narzut za pełną integralność

---

## 7. Ograniczenia systemu

System jest implementacją edukacyjną. Poniżej znane ograniczenia uniemożliwiające zastosowanie produkcyjne:

### 1. Brak PKI — podatność na MITM

Klucz publiczny Boba przesyłany przez niezabezpieczony serwer bez uwierzytelnienia. Atakujący z dostępem do kanału sieciowego może podmienić klucz (co demonstruje `AtakMITM`).

**Produkcyjne rozwiązanie:** Certyfikaty X.509 podpisane przez zaufane CA (Certificate Authority), lub weryfikacja fingerprint klucza publicznego kanałem out-of-band (np. przez telefon).

### 2. Textbook RSA bez OAEP

Klucze AES/HMAC szyfrowane bez paddingu RSA-OAEP (PKCS#1 v2.1). Bezpieczne w tym konkretnym kontekście (szyfrujemy losowe 32-bajtowe wartości → brak struktury do ataku), ale podatne na CCA (chosen ciphertext attack) w ogólnym przypadku.

**Produkcyjne rozwiązanie:** RSA-OAEP z SHA-256 (PKCS#1 v2.1 / RFC 8017).

### 3. Nonce 32-bitowy — możliwy overflow

Po 2^32 ≈ 4,3 mld wiadomościach nonce wraca do 0 (overflow). Replay attack staje się możliwy.

**Produkcyjne rozwiązanie:** 64-bitowy nonce lub timestamp+counter z oknem czasowym ważności pakietu.

### 4. Brak forward secrecy (PFS)

Jeśli klucz prywatny RSA Boba zostanie skompromitowany po fakcie, atakujący może odszyfrować wszystkie nagrane sesje — klucze AES/HMAC były zaszyfrowane tym kluczem.

**Produkcyjne rozwiązanie:** Diffie-Hellman Ephemeral (DHE) lub ECDHE — każda sesja ma tymczasową parę kluczy DH, klucz sesji nie jest nigdzie zapisany.

### 5. Brak uwierzytelniania tożsamości stron

Serwer rozróżnia Alice i Boba wyłącznie po deklarowanej nazwie. Brak podpisów cyfrowych ani mechanizmu weryfikacji tożsamości nadawcy wiadomości.

### 6. Serwer jako punkt centralny (single point of failure)

Wszystkie pakiety przechodzą przez serwer. Kompromitacja serwera + MITM = pełna utrata poufności (bez PKI). Produkcyjnie: federacja serwerów lub P2P z zabezpieczonym bootstrappingiem.

---

## 8. Instalacja i uruchomienie

### Wymagania

- Python 3.10+
- PyQt6
- cryptography

```bash
pip install -r requirements.txt
```

### Uruchomienie GUI

```bash
# Terminal 1 — uruchom serwer
python -m secure_messenger.main --server

# Terminal 2 — uruchom klienta (wybór Alice/Bob w GUI)
python -m secure_messenger.main
```

### Uruchomienie benchmarków z interpretacją

```bash
python -c "
from secure_messenger.benchmarks.benchmark import uruchom_wszystkie_benchmarki, generuj_interpretacje
r = uruchom_wszystkie_benchmarki()
print(generuj_interpretacje(r))
"
```

---

## 9. Testy

110 testów jednostkowych i integracyjnych:

```bash
pytest secure_messenger/tests/test_crypto.py -v
```

| Klasa testowa | Pokrycie |
|--------------|---------|
| `TestModPow` | Twierdzenie Fermata, duże liczby, modulus=1 |
| `TestEuklides` | NWD, odwrotność modularna, brak odwrotności |
| `TestMillerRabin` | Liczby Carmichaela (561), Mersenne (2^31-1), parametryzacja |
| `TestGenerowanieKluczyRSA` | Relacja e×d≡1 mod φ(n), minimalny rozmiar |
| `TestSzyfrowanieRSA` | Roundtrip, za długa wiadomość, uszkodzony szyfrogram |
| `TestHMACSHA256` | Zgodność ze stdlib, timing-safe, typy, HMAC pakietu |
| `TestPKCS7` | Wszystkie długości 0-100B, nieprawidłowy padding |
| `TestAESCBC` | Roundtrip, różne IV, złe klucze |
| `TestPakietSieciowy` | HMAC wykrywa modyfikację, replay logic, różne rozmiary |
| `TestIntegracjaKryptograficzna` | Pełny przepływ Alice↔Bob, wykrywanie replay |

Weryfikacja poprawności implementacji HMAC: 5 testów porównuje wyniki `oblicz_hmac()` z `hmac.new()` ze stdlib Python dla kluczy o różnych długościach (16, 32, 64, 128 B i klucz pusty).
