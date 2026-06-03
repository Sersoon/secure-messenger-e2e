# Secure Messenger E2E

Szyfrowany komunikator z szyfrowaniem end-to-end, napisany w Pythonie. 

## Działanie

Wiadomości są szyfrowane po stronie nadawcy i odszyfrowane dopiero u odbiorcy — serwer widzi tylko zaszyfrowane dane.

**Stos kryptograficzny (własna implementacja):**
- RSA-2048 — wymiana kluczy przy połączeniu
- AES-CBC + HMAC-SHA256 — szyfrowanie i integralność wiadomości
- LSB steganografia — ukrywanie wiadomości w obrazach

## Wymagania

Python 3.10+

```
pip install -r requirements.txt
```

## Uruchomienie

```
python -m secure_messenger.main --server   # uruchamia serwer
python -m secure_messenger.main            # uruchamia klienta
```

## Testy

```
pytest secure_messenger/tests/
```
