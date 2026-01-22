#!/usr/bin/env python3
# HU2 – Aufgabe 3c
# Ziel: RSA KeyGen, SHA-256 Hash, Encrypt/Decrypt, Sign/Verify, Tests

# WICHTIG: Übungs-Implementierung (OHNE Padding wie OAEP/PSS).
# Für echte Sicherheit: >= 2048 Bit und OAEP/PSS verwenden.

import hashlib          # Für SHA-256 (Hashfunktion)
import secrets          # Für sichere Zufallszahlen (Primzahlen erzeugen)
from dataclasses import dataclass
from typing import Tuple


# ============================================================
# MATHE-HILFSFUNKTIONEN (RSA braucht das für d = invmod(e, phi))
# ============================================================

def gcd(a: int, b: int) -> int:
    """
    gcd = größter gemeinsamer Teiler.
    Beispiel: gcd(20, 8) = 4.
    RSA nutzt gcd, um zu prüfen: gcd(e, phi) == 1 (sonst kein d möglich).
    """
    while b != 0:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Erweiterter Euklid:
    Liefert (g, x, y) so dass gilt:
    a*x + b*y = g und g = gcd(a, b)

    Beispiel (wichtig für RSA):
    egcd(3, 20) -> (1, 7, -1)
    weil 3*7 + 20*(-1) = 1
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def invmod(a: int, m: int) -> int:
    """
    Modulares Inverses:
    Findet d so dass gilt:
    a*d mod m = 1

    RSA-Anwendung:
    d = invmod(e, phi)

    Beispiel:
    invmod(3, 20) = 7
    weil 3*7 mod 20 = 1
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        # Kein Inverses, wenn a und m nicht teilerfremd sind
        raise ValueError("Kein modulares Inverses existiert (a und m nicht teilerfremd).")
    return x % m


# ============================================================
# PRIMZAHLEN ERZEUGEN (RSA braucht zwei große Primzahlen p und q)
# ============================================================

def is_probable_prime(n: int, rounds: int = 16) -> bool:
    """
    Miller-Rabin Primzahltest (wahrscheinlich prim).
    Für Übungszwecke ausreichend.
    """
    if n < 2:
        return False

    # Kleine Primzahlen schnell prüfen (Filter)
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Schreibe n-1 = d * 2^s mit d ungerade
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Wiederhole Test mehrere Runden
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # Zufallszahl in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """
    Erzeugt eine zufällige Primzahl mit 'bits' Bit.
    """
    if bits < 16:
        raise ValueError("Bitte mindestens 16 Bits nutzen.")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))  # höchstes Bit setzen (damit genau bits Bits)
        candidate |= 1                  # ungerade machen
        if is_probable_prime(candidate):
            return candidate


# ============================================================
# RSA SCHLÜSSEL-STRUKTUREN (Public Key und Private Key)
# ============================================================

@dataclass(frozen=True)
class RSAPublicKey:
    # Öffentlicher Schlüssel: (n, e)
    n: int
    e: int


@dataclass(frozen=True)
class RSAPrivateKey:
    # Privater Schlüssel: (n, d)
    n: int
    d: int


# ============================================================
# 1) RSA KEYGEN (Aufgabe 3c.1)
# ============================================================

def rsa_keygen(bits: int = 1024, e: int = 65537) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Erzeugt RSA-Schlüsselpaar:
    - wähle Primzahlen p, q
    - n = p*q
    - phi = (p-1)(q-1)
    - wähle e (Standard 65537)
    - berechne d = invmod(e, phi)
    """
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        # RSA braucht gcd(e, phi) = 1
        if gcd(e, phi) != 1:
            continue

        d = invmod(e, phi)
        return RSAPublicKey(n=n, e=e), RSAPrivateKey(n=n, d=d)


# ============================================================
# 2) SHA-256 HASH (Aufgabe 3c.2)
# ============================================================

def sha256_bytes(message: bytes) -> bytes:
    """
    Gibt den SHA-256 Hash als Bytes zurück (32 Bytes).
    """
    return hashlib.sha256(message).digest()


def sha256_hex(message: bytes) -> str:
    """
    Gibt den SHA-256 Hash als Hex-String zurück (lesbar).
    """
    return hashlib.sha256(message).hexdigest()


# ============================================================
# HILFE: RSA arbeitet mit Zahlen -> bytes in int umwandeln und zurück
# ============================================================

def bytes_to_int(b: bytes) -> int:
    """
    Bytes -> Integer (z.B. b"Hi" wird eine Zahl).
    """
    return int.from_bytes(b, byteorder="big", signed=False)


def int_to_bytes(x: int) -> bytes:
    """
    Integer -> Bytes (Zahl zurück in Text-Bytes).
    """
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, byteorder="big", signed=False)


# ============================================================
# 3) RSA ENCRYPT (Aufgabe 3c.3)  c = m^e mod n
# ============================================================

def rsa_encrypt(pub: RSAPublicKey, message: bytes) -> int:
    """
    Verschlüsselt eine Nachricht (Bytes) mit Public Key (n,e).
    Ergebnis ist ein Integer-Chiffretext.
    """
    m_int = bytes_to_int(message)
    if m_int >= pub.n:
        raise ValueError("Nachricht zu groß für n (ohne Padding). Nutze kürzere Nachricht oder größeres n.")
    return pow(m_int, pub.e, pub.n)


# ============================================================
# 4) RSA DECRYPT (Aufgabe 3c.4)  m = c^d mod n
# ============================================================

def rsa_decrypt(priv: RSAPrivateKey, ciphertext_int: int) -> bytes:
    """
    Entschlüsselt Integer-Chiffretext mit Private Key (n,d).
    Gibt die ursprünglichen Bytes zurück.
    """
    m_int = pow(ciphertext_int, priv.d, priv.n)
    return int_to_bytes(m_int)


# ============================================================
# 5) SIGN (Aufgabe 3c.5)  sig = Hash(m)^d mod n
# ============================================================

def rsa_sign(priv: RSAPrivateKey, message: bytes) -> int:
    """
    Signiert eine Nachricht:
    1) Hash (SHA-256) berechnen
    2) Hash als Zahl darstellen
    3) Signatur = hash^d mod n
    """
    h_int = bytes_to_int(sha256_bytes(message))
    if h_int >= priv.n:
        raise ValueError("Hash ist größer als n. Nutze größeres n (z.B. 2048 Bit) oder passe die Darstellung an.")
    return pow(h_int, priv.d, priv.n)


# ============================================================
# 6) VERIFY (Aufgabe 3c.6)  prüfe: sig^e mod n == Hash(m)
# ============================================================

def rsa_verify(pub: RSAPublicKey, message: bytes, signature_int: int) -> bool:
    """
    Verifiziert eine Signatur:
    1) Hash der Nachricht berechnen
    2) Signatur mit Public Key "öffnen": recovered = sig^e mod n
    3) Vergleich: recovered == hash
    """
    h_int = bytes_to_int(sha256_bytes(message))
    recovered = pow(signature_int, pub.e, pub.n)
    return recovered == h_int


# ============================================================
# 7) TESTS (Aufgabe 3c.7)
# ============================================================

def run_tests() -> None:
    # 7.1 Schlüssel erzeugen
    print("== KeyGen ==")
    pub, priv = rsa_keygen(bits=1024)  # Demo: 1024 Bit; real >=2048
    print("Public Key (n, e):")
    print("n =", pub.n)
    print("e =", pub.e)
    print("Private Key d:")
    print("d =", priv.d)
    print()

    # 7.2 Nachricht und Hash
    message = b"Hallo Alice!"
    print("== Hash (SHA-256) ==")
    print("Message:", message)
    print("SHA-256:", sha256_hex(message))
    print()

    # 7.3 Encrypt / Decrypt Test
    print("== Encrypt / Decrypt ==")
    c = rsa_encrypt(pub, message)
    print("Ciphertext (int):", c)
    decrypted = rsa_decrypt(priv, c)
    print("Decrypted:", decrypted)
    print("Encrypt/Decrypt OK?:", decrypted == message)
    print()

    # 7.4 Sign / Verify Test
    print("== Sign / Verify ==")
    sig = rsa_sign(priv, message)
    print("Signature (int):", sig)

    ok_original = rsa_verify(pub, message, sig)
    print("Verify (original):", ok_original)

    # 7.5 Manipulationstest (Signatur muss fehlschlagen)
    tampered = b"Hallo Mallory!"
    ok_tampered = rsa_verify(pub, tampered, sig)
    print("Verify (manipulated message):", ok_tampered)
    print()

    # 7.6 "Harte" automatische Tests (Programm bricht ab, wenn etwas falsch ist)
    assert decrypted == message, "Entschlüsselung fehlgeschlagen!"
    assert ok_original is True, "Signaturprüfung (original) sollte True sein!"
    assert ok_tampered is False, "Signaturprüfung (manipuliert) sollte False sein!"
    print("Alle Tests erfolgreich.")


# Startpunkt: wenn Datei direkt ausgeführt wird, starte Tests
if __name__ == "__main__":
    run_tests()
