import hashlib
import math
from math import gcd
import decimal
import uuid


###### HELPER:
# größter gemeinsamer Teiler
def ggT(p, q):
    rest = 1
    while rest != 0: 
        if p >= q:
            rest = p % q
            p = q
            q = rest
            ggt = p
        else:
            rest = q % p
            q = p
            p = rest
            ggt=q
    return ggt


# Multiple Inverse berechnen:
def calc_multi_inverse(a, n):
    while math.gcd(a, n) > 1:
         print("Die Zahlen ", a, " und ", n, " sind nicht teilerfremd")
         b = 0
         return n, a, b
    b = 0
    h = 2
    while h!=1:
          b = b + 1
          h = a * b % n
    return b


# Berechne Anzahl möglicher Passwörter für eine bestimmte Passwortlänge
# z: Anzahl der Zeichen im Alphabet, pw: Passwortlänge
def anzahl_moeglicher_passwoerter(z, pw):
    anzahl_pw = z**pw
    print("Anzahl möglicher Passwörter: ", anzahl_pw)

##############################################################################################################################
###### CAESAR:
# Caesar-Verschlüsselung
def ceasar_encrypt(key, text):
    verschluesselter_text = ''
    key = key % 26
    for zeichen in text:
        zahl = ord(zeichen)
        neue_zahl = zahl + key
        if neue_zahl > ord('Z'):
            neue_zahl = neue_zahl - 26
        neuesZeichen = chr(neue_zahl)
        verschluesselter_text = verschluesselter_text + neuesZeichen
    print(verschluesselter_text)

##############################################################################################################################
###### FIAT-SHAMIR:
# Fiat-Shamir
def fiat_shamir():
    k = int(decimal.Decimal(input("Eingabe Zufallszahl k = ")))
    n = int(decimal.Decimal(input("Eingabe öffentlicher Schlüssel n = ")))
    v = int(decimal.Decimal(input("Eingabe öffentlicher Schlüssel v = ")))
    s = int(decimal.Decimal(input("Eingabe privater Schlüssel s = ")))
    x = k**2 % n
    print("Bob sendet x mit Wert " , x, " an Alice ")
    b = int(decimal.Decimal(input("Eingabe Zufallsbit b = ")))
    y = 0
    if b == 1:
        y = k*s % n
        print("Für Zufallsbit = 1 ist der Wert für y " , y)
        print("Verifikation: y^2 = x * v(invers) mod n -> y = ", math.sqrt(x * calc_multi_inverse(v, n) % n))
    else:
        y = k % n
        print("Für Zufallsbit = 0 ist der Wert für y " , y)
        print("Verifikation: y^2 = x mod n -> y = ", math.sqrt(x) % n)


# Angriff auf Fiat-Shamir
def fiat_shamir_angriff():
    b = int(decimal.Decimal(input("Errate Zufallsbit b = ")))
    n = int(decimal.Decimal(input("Eingabe öffentlicher Schlüssel n = ")))
    v = int(decimal.Decimal(input("Eingabe öffentlicher Schlüssel v = ")))
    y = int(decimal.Decimal(input("Wähle y = ")))
    if b == 1:
        x = y**2 * v % 15
        print("Für Zufallsbit = 1 sende den Wert für x " , x)
        print("Verifikation: y^2 = x * v(invers) mod n -> y = ", math.sqrt(x * calc_multi_inverse(v, n) % n))
    else:
        x = y**2
        print("Für Zufallsbit = 0 sende den Wert für x " , x)
        print("Verifikation: y^2 = x mod n -> y = ", math.sqrt(x) % n)


# Angriff bei gleicher Zufallszahl k für 2 verschiedene Geheimtexte
def fiat_shamir_angriff_zufall(y1, y2, n):
    s = (y2 * calc_multi_inverse(y1, n)) % n
    print("Berechneter Schlüssel s: ", s)
    
##############################################################################################################################
###### RSA:
def rsa_encrypt(n, e, x):
    y = x**e % n
    return y

	 
def rsa_decrypt(n, d, y):
    x = y**d % n
    return x


# Schlüsselberechnung
def rsa_key(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = int(input("Zahl für e: "))
    while math.gcd(e, phi_n) > 1:
        e += 1
    d = 0
    h = int(input("Zahl für h: "))
    while h != 1:
        d += 1
        h = e * d % phi_n
    return n, e, d, phi_n


# Privaten Schlüssel berechnen	 
def rsa_privatekey(e, phi_n):
    d = 0
    h = int(input("Zahl für h: "))
    while h != 1:
        d += 1
        h = e * d % phi_n
    return d
     

# Wird gebraucht um aus dem Public Key den privaten Schlüssel zu berechnen
def rsa_phi_n(n):
    amount = 0        
    for k in range(1, n + 1):
        if gcd(n, k) == 1:
            amount += 1
    return amount


# Signatur
def rsa_signature(x, d, n):
    s = x**d % n
    return s


# Verifizierung
def rsa_verifysignature(n, e, s):
     x = s**e % n
     return x


# Blinde Signatur
def rsa_blind_signature(x, e, n, d):
    r = int(decimal.Decimal(input("Wähle Zufallszahl r = ")))
    y = x * r**e % n
    print("Alice berechnet Wert y=" , y)
    y_signiert = y**d % n
    print("Signiertes Dokument von Bob: " , y_signiert)
    r_invers = calc_multi_inverse(r, n)
    nachricht_signiert = y_signiert * r_invers % n
    print("Signierte Nachricht: " , nachricht_signiert)

# Chosen-Ciphertext-Angriff auf RSA-Verschlüsselung
def rsa_chosen_ciphertext(n, e, d, y3, x1):
    y1 = x1**e % n
    print("x1 Verschlüsselt (y1) " , y1)
    y_invers = calc_multi_inverse(y1, n) % n
    print("Inverses von y1" , y_invers)
    y2 = y3 * y_invers % n
    print("Mit Tarnung (y2): " , y2)
    x2 = rsa_decrypt(n, d, y2)
    print("Zu y2 gehörender Klartext x2 " , x2)
    x3 = x1 * x2
    print("Zu Chosen-Ciphertext y3 gehörender Klartext: " , x3)


# Angriff auf RSA-Signatur
def rsa_angriff_auf_signature(x1, x3, n, d):
    x1_invers = calc_multi_inverse(x1, n)
    print("Inverse von x1 " , x1_invers)
    x2 = x3 * x1_invers % n
    print("x2: " , x2)
    s1 = x1**d % n
    s2 = (x3 * x1_invers)**d % n
    print("s1: " , s1 , ", s2: ", s2)
    s3 = s1 * s2 % n
    print("Gültiges Signaturepaar (x, y) " , x3, ", ", s3)
    s_verify = x3**d % n
    print("Verifikation für Signatur ", s3, ": " , s_verify)

##############################################################################################################################
###### ELGAMAL:
# Berechne e aus K(p, g, e)
def key_elgamal(g, d, p):
    e = g**d % p
    return e

	 
def elgamal_encrypt(p, g, e, k, x):
    a = g**k % p
    b = e**k * x % p
    return a,b


def elgamal_decrypt(p, d, a, b):
    h = a**d % p
    invers = 0
    h1 = 2
    while h1 != 1:
        invers = invers + 1
        h1 = h * invers % p
    y = b * invers % p
    return y


# ElGamal Signatur
def elgamal_signature(r, p, g, d):
    p_neu = p - 1
    r_invers = calc_multi_inverse(r, p_neu)
    print("Inverse von r: ", r_invers)
    nb = g**r % p
    print("Nachrichtenbezeichner: ", nb)
    m = int(decimal.Decimal(input("Wähle Nachricht m = ")))
    s = (m - (d * nb))* r_invers % p_neu
    print("Signierte Nachricht von Alice (m, nb, s): ", m,", ", nb,", ", s)
    

# Verifizierung
def elgamal_verify_signature(p, g, e, d, s, nb, r):
    print("Verifikation (Bob): ")
    m = (d * nb + r * s) % p
    gm = g**m % p
    enb = e**nb * nb**s % p
    print("g**m = e**nb * nb**s mod p: ", gm, " = ", enb, "?" )
    

# Known-Plaintext-Angriff auf ElGamal
def elgamal_known_plain(p, b1, b2):
    m2 = int(decimal.Decimal(input("Nachricht 2 (m2) = ")))
    m1 = (b1 * calc_multi_inverse(b2, p) * m2) % p
    print("Inverse zu b2: ", calc_multi_inverse(b2, p))
    print("Klartext m1: ", m1)


# Chosen-Ciphertext-Angriff auf ElGamal
def elgamal_chosen_cipher(p, g, e, d, a, b):
    r = int(decimal.Decimal(input("Wähle Zufallszahl r = ")))
    m1 = int(decimal.Decimal(input("Wähle beliebige Nachricht m1 = ")))
    a_mod = (g**r * a) % p
    b_mod = (e**r * m1 * b) % p
    print("Verschlüsseltes m1 (modifiziert): ", a_mod, ", ", b_mod)
    m2 = elgamal_decrypt(p, g, d, a_mod, b_mod)
    print("Entschlüsseltes m2: ", m2)
    m = (m2 * calc_multi_inverse(m1, p)) % p
    print("Klartext zu Geheimtext (a, b): ", m)


# Zufallszahl k in ElGamal berechnen
def elgamal_zufall(p, g, a):
    k = 0
    h = 0
    while h != a:
        k += 1
        h = g**k % p
    return k


# Schlüssel berechnen
def elgamal_key_decrypt(p, g, e, k, d):
        x = g**d % p
        print("Zwischenwert x: ", x)
        y = e**k % p
        print("Sitzungsschlüssel K: ", y)
        a = g**k % p
        print("Schlüsselwert: ", a)
	
##############################################################################################################################
###### ELLIPTIC CURVES:
# Unendlicher Zahlenkörper
def punkt_addition_unendlich(xp, yp, xq, yq):
    m = (yp - yq)/(xp - xq)
    print("Steigung m= ", m)
    xr = m**2 - xp - xq
    yr = yp * (-1) + m * (xp - xr)
    print("R(x, y) = (", xr, ", ", yr, ")")


def punkt_verdopplung_unendlich(xp, yp):
    m = (3 * xp**2) / (2 * yp)
    print("Steigung m: ", m)
    b = yp - m*xp
    print("b = ", b)
    xr = m**2 - 2 * xp
    yr = yp * (-1) + m * (xp - xr)
    print("R(x, y) = (", xr, ", ", yr, ")")


# Endlicher Zahlenkörper
def punkt_addition_endlich(xp, yp, xq, yq, p):
     m = ((yp - yq)/(xp - xq)) % p
     print("Steigung m= ", m)
     xr = (m**2 - xp - xq) % p
     yr = (yp * (-1) + m * (xp - xr)) % p
     print("R(x, y) = (", xr, ", ", yr, ")")


def punkt_verdopplung_endlich(xp, yp, p):
    m1 = ((3 * xp**2) + 1) % p
    m2 = (2 * yp) % p
    m = (m1 * calc_multi_inverse(m2, p)) % p
    print("Steigung m: ", m)
    xr = (m**2 - 2 * xp) % p
    yr = (yp * (-1) + m * (xp - xr)) % p
    print("R(x, y) = (", xr, ", ", yr, ")")
    xr = m**2 - 2 * xp % p
    yr = (yp * (-1) + m * (xp - xr)) % p
    return xr, yr


# Verifizierung
def ec_verify(yr, xr, p):
    a = int(decimal.Decimal(input("a aus x^3 + ax + b (gib 1 an, falls nicht vorhanden) ")))
    b = int(decimal.Decimal(input("b aus x^3 + ax + b (gib 0 an, falls nicht vorhanden) ")))
    print("================================")
    t1 = yr**2 % p
    t2 = (xr**3 + a * xr + b) % p
    print("Verifikation: ", t1, " = ", t2, "?")


# Diffie-Hellman
def ec_diffie_hellman(xp, yp, p):
    Ak1 = punkt_verdopplung_endlich(xp, yp, p)
    print("Einmalige Punktverdopplung Ak1: ", Ak1)
    print("Wiederhole bis a = 0 falls a eine gerade Zahl ist: a = a-1 für jede Verdopplung -> Bsp: 4P = 2P + 2P -> 3 Verdopplungen")
    print("Wiederhole bis a = 0 falls a eine gerade Zahl ist: a = a-1 für jede Verdopplung -> Bsp: 5P = 2P + 2P + P -> 3 Verdopplungen und eine Addition")
    print("Wiederhole für b und erhalte Bk")
    print("Alice sendet dann Bk*a, Bob berechnet Ak*b")

##############################################################################################################################
###### DIGITAL SIGNATURE ALGORITHM:
def dsa_signature(p, g, d, m):
    r = int(decimal.Decimal(input("Wähle Zufallszahl r = ")))
    hm = int(decimal.Decimal(input("Hashwert von m = ")))
    nb = g**r % p
    print("Nachrichtenbezeichner nb: ", nb)
    r_invers = calc_multi_inverse(r, (p - 1))
    print("Inverse von r: ", r_invers)
    s = r_invers * (hm + d * nb) % (p - 1)
    print("s: ", s, ", Signatur (m, s, nb): (", m, ", ", s, ", ", nb, ")")
    

def dsa_verify_signature(hm, s, p, g, e, nb):
    w = calc_multi_inverse(s, (p - 1)) % (p - 1)
    u1 = (w * hm) % (p - 1)
    u2 = (w * nb) % (p - 1)
    print("w: ", w, ", u1: ", u1, ", u2: ", u2)
    s_verify = ((g**u1) * (e**u2)) % p
    print("Verifikation: ", nb, " = ", s_verify, "?")


def dsa_angriff(s1, s2, p, nb):
    hm1 = int(decimal.Decimal(input("Hashwert von m1 = ")))
    hm2 = int(decimal.Decimal(input("Hashwert von m2 = ")))
    r = ((hm1 - hm2) / (s1 - s2 )) % (p - 1)
    print("Zufallswert r berechnet: ", r)
    d = ((s1 * r - hm1 ) * calc_multi_inverse(nb, (p - 1))) % (p - 1)
    print("Errechneter privater Schlüssel d: ", d)
    
# Elliptic Curve Digital Signature Algorithm
def ec_dsa(x, p, r, d, m):
    nb = x % p
    print("Nachrichtenbezeichner nb: ", nb)
    hm1 = int(decimal.Decimal(input("Hashwert von m1 = ")))
    r_invers = calc_multi_inverse(r, p)
    print("Inverse von r: ", r_invers)
    s = (r_invers * (hm1 + d * nb)) % p
    print("Signatur (m, s, nb): (", m, ", ", s, ", ", nb, ")")
    
    
def ec_dsa_verifikation(hm, s, p, nb):
    w = calc_multi_inverse(s, p) % (p - 1)
    u1 = (w * hm) % p
    u2 = (w * nb) % p
    print("w: ", w, ", u1: ", u1, ", u2: ", u2)
    x = int(decimal.Decimal(input("x-Wert aus u1 * P + u2 * Q mod p = ")))
    t = x % p
    print("Verifikation: ", t, " = ", nb, "?")

##############################################################################################################################
###### PASSWORD HASHING:
def hash_only_password():
    passwort = input("Zu hashendes Passwort: ")
    hashed_passwort = hashlib.sha512( passwort.encode()).hexdigest()
    print('Hash-Wert: ' , hashed_passwort)
    print("================================")
    i = 1
    while i <= 3 :   
       vergleich_passwort = input("Zum Vergleich Passwort erneut eingeben: ")
       i += 1
       if passwort == vergleich_passwort:
           print("Das Passwort war korrekt!")
           print("================================")
           break
       else:
           print("Die Passwörter stimmen nicht überein")
     

def hash(password):
    salt=uuid.uuid4().hex
    return hashlib.sha512(salt.encode() + password.encode()).hexdigest() + ":" + salt , salt


def hash_password_salted():
    passwort = input("Zu hashendes Passwort:  ")
    hashed_passwort , salt = hash(passwort)
    print('Hash-Wert: ' , hashed_passwort , "mit Salt: " , salt)
    print("================================")
    i = 1
    while i <= 3 :   
       vergleich_passwort = input("Zum Vergleich Passwort erneut eingeben: ")
       i += 1
       if passwort == vergleich_passwort:
           print("Das Passwort war korrekt!")
           print("================================")
           break
       else:
           print("Die Passwörter stimmen nicht überein")


def sha_pwd_hash():
   passwort = input("Passwort: ")
   print("================================")
   x=['md5','sha1','sha256', 'sha384', 'sha512']
   for x in x:
      hash = hashlib.new(x)
      hash.update(passwort.encode())
      print("Gehashtes Passwort nach" , x, "  ", hash.hexdigest())
      print("Gehashtes Passwort nach" , x," hat ", hash.digest_size * 8 , "Bit Länge \n")

##############################################################################################################################
###### POLLARD-RHO:
def pollard_rho () :
   n=int(decimal.Decimal(input("Modul n: "))) 
   count = 0
   x = 2
   y = 2
   d = 1
   while d<=1:
       x = ( x * x + 23) % n
       print("Zufallszahl x: ", x)
       y = ( y * y + 23) % n
       y = ( y * y + 23) % n
       print("Zufallszahl y: ", y)
       print("x - y: ", x - y)
       d = math.gcd (x - y, n)    
       count += 1
       print("ggT(x - y, n)-> p: ", d)
       print("Durchlauf: ", count)
       print("================================")

##############################################################################################################################
###### FERMAT:
def factorize_fermat(n):
   x = math.ceil(math.sqrt(n))
   print("Startwert x: ", x)
   print ("================================")
   y = x**2 - n
   print("y zum Startwert x: ", y)
   while not math.sqrt(y).is_integer():
      x += 1
      y = x**2 - n
      print("Aktuelles x: ", x, ", aktuelles y: ", y)
      print("y ist eine Quadratzahl? -> ", math.sqrt(y))
   print("x + sqrt(y) ", x + math.sqrt(y), ", x - math.sqrt(y): ", x - math.sqrt(y))
     
	
def trial_factorization(n):
   p = 2
   while p <= math.sqrt(n) :
         if n % p == 0:
            n //= p
            print ("Faktor 1 = ", n)
            return (p)
         else:
            p +=1
   n = int(decimal.Decimal(input("Modul: ")))
   print ("================================")
   print ("Faktor 2 = ", p)

##############################################################################################################################
###### ANDERE:
# Shamir's No-Key-Protokoll
def shamir_no_key(p, a, b, x):
    y1 = (x**a) % p
    print("Alice sendet y1 an Bob: ", y1)
    y2 = (y1**b) % p
    print("Bob sendet y2 an Alice: ", y2)
    y3 = (y2**calc_multi_inverse(a, (p - 1))) % p
    print("Alice sendet y3 an Bob: ", y3)
    k = (y3**calc_multi_inverse(b, (p - 1))) % p
    print("Von Bob errechnete Nachricht: ", k)