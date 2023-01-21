import hashlib
import json
import math
import decimal
import uuid


##############################################################################################################################
###### SETTINGS:
# get text translations
with open('language_support/text_translations.json', 'r') as translations:
    CONFIG = json.load(translations)

# define language to be used for input descriptions and print statements
# per default German (de) and English (en) are available, but feel free to add more translations to the text_translations.json
language_code = "de"

##############################################################################################################################
###### HELPER:
# greatest common divisor
def gcD(p, q):
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


# Multiple Inverse:
def calc_multi_inverse(a, n):
    while math.gcd(a, n) > 1:
         print(CONFIG['helper_01'][language_code], a, CONFIG['helper_02'][language_code], n,CONFIG['helper_03'][language_code])
         b = 0
         return n, a, b
    b = 0
    h = 2
    while h!=1:
          b = b + 1
          h = a * b % n
    return b


# Calculate number of possible passwords for a certain number of characters
# z: number of characters in the alphabet, pw: password length
def number_possible_passwords(z, pw):
    number_passwords = z**pw
    print(CONFIG['helper_04'][language_code], number_passwords)

##############################################################################################################################
###### TRANSPOSITION:
def trans_encrypt(key, text):
    encrypted_text = ''
    key = key % 26
    for char in text:
        number = ord(char)
        new_number = number + key
        if new_number > ord('Z'):
            new_number = new_number - 26
        new_char = chr(new_number)
        encrypted_text = encrypted_text + new_char
    print(encrypted_text)

##############################################################################################################################
###### FIAT-SHAMIR:
# Fiat-Shamir
def fiat_shamir():
    k = int(decimal.Decimal(input(CONFIG['fs_input_01'][language_code])))
    n = int(decimal.Decimal(input(CONFIG['fs_input_02'][language_code])))
    v = int(decimal.Decimal(input(CONFIG['fs_input_03'][language_code])))
    s = int(decimal.Decimal(input(CONFIG['fs_input_04'][language_code])))
    x = k**2 % n
    print(CONFIG['fs_print_01'][language_code] , x, CONFIG['fs_print_02'][language_code])
    b = int(decimal.Decimal(input(CONFIG['fs_input_05'][language_code])))
    y = 0
    if b == 1:
        y = k*s % n
        print(CONFIG['fs_print_03'][language_code] , y)
        print(CONFIG['fs_print_04'][language_code], math.sqrt(x * calc_multi_inverse(v, n) % n))
    else:
        y = k % n
        print(CONFIG['fs_print_05'][language_code] , y)
        print(CONFIG['fs_print_06'][language_code], math.sqrt(x) % n)


# Attack on Fiat-Shamir
def fiat_shamir_attack():
    b = int(decimal.Decimal(input(CONFIG['fs_input_06'][language_code])))
    n = int(decimal.Decimal(input(CONFIG['fs_input_07'][language_code])))
    v = int(decimal.Decimal(input(CONFIG['fs_input_08'][language_code])))
    y = int(decimal.Decimal(input(CONFIG['fs_input_09'][language_code])))
    if b == 1:
        x = y**2 * v % 15
        print(CONFIG['fs_print_07'][language_code], x)
        print(CONFIG['fs_print_04'][language_code], math.sqrt(x * calc_multi_inverse(v, n) % n))
    else:
        x = y**2
        print(CONFIG['fs_print_08'][language_code] , x)
        print(CONFIG['fs_print_06'][language_code], math.sqrt(x) % n)


# Attack for same random number k on two different encrypted texts
def fiat_shamir_random(y1, y2, n):
    s = (y2 * calc_multi_inverse(y1, n)) % n
    print(CONFIG['fs_print_09'][language_code], s)
    
##############################################################################################################################
###### RSA:
def rsa_encrypt(n, e, x):
    y = x**e % n
    return y

	 
def rsa_decrypt(n, d, y):
    x = y**d % n
    return x


# calculate keys
def rsa_key(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = int(input(CONFIG['rsa_input_01'][language_code]))
    while math.gcd(e, phi_n) > 1:
        e += 1
    d = 0
    h = int(input(CONFIG['rsa_input_02'][language_code]))
    while h != 1:
        d += 1
        h = e * d % phi_n
    return n, e, d, phi_n


# calc private key 
def rsa_privatekey(e, phi_n):
    d = 0
    h = int(input(CONFIG['rsa_input_02'][language_code]))
    while h != 1:
        d += 1
        h = e * d % phi_n
    return d
     

# Will be needed to calculate private key from public key
def rsa_phi_n(n):
    amount = 0        
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount


# signature
def rsa_signature(x, d, n):
    s = x**d % n
    return s


# verification
def rsa_verifysignature(n, e, s):
     x = s**e % n
     return x


# blind signature
def rsa_blind_signature(x, e, n, d):
    r = int(decimal.Decimal(input(CONFIG['rsa_input_03'][language_code])))
    y = x * r**e % n
    print(CONFIG['rsa_print_01'][language_code] , y)
    y_signed = y**d % n
    print(CONFIG['rsa_print_02'][language_code]  , y_signed)
    r_inverse = calc_multi_inverse(r, n)
    msg_signed = y_signed * r_inverse % n
    print(CONFIG['rsa_print_03'][language_code]  , msg_signed)


# Chosen-Ciphertext-Attack on RSA-Encryption
def rsa_chosen_ciphertext(n, e, d, y3, x1):
    y1 = x1**e % n
    print(CONFIG['rsa_print_04'][language_code] , y1)
    y_inverse = calc_multi_inverse(y1, n) % n
    print(CONFIG['rsa_print_05'][language_code] , y_inverse)
    y2 = y3 * y_inverse % n
    print(CONFIG['rsa_print_06'][language_code] , y2)
    x2 = rsa_decrypt(n, d, y2)
    print(CONFIG['rsa_print_07'][language_code] , x2)
    x3 = x1 * x2
    print(CONFIG['rsa_print_08'][language_code] , x3)


# Attack on RSA-Signature
def rsa_attack_signature(x1, x3, n, d):
    x1_inverse = calc_multi_inverse(x1, n)
    print(CONFIG['rsa_print_09'][language_code] , x1_inverse)
    x2 = x3 * x1_inverse % n
    print("x2: " , x2)
    s1 = x1**d % n
    s2 = (x3 * x1_inverse)**d % n
    print("s1: " , s1 , ", s2: ", s2)
    s3 = s1 * s2 % n
    print(CONFIG['rsa_print_10'][language_code] , x3, ", ", s3)
    s_verify = x3**d % n
    print(CONFIG['rsa_print_11'][language_code], s3, ": " , s_verify)

##############################################################################################################################
###### ELGAMAL:
# calculate e from K(p, g, e)
def key_elgamal(g, d, p):
    e = g**d % p
    return e

	 
def elgamal_encrypt(p, g, e, k, x):
    a = g**k % p
    b = e**k * x % p
    return a,b


def elgamal_decrypt(p, d, a, b):
    h = a**d % p
    inverse = 0
    h1 = 2
    while h1 != 1:
        inverse = inverse + 1
        h1 = h * inverse % p
    y = b * inverse % p
    return y


# ElGamal Signature
def elgamal_signature(r, p, g, d):
    p_new = p - 1
    r_inverse = calc_multi_inverse(r, p_new)
    print(CONFIG['elgamal_print_01'][language_code], r_inverse)
    nb = g**r % p
    print(CONFIG['elgamal_print_02'][language_code], nb)
    m = int(decimal.Decimal(input(CONFIG['elgamal_input_01'][language_code])))
    s = (m - (d * nb))* r_inverse % p_new
    print(CONFIG['elgamal_print_03'][language_code], m,", ", nb,", ", s)
    

# Verfication
def elgamal_verify_signature(p, g, e, d, s, nb, r):
    print(CONFIG['elgamal_print_04'][language_code])
    m = (d * nb + r * s) % p
    gm = g**m % p
    enb = e**nb * nb**s % p
    print("g**m = e**nb * nb**s mod p: ", gm, " = ", enb, "?" )
    

# Known-Plaintext-Attack on ElGamal
def elgamal_known_plain(p, b1, b2):
    m2 = int(decimal.Decimal(input(CONFIG['elgamal_input_02'][language_code])))
    m1 = (b1 * calc_multi_inverse(b2, p) * m2) % p
    print(CONFIG['elgamal_print_05'][language_code], calc_multi_inverse(b2, p))
    print(CONFIG['elgamal_print_06'][language_code], m1)


# Chosen-Ciphertext-Attack on ElGamal
def elgamal_chosen_cipher(p, g, e, d, a, b):
    r = int(decimal.Decimal(input(CONFIG['elgamal_input_03'][language_code])))
    m1 = int(decimal.Decimal(input(CONFIG['elgamal_input_04'][language_code])))
    a_mod = (g**r * a) % p
    b_mod = (e**r * m1 * b) % p
    print(CONFIG['elgamal_print_07'][language_code], a_mod, ", ", b_mod)
    m2 = elgamal_decrypt(p, g, d, a_mod, b_mod)
    print(CONFIG['elgamal_print_08'][language_code], m2)
    m = (m2 * calc_multi_inverse(m1, p)) % p
    print(CONFIG['elgamal_print_09'][language_code], m)


# calculate random number k
def elgamal_random(p, g, a):
    k = 0
    h = 0
    while h != a:
        k += 1
        h = g**k % p
    return k


# calculate key
def elgamal_key_decrypt(p, g, e, k, d):
        x = g**d % p
        print(CONFIG['elgamal_print_10'][language_code], x)
        y = e**k % p
        print(CONFIG['elgamal_print_11'][language_code], y)
        a = g**k % p
        print(CONFIG['elgamal_print_12'][language_code], a)
	
##############################################################################################################################
###### ELLIPTIC CURVES:
# infinite number field
def point_addition_infinite(xp, yp, xq, yq):
    m = (yp - yq)/(xp - xq)
    print(CONFIG['ec_print_01'][language_code], m)
    xr = m**2 - xp - xq
    yr = yp * (-1) + m * (xp - xr)
    print("R(x, y) = (", xr, ", ", yr, ")")


def point_duplication_infinite(xp, yp):
    m = (3 * xp**2) / (2 * yp)
    print(CONFIG['ec_print_01'][language_code], m)
    b = yp - m*xp
    print("b = ", b)
    xr = m**2 - 2 * xp
    yr = yp * (-1) + m * (xp - xr)
    print("R(x, y) = (", xr, ", ", yr, ")")


# finite number field
def point_addition_finite(xp, yp, xq, yq, p):
     m = ((yp - yq)/(xp - xq)) % p
     print(CONFIG['ec_print_01'][language_code], m)
     xr = (m**2 - xp - xq) % p
     yr = (yp * (-1) + m * (xp - xr)) % p
     print("R(x, y) = (", xr, ", ", yr, ")")


def point_duplication_finite(xp, yp, p):
    m1 = ((3 * xp**2) + 1) % p
    m2 = (2 * yp) % p
    m = (m1 * calc_multi_inverse(m2, p)) % p
    print(CONFIG['ec_print_01'][language_code], m)
    xr = (m**2 - 2 * xp) % p
    yr = (yp * (-1) + m * (xp - xr)) % p
    print("R(x, y) = (", xr, ", ", yr, ")")
    xr = m**2 - 2 * xp % p
    yr = (yp * (-1) + m * (xp - xr)) % p
    return xr, yr


# Verification
def ec_verify(yr, xr, p):
    a = int(decimal.Decimal(input(CONFIG['ec_input_01'][language_code])))
    b = int(decimal.Decimal(input(CONFIG['ec_input_02'][language_code])))
    print("================================")
    t1 = yr**2 % p
    t2 = (xr**3 + a * xr + b) % p
    print(CONFIG['ec_print_02'][language_code], t1, " = ", t2, "?")


# Diffie-Hellman
def ec_diffie_hellman(xp, yp, p):
    Ak1 = point_duplication_finite(xp, yp, p)
    print(CONFIG['ec_print_03'][language_code], Ak1)
    print(CONFIG['ec_print_04'][language_code])
    print(CONFIG['ec_print_05'][language_code])
    print(CONFIG['ec_print_06'][language_code])
    print(CONFIG['ec_print_07'][language_code])

##############################################################################################################################
###### DIGITAL SIGNATURE ALGORITHM:
def dsa_signature(p, g, d, m):
    r = int(decimal.Decimal(input(CONFIG['dsa_input_01'][language_code])))
    hm = int(decimal.Decimal(input(CONFIG['dsa_input_02'][language_code])))
    nb = g**r % p
    print(input(CONFIG['dsa_print_01'][language_code], nb))
    r_invers = calc_multi_inverse(r, (p - 1))
    print(CONFIG['dsa_print_02'][language_code], r_invers)
    s = r_invers * (hm + d * nb) % (p - 1)
    print("s: ", s, CONFIG['dsa_print_03'][language_code], m, ", ", s, ", ", nb, ")")
    

def dsa_verify_signature(hm, s, p, g, e, nb):
    w = calc_multi_inverse(s, (p - 1)) % (p - 1)
    u1 = (w * hm) % (p - 1)
    u2 = (w * nb) % (p - 1)
    print("w: ", w, ", u1: ", u1, ", u2: ", u2)
    s_verify = ((g**u1) * (e**u2)) % p
    print(CONFIG['dsa_print_04'][language_code], nb, " = ", s_verify, "?")


def dsa_angriff(s1, s2, p, nb):
    hm1 = int(decimal.Decimal(input(CONFIG['dsa_input_03'][language_code])))
    hm2 = int(decimal.Decimal(input(CONFIG['dsa_input_04'][language_code])))
    r = ((hm1 - hm2) / (s1 - s2 )) % (p - 1)
    print(CONFIG['dsa_print_05'][language_code], r)
    d = ((s1 * r - hm1 ) * calc_multi_inverse(nb, (p - 1))) % (p - 1)
    print(CONFIG['dsa_print_06'][language_code], d)
    
# Elliptic Curve Digital Signature Algorithm
def ec_dsa(x, p, r, d, m):
    nb = x % p
    print(CONFIG['dsa_print_01'][language_code], nb)
    hm1 = int(decimal.Decimal(input(CONFIG['dsa_input_03'][language_code])))
    r_inverse = calc_multi_inverse(r, p)
    print(CONFIG['dsa_print_02'][language_code], r_inverse)
    s = (r_inverse * (hm1 + d * nb)) % p
    print(str(CONFIG['dsa_print_03'][language_code]).strip(', '), m, ", ", s, ", ", nb, ")")
    
    
def ec_dsa_verification(hm, s, p, nb):
    w = calc_multi_inverse(s, p) % (p - 1)
    u1 = (w * hm) % p
    u2 = (w * nb) % p
    print("w: ", w, ", u1: ", u1, ", u2: ", u2)
    x = int(decimal.Decimal(input(CONFIG['dsa_input_05'][language_code])))
    t = x % p
    print(CONFIG['dsa_print_04'][language_code], t, " = ", nb, "?")

##############################################################################################################################
###### PASSWORD HASHING:
def hash_only_password():
    password = input(CONFIG['pwhash_input_01'][language_code])
    hashed_password = hashlib.sha512(password.encode()).hexdigest()
    print(CONFIG['pwhash_print_01'][language_code], hashed_password)
    print("================================")
    i = 1
    while i <= 3 :   
       compare_pw = input(CONFIG['pwhash_input_02'][language_code])
       i += 1
       if password == compare_pw:
           print(CONFIG['pwhash_print_02'][language_code])
           print("================================")
           break
       else:
           print(CONFIG['pwhash_print_03'][language_code])
     

def hash(password):
    salt=uuid.uuid4().hex
    return hashlib.sha512(salt.encode() + password.encode()).hexdigest() + ":" + salt , salt


def hash_password_salted():
    password = input(CONFIG['pwhash_input_01'][language_code])
    hashed_password , salt = hash(password)
    print(CONFIG['pwhash_print_01'][language_code] , hashed_password ,CONFIG['pwhash_print_04'][language_code] , salt)
    print("================================")
    i = 1
    while i <= 3 :   
       compare_pw = input(CONFIG['pwhash_input_01'][language_code])
       i += 1
       if password == compare_pw:
           print(CONFIG['pwhash_print_02'][language_code])
           print("================================")
           break
       else:
           print(CONFIG['pwhash_print_03'][language_code])


def sha_pwd_hash():
   password = input(CONFIG['pwhash_input_03'][language_code])
   print("================================")
   x=['md5','sha1','sha256', 'sha384', 'sha512']
   for x in x:
      hash = hashlib.new(x)
      hash.update(password.encode())
      print(CONFIG['pwhash_print_05'][language_code], x, "  ", hash.hexdigest())
      print(CONFIG['pwhash_print_05'][language_code], x, CONFIG['pwhash_print_07'][language_code], hash.digest_size * 8 , CONFIG['pwhash_print_08'][language_code])

##############################################################################################################################
###### POLLARD-RHO:
def pollard_rho () :
   n=int(decimal.Decimal(input(CONFIG['pr_input_01'][language_code]))) 
   count = 0
   x = 2
   y = 2
   d = 1
   while d<=1:
       x = ( x * x + 23) % n
       print(CONFIG['pr_print_01'][language_code], x)
       y = ( y * y + 23) % n
       y = ( y * y + 23) % n
       print(CONFIG['pr_print_02'][language_code], y)
       print("x - y: ", x - y)
       d = math.gcd (x - y, n)    
       count += 1
       print(CONFIG['pr_print_03'][language_code], d)
       print(CONFIG['pr_print_04'][language_code], count)
       print("================================")

##############################################################################################################################
###### FERMAT:
def factorize_fermat(n):
   x = math.ceil(math.sqrt(n))
   print(CONFIG['fermat_print_01'][language_code], x)
   print ("================================")
   y = x**2 - n
   print(CONFIG['fermat_print_02'][language_code], y)
   while not math.sqrt(y).is_integer():
      x += 1
      y = x**2 - n
      print(CONFIG['fermat_print_03'][language_code], x, CONFIG['fermat_print_04'][language_code], y)
      print(CONFIG['fermat_print_05'][language_code], math.sqrt(y))
   print("x + sqrt(y) ", x + math.sqrt(y), ", x - math.sqrt(y): ", x - math.sqrt(y))
     
	
def trial_factorization(n):
   p = 2
   while p <= math.sqrt(n) :
         if n % p == 0:
            n //= p
            print (CONFIG['fermat_print_06'][language_code], n)
            return (p)
         else:
            p +=1
   n = int(decimal.Decimal(input(CONFIG['pr_input_01'][language_code])))
   print ("================================")
   print (CONFIG['fermat_print_07'][language_code], p)

##############################################################################################################################
###### OTHER:
# Shamir's No-Key-Protokoll
def shamir_no_key(p, a, b, x):
    y1 = (x**a) % p
    print(CONFIG['nokey_print_01'][language_code], y1)
    y2 = (y1**b) % p
    print(CONFIG['nokey_print_02'][language_code], y2)
    y3 = (y2**calc_multi_inverse(a, (p - 1))) % p
    print(CONFIG['nokey_print_03'][language_code], y3)
    k = (y3**calc_multi_inverse(b, (p - 1))) % p
    print(CONFIG['nokey_print_04'][language_code], k)