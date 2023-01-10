def caesar_bruteforce():
    verschluesselter_text = input("Verschlüsselten Text eingeben:")
    dict = {
        'A':0 , 'B':1, 'C':2,'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8, 'J':9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16, 'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24, 'Z':25
        }
    keys = dict.keys()
    # loope durch alle möglichen Schlüssel 0-25 (Alphabet ohne Umlaute)
    key = 0
    for key in range(0, 25):
        klar = ""
        for buchstabe in verschluesselter_text.upper():
            current = str(dict[buchstabe])
            klar += (list(keys))[(int(current) - key) % 26]
        print("Wenn der Schlüssel ", key, " ist, ist der entschlüsselte Text ", klar)
    

caesar_bruteforce()