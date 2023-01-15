# get text translations
import json

with open('language_support/text_translations.json', 'r') as translations:
    CONFIG = json.load(translations)

# define language to be used for input descriptions and print statements
# per default German (de) and English (en) are available, but feel free to add more translations to the text_translations.json
language_code = "de"

def caesar_bruteforce():
    encrypted_text = input(CONFIG['caesar_input'][language_code])
    dict = {
        'A':0 , 'B':1, 'C':2,'D':3, 'E':4, 'F':5, 'G':6, 'H':7, 'I':8, 'J':9, 'K':10, 'L':11, 'M':12, 'N':13, 'O':14, 'P':15, 'Q':16, 'R':17, 'S':18, 'T':19, 'U':20, 'V':21, 'W':22, 'X':23, 'Y':24, 'Z':25
        }
    # loop through all possible keys 0-25 (alphabeth without Umlaute)
    key = 0
    while key < 26:
        clear = ""
        for char in encrypted_text.upper():
            if not char in [" ", ",", ".", "!", "?", "(", ")", "Ä", "Ö", "Ü", ";", ":", "-", "+", "*"]:
                current = str(dict[char])
                clear += (list(dict.keys()))[(int(current) - key) % 26]
            else:
                clear += char
        key += 1
        print(CONFIG['caesar_print_01'][language_code], key, CONFIG['caesar_print_02'][language_code], clear)
    

caesar_bruteforce()