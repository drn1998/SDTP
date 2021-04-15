import re

def is_vowel(char):
    vowels = ['a','e','i','o','u','y','ä','ü','ö']
    return char in vowels

def count_syllables(word):
    syl_n = 0
    in_vowel = False
    
    for i in range(len(word)):
        if is_vowel(word[i]):
            if not in_vowel:
                syl_n = syl_n + 1
            in_vowel = True
        else:
            in_vowel = False
    
    return syl_n

corpus = "Beispieltext. Später durch Textdatei."

regex = re.compile('[^a-zäüöß ]')
corpus = regex.sub('', corpus.lower())

words = corpus.split(" ")

for i, word in enumerate(words):
    r = count_syllables(word)
    if r > 2:
        print('+', end="")
    else:
        print(r, end="")
    
    if(i%3 == 2):
        print("")