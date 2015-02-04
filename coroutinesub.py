#!/usr/bin/python2.7

"""
This is a piece of code which takes from the command line a string encrypted
with a general substitution cipher and attempts to decrypt it. The program
logic is implemented using coroutines. A good introduction, should you need
one, to how coroutines work in Python can be found at
www.dabeaz.com/coroutines/Coroutines.pdf

Basically we define a coroutine which at declaration takes as arguments a
ciphertext word and another coroutine, which it'll send its guesses for the
substitution alphabet on to.

The coroutine takes guesses at the substitution dictionary, works out guesses
for its word given the assumption that the substitution dictionary is correct,
and pushes forward updated guesses at the substitution dict based on its word.

What this allows us to do is set up the entire guessing algorithm as a chain of
coroutines, push an empty guess in one end, and get all plausible sets of
substitutions out on the other end.

The endpoint for this chain is an aggregator which takes complete guess sets,
tracks what is and isn't certain, and prints out all of this on GeneratorExit.

The decision to print only on GeneratorExit may seem odd, but for our purposes,
where we only need to get our conjectured decipherment once, at program end, it
is sufficient. It would be trivial to write an alternate endpoint, if different
behavior is needed.

For further details, see the functions' individual docstrings.

I think this is a really cool and straightforward way to implement this logic.
Comments or improvements are invited.
"""

from string import ascii_lowercase
import re
from copy import copy
import argparse 

def coroutine(f):
    """Decorator for coroutines."""
    def start(*args, **kwargs):
        cr = f(*args, **kwargs)
        cr.next()
        return cr
    return start

def scrubstring(s):
    """Takes a string, s, and returns that string after conversion to lowercase
    and with all characters not present in ascii_lowercase removed. Examples:
    
    'Test!!' -> 'test'
    'I'm' -> 'im'
    'Don't use multiple words...' -> 'dontusemultiplewords'"""
    
    return ''.join(ch for ch in s.lower() if ch in ascii_lowercase)

def getpatterntuple(word):
    """Takes a string and returns a tuple which retains only character
    repetition info. Examples:
    'word'  -> (1, 2, 3, 4)
    'all'   -> (1, 2, 2)
    'llama' -> (1, 1, 2, 3, 2)"""
    
    word = word.lower()
    
    letters = {}
    tup = ()
    
    for letter in word:
        if letter in letters:
            tup += (letters[letter],)
        else:
            letternum = len(letters) + 1
            tup += (letternum,)
            letters[letter] = letternum
    
    return tup

def getregex(cipherword, subs):
    """Given a ciphertext word and a dictionary of ciphertext-to-plaintext
    substitutions, returns a regex that matches all and only those words which,
    given additionally that their letter repetition patterns are correct, could
    be the plaintext. That's a tricky explanation, so here's an example:
    
    getregex('skmms', {'m':'l'}) returns a regex which would match any five-
    letter word that has Ls where 'skmms' has Ms. So for example, it would
    match 'sells', 'sills', or 'balls' (even though it doesn't fit the letter
    repetition pattern). The regex would not, however, match e.g. 'shoos'."""
    
    if len(subs) > 0:
        wildcard = "[^"+"".join(str(n) for n in subs.values())+"]"
    else:
        wildcard = "."
    
    regex = "".join(wildcard if ch not in subs else subs[ch] for ch in cipherword)
    return re.compile("^%s$"%(regex,))

def prettyprint(ciphertext, substitutions):
    """Takes a dictionary of substitutions and performs them to the original
    ciphertext, allowing us to serve up a result which isn't scrubbed of all
    punctuation. This string is fit to print, but the function doesn't actually
    print it."""
    
    ans = ""
    for ch in ciphertext:
        if ch.lower() in substitutions:
            if ch in ascii_lowercase:
                ans += substitutions[ch]
            else:
                ans += substitutions[ch.lower()].upper()
        else:
            ans += ch
    
    return ans

@coroutine
def guesser(cipherword, patterns, target):
    """Coroutine. Takes a cipherword, a list of plaintext words which have the
    same pattern tuple as the cipherword, and a target. When sent a guess for
    what part of the substitution dictionary might be, works out all
    conjectures for the decryption of its cipherword which match with this
    guessed dictionary, then sends off to target an updated guess dictionary
    containing any new substitutions gleaned from the conjectured plaintext
    words."""
    
    while True:
        guess = (yield)
        regex = getregex(cipherword, guess)
        
        for plainword in patterns:
            if regex.match(plainword):
                newguess = copy(guess)
                
                for i in xrange(len(cipherword)):
                    newguess[cipherword[i]] = plainword[i]
                target.send(newguess)

@coroutine
def guesscollector(originalciphertext):
    """Aggregator for guesses. If there is more than one guess for any letter,
    then that letter is considered unknown. Prints out a conjectured (possibly
    partial) decryption upon receiving GeneratorExit."""
    
    try:
        possibilities = {letter : set() for letter in ascii_lowercase}
        
        while True:
            guess = (yield)
            for cipherletter in guess:
                possibilities[cipherletter].add(guess[cipherletter])
    
    except GeneratorExit:
        finaldict = {}
        for cipherletter in possibilities:
            n = len(possibilities[cipherletter])
            if n == 0:
                continue
            elif n == 1:
                finaldict[cipherletter] = possibilities[cipherletter].pop()
            else:
                finaldict[cipherletter] = '_'
        
        print prettyprint(originalciphertext, finaldict)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt instead of decrypting. Useful for making test cases.")
    parser.add_argument("text", help="Text to decrypt (or encrypt)")
    parser.add_argument("-d", "--dictfile", nargs="?",
                        default="/usr/share/dict/words")
    args = parser.parse_args()
    
    text = args.text
    if args.encrypt:
        import random
        letters = list(ascii_lowercase)
        random.shuffle(letters)
        cipher = {ascii_lowercase[i] : letters[i] for i in xrange(len(letters))}
        print prettyprint(text, cipher)
    
    else:
        # it's showtime
        cipherlist = [scrubstring(word) for word in text.split(' ') 
                      if scrubstring(word) != '']
    
        patterns = {getpatterntuple(word) : [] for word in cipherlist}
    
        with open(args.dictfile, 'r') as f:
            for line in f:
                line = scrubstring(line)
                tup = getpatterntuple(line)
                
                if tup in patterns:  # we only record patterns we'll need
                    if line not in patterns[tup]:
                        patterns[tup].append(line)
        
        # sorting our list like this reduces the search tree's branching factor
        # because it ensures words with more possible guesses come up first in
        # our chain creation loop & therefore get placed closer to the end of
        # the chain, where more of their guesses can be weeded out
        cipherlist.sort(lambda a,b : len(patterns[getpatterntuple(b)]) - 
                                     len(patterns[getpatterntuple(a)]))
        
        target = guesscollector(text)
        for word in cipherlist:
            target = guesser(word, patterns[getpatterntuple(word)], target)

        target.send({})
        target.close()

