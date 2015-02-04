#!/usr/bin/python2.7

from string import ascii_lowercase
import sys
import re


###### HELPER FUNCTIONS ######

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

def getsubs(cipherwords, guess):
    """Takes a list or tuple of ciphertext words and a list or tuple which is
    the current guess, and returns a dictionary describing every substitution
    assumed by this guess. Does not perform any checks to make sure that the
    guess is internally consistent. Example:
    
    getsubs(['abb'], ['add']) -> {'a':'a', 'b':'d'}"""
    subs = {}

    for wordind in xrange(len(guess)):
        for letterind in xrange(len(guess[wordind])):
            subs[cipherwords[wordind][letterind]] = guess[wordind][letterind]
    
    return subs

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


###### BODY -- LOADING DICTIONARY FILE ######

dictfile = "/usr/share/dict/words"
patterns = {}

with open(dictfile, 'r') as f:
    for line in f:    # files are iterators!! python is so cool
        line = scrubstring(line)
        tup = getpatterntuple(line)
        
        if tup in patterns:
            # some words (e.g. its and it's) are identical after scrubbing, so
            # we're better off making sure we don't add them twice
            if line not in patterns[tup]:
                patterns[tup].append(line)
        else:
            patterns[tup] = [line]

print "Dictionary file loaded."


###### BODY -- CRACKING THE CODE ######

if len(sys.argv) < 2:
    ciphertext = "pf mmwpw skmms fjppf kkms" # same as in the blog's example
else:
    ciphertext = ' '.join(sys.argv[1:])

print "Ciphertext: " + ciphertext
print "Cracking..."

cipherlist = [scrubstring(word) for word in ciphertext.split(' ')
              if scrubstring(word) != '']

# each entry on the stack is a tuple of guessed plaintext words
# its initial entry, the empty tuple represents the search tree's root node
stack = [()]
possibilities = []

while stack:
    currguess = stack.pop()
    ind = len(currguess)
    
    if ind == len(cipherlist):
        # we've got a complete guess!!
        possibilities.append(currguess)
        
        if len(possibilities) >= 15:
            print "Possibilities abound! We're calling the search off early."
            break
        
        continue
    
    # our guess isn't full yet, so let's add to it however we can
    # first we make a dict describing all the substitutions we're assuming thus
    # far.
    
    subs = getsubs(cipherlist, currguess)
    regex = getregex(cipherlist[ind], subs)
    
    for guess in patterns[getpatterntuple(cipherlist[ind])]:
        if regex.match(guess):
            stack.append(currguess + (guess,))


###### BODY -- BOASTING OF OUR GLORIOUS SUCCESS ######

if len(possibilities) == 0:
    print "No answers found... Perhaps one of the plaintext words isn't in our dictionary?"
elif len(possibilities) == 1:
    print "We've got it!\n"
    print prettyprint(ciphertext, getsubs(cipherlist, possibilities[0]))
else:
    print "Yee dawgies!"
    print "We've got more possible solutions than we know what to do with."
    print "Here's %s of them:\n"%(len(possibilities),)
    
    for possibility in possibilities:
        print prettyprint(ciphertext, getsubs(cipherlist, possibility))

