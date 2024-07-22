
Generating a BIP39 Mnemonic Seed Manually
=========================================

This document assumes you are using an air-gapped live system like
Tails, and that seedkit is installed in your `~/Persistent` folder
(see [Installing seedkit on tails](https://github.com/gavincarr/seedkit/blob/main/recipes/installing_seedkit_on_tails.md)
for instructions). Adjust as required.

Please **DO NOT** use with real secrets on a network-connected computer.


## 1. Print out the BIP39 word list

The [BIP39 word list](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
is a list of 2048 words which are used to generate a mnemonic seed. I like
[this PDF version](https://btcguide.github.io/assets/guide/bip39_wordlist.pdf)
by [Michael Flaxman](https://btcguide.github.io/),
who also has some [nice instructions](https://btcguide.github.io/setup-wallets/paper)
on generating paper wallets (without seedkit).


## 2. Select 23 words from the BIP39 word list

Select 23 words from the BIP39 word list, one at a time, replacing them
in your bag/hat after recording each one. I suggest recording them in a
file on your (air-gapped) tails machine using a text editor, with one word
per line e.g.

```bash
nano bip39p.txt
# Double-check you have exactly 23 words
wc -l bip39p.txt
```


## 3. Generate a 24th checksum word for your mnemonic seed

```bash
cat bip39p.txt | ~/Persistent/seedkit bc | tee bip39.txt
```


## 4. Verify the complete mnemonic seed

```bash
cat bip39.txt | ~/Persistent/seedkit bv
```


