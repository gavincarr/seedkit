
Generating SLIP-39 shares from a BIP-39 seed
============================================

This document assumes you are using an air-gapped live system like
Tails, and that seedkit is installed in your ~/Persistent folder.
(see [Installing seedkit on tails](https://github.com/gavincarr/seedkit/blob/main/recipes/installing_seedkit_on_tails.md)
for instructions). Adjust as required.

Please **DO NOT** use with real secrets on a network-connected computer.


## 1. Start Tails and open a terminal

Open a terminal using "Applications > Utilities > Terminal".


## 2. Generate SLIP-39 shares from your BIP-39 seed

The seedkit `bs` command, which generates SLIP-39 shares from a
BIP-39 seed, requires you to specify at least one `-g/--groups` option,
as an 'MofN' string e.g. `2of3`, `3of5`, etc. If specifying multiple
groups, you may also specify the minimum group threshold using the
`-t/--threshold` option (default is 1).

For example:

```bash
# Generate one group of 2-of-3 shares for a BIP-39 seed
# (outputs 3 shares in total)
cat bip39.txt | ~/Persistent/seedkit bs -g 2of3 | tee slip39.txt

# Generate a 1-of-1 share and a set of 3-of-5 shares (default threshold == 1)
# (outputs 6 shares in total)
cat bip39.txt | ~/Persistent/seedkit bs -g 1of1 -g 3of5 | tee slip39.txt

# Generate a 2-of-3 share and a 3-of-5 share with a group threshold of 2
# (outputs 8 shares in total)
cat bip39.txt | ~/Persistent/seedkit bs -t 2 -g 2of3 -g 3of5 | tee slip39.txt
```


## 3. Validate the generated SLIP-39 shares

Exhaustively validate the generated SLIP-39 shares using the `sv` command,
which checks that all quorum combinations of shares are valid, and produce
the same BIP-39 mnemonic.

```bash
cat slip39.txt | ~/Persistent/seedkit sv
```

This will produce a success message if all shares are valid, and output the
BIP-39 mnemonic the shares generated (which should match your input BIP-39
mnemonic, of course).


## 4. Record your SLIP-39 shares

Record your SLIP-39 shares either on paper, or on a durable medium like
metal. If you are recording on paper you might like to use the 33-word
templates in the templates directory:
[A4 version](https://github.com/gavincarr/seedkit/blob/main/templates/slip39_33x4_a4.pdf), 
[Letter version](https://github.com/gavincarr/seedkit/blob/main/templates/slip39_33x4_letter.pdf).

It is recommended that you label each share with:

- wallet name
- group number (if more than one group)
- share number (if more than one share in the group)
- share group definition (your 'MofN' string for the group)
- group threshold (if more than one group)

e.g. "RedWallet, #2, 2of3", "Cicero, Group 2, Share 3, 3of5, Threshold 2"

If you would like to see your shares in a numbered format for transcribing,
you can run them through the `sl` command:

```bash
cat slip39.txt | ~/Persistent/seedkit sl | less
# Or in uppercase:
cat slip39.txt | ~/Persistent/seedkit sl -u | less
```


## 5. Re-enter your SLIP-39 shares to check for transcription errors

Next, to check for transcription errors, you should re-enter
your transcribed words into a new shares file (either one share per
line, space separated, or one word per line), and then re-validate
with seedkit:

```bash
nano slip39_transcribed.txt
cat slip39_transcribed.txt | ~/Persistent/seedkit sv -c bip39.txt
```

This should produce a success message if all shares are valid and all
combinations produced the mnemonic in "bip39.txt". If you get an error it
means that you have one or more transcription errors in your shares,
which need to be corrected (most importantly, on the version you have
recorded on paper or metal).


## 6. Store your SLIP-39 shares securely

Finally, store your SLIP-39 shares in separate secure locations.

**NEVER** store a quorum of shares from the same group in the same location.
