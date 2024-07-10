Seedkit
=======

[![MIT License](https://img.shields.io/github/license/gavincarr/go-slip39.svg?maxAge=2592000&color=blue)](https://github.com/gavincarr/go-slip39/blob/master/LICENCE)

Seedkit is a command line tool for working with Bitcoin BIP-39 mnemonic seeds
and SLIP-39 mnemonic shares. It is intended for use on an air-gapped live
system (such as [Tails](https://tails.net) to securely generate and recover
reliable seed backups.

Seedkit supports the following operations:

- generating the 12th or 24th checksum word for a partial BIP-39 mnemonic seed
  (such as one generated manually using dice or drawing words from a hat)

- validating BIP-39 mnemonic seeds

- generating SLIP-39 mnemonic shares from a BIP-39 mnemonic seed

- validating that a full set of SLIP-39 mnemonic shares is complete and
  all generate the same master secret

- combining a minimal set SLIP-39 mnemonic shares to recover a BIP-39 mnemonic
  seed

- converting a set of SLIP-39 mnemonic shares into a labelled word format
  (suitable for stamping onto metal washers), and the reverse


Security
--------

This implementation is not using any hardening techniques. Secrets are passed
in the open, and calculations are most likely vulnerable to side-channel attacks.
The code has not been audited by security professionals. Use at your own risk.

Seedkit is intended for use on an air-gapped live system (such as
[Tails](https://tails.net)), and should NOT be used with any valuable secrets
outside of such an environment. You should always assume that any machine you
have had connected to the internet is compromised and untrustworthy.


Installation
------------

TODO


Usage
-----

```bash
# Seedkit top-level help
seedkit -h
# Seedkit command-specific help
seedkit <cmd> -h

# Generate  a randomised final checksum word for a partial BIP-39 mnemonic seed
$ PARTIAL_SEED="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
$ echo $PARTIAL_SEED | seedkit bc | tee bip39.txt
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bean

# Generate a list of final checksum words for a partial BIP-39 mnemonic seed
$ echo $PARTIAL_SEED | seedkit bc --multi --word
about
actual
[...]
world
wrap

# Validate a BIP-39 mnemonic seed
$ cat bip39.txt | seedkit bv
BIP-39 mnemonic is good

# Generate SLIP-39 mnemonic shares from a BIP-39 mnemonic seed
$ cat bip39.txt | seedkit bs -g 2of3 | tee slip39.txt
carpet morning academic acid carbon mild yield axis premium username olympic parking crystal costume exhaust language equip prevent beam velvet
carpet morning academic agency alien scramble traffic again total payroll language galaxy fluff debut destroy pickup bucket level unfair daisy
carpet morning academic always cylinder display remind lying document fishing decorate work either briefing software herd craft crucial duckling premium

# Validate a full set of SLIP-39 mnemonic shares
$ cat slip39.txt | seedkit sv 
SLIP-39 shares are good - 3 combinations produced the same BIP-39 mnemonic:
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bean

# Combine a minimal set of SLIP-39 mnemonic shares to recover a BIP-39 mnemonic seed
$ head -n2 slip39.txt | seedkit sb
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bean
$ tail -n2 slip39.txt | seedkit sb
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bean

# Convert a set of SLIP-39 mnemonic shares into labelled word format
$ cat slip39.txt | seedkit sl | tee slip39-words.txt
101 carpet
102 morning
[...]
319 duckling
320 premium

# Convert from labelled word format back to SLIP-39 mnemonic shares
$ cat slip39-words.txt | seedkit ls
carpet morning academic acid carbon mild yield axis premium username olympic parking crystal costume exhaust language equip prevent beam velvet
carpet morning academic agency alien scramble traffic again total payroll language galaxy fluff debut destroy pickup bucket level unfair daisy
carpet morning academic always cylinder display remind lying document fishing decorate work either briefing software herd craft crucial duckling premium
```


Acknowledgements
----------------

seedkit uses the following excellent libraries:

- [go-bip39](https://github.com/tyler-smith/go-bip39)
- [go-slip39](https://github.com/gavincarr/go-slip39)
- [kong](https://github.com/alecthomas/kong)

