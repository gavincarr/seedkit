Seedkit
=======

[![MIT License](https://img.shields.io/github/license/gavincarr/seedkit.svg?maxAge=2592000&color=blue)](https://github.com/gavincarr/seedkit/blob/master/LICENCE)
[![Go Build Status](https://github.com/gavincarr/seedkit/actions/workflows/go.yml/badge.svg)](https://github.com/gavincarr/seedkit/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/gavincarr/seedkit)](https://goreportcard.com/report/github.com/gavincarr/seedkit)



Seedkit is a command line tool for working with Bitcoin BIP-39 mnemonic seeds
and SLIP-39 mnemonic shares. It is intended for use on an air-gapped live
system (such as [Tails](https://tails.net) to securely generate and recover
reliable seed backups.

Seedkit supports the following operations:

- generating the 12th or 24th checksum word for a partial BIP-39 mnemonic seed
  (such as one generated manually using dice or drawing words from a hat)

- validating BIP-39 mnemonic seeds

- generating SLIP-39 mnemonic shares from a BIP-39 mnemonic seed

- validating that all shares from a set of SLIP-39 mnemonic shares are valid
  and that all combinations generate the same master secret

- combining a minimal set SLIP-39 mnemonic shares to recover a BIP-39 mnemonic
  seed

- converting a set of SLIP-39 mnemonic shares into a labelled word format
  (suitable for transcribing on long-term media like metal), and converting
  labelled words back into SLIP-39 mnemonic shares (e.g. for transcription
  validation)


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

For test purposes use the [official release tarballs](https://github.com/gavincarr/seedkit/releases/latest), or build from source:

```bash
go install github.com/gavincarr/seedkit@latest
``` 

To install on Tails, see the [Installing seedkit on tails](https://github.com/gavincarr/seedkit/blob/main/recipes/installing_seedkit_on_tails.md) recipe.


Usage
-----

Specific use cases are documented in more detail in the [recipes folder](https://github.com/gavincarr/seedkit/tree/main/recipes) e.g.

- [Reproducing a seedkit build](https://github.com/gavincarr/seedkit/blob/main/recipes/reproducing_a_seedkit_build.md)
- [Installing seedkit on tails](https://github.com/gavincarr/seedkit/blob/main/recipes/installing_seedkit_on_tails.md)
- [Generating a BIP-39 mnemonic seed from words](https://github.com/gavincarr/seedkit/blob/main/recipes/generating_a_bip39_mnemonic_seed_from_words.md)
- [Generating SLIP-39 shares from a BIP-39 seed](https://github.com/gavincarr/seedkit/blob/main/recipes/generating_slip39_shares_from_a_bip39_seed.md)

General usage is as follows.

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

