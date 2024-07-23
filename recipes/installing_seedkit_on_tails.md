
Installing Seedkit on Tails
===========================

This recipe covers downloading, verifying, and installing seedkit to
Persistent Storage on [Tails](https://tails.net/). You can do this
once while you have an internet connection, and then reboot and use
seedkit on your Tails system without an internet connection (i.e.
"air-gapped").


## 1. Creating Persistent Storage on Tails

Boot Tails and stop when you get to the "Welcome to Tails" screen,
before you click "Start Tails". Turn on the button beside "Create
Persistent Storage", and then click "Start Tails" as normal.
(Alternatively, if you have already started Tails, you can choose
Applications -> Tails -> Persistent Storage.)

Click "Continue" on the initial Persistent Storage screen, and then
enter and confirm the passphrase you want to use to secure your
Persistent Storage.

Once created, you will have a new "Places > Persistent" folder
available that will persist across reboots. We will use this to store
the seedkit executable you will download and verify next.


## 2. Download the latest seedkit release

a. Open the Tor Browser under "Applications" and choose "Open Tor
Connection" to enable networking, and enter your wifi settings (or
connect via a physical ethernet cable, etc.). Then connect to Tor
using the most appropriate option for your situation, and finally
start the Tor Browser.

Then, visit the seedkit releases page at:

  https://github.com/gavincarr/seedkit/releases/latest

b. Download the seedkit Linux tarball for your architecture, as well
as the checksums.txt and checksums.txt.sig files e.g.

- seedkit_0.2.2_checksums.txt
- seedkit_0.2.2_checksums.txt.sig
- seedkit_Linux_x86_64.tar.gz
- seedkit_Linux_arm64.tar.gz

(download both tar.gz files if you're not sure of your architecture).


## 3. Verify the seedkit release files

a. In a terminal (Applications > Utilities > Terminal) import the GPG
public key used to sign the seedkit release files

```bash
curl -sS https://github.com/gavincarr.gpg | gpg --import
```

b. Change to the directory where you downloaded the seedkit release
files (e.g. the default `amnesia/Tor Browser` folder):

```bash
cd ~/Tor\ Browser
ls -l
```

c. Verify the signature on the checksums.txt file:

```bash
gpg --verify seedkit_0.2.2_checksums.txt.sig seedkit_0.2.2_checksums.txt
```

Check that the signature is good. A warning that the key is not certified
with a trusted signature is expected and okay (that just means your tails
keyring doesn't have a trust path to the key).

d. Next, verify the checksums on your downloaded seedkit tarball(s):

```bash
grep Linux_x86_64 seedkit_0.2.2_checksums.txt | sha256sum -c
# and/or:
grep Linux_arm64 seedkit_0.2.2_checksums.txt | sha256sum -c
```

e. Now the tarball has been verified, extract the seedkit executable

```bash
tar zxvf seedkit_Linux_x86_64.tar.gz
# and/or:
tar zxvf seedkit_Linux_arm64.tar.gz
```

Verify that the seedkit executable works on your architecture, and then
copy it and the README to your Persistent Storage:

```bash
./seedkit -h
cp seedkit README.md ~/Persistent
ls ~/Persistent
```


## 4. Reboot tails and confirm seedkit is available

Finally, reboot tails and verify that seedkit is available in your
Persistent Storage folder:

```bash
# Open a terminal and check the seedkit version
~/Persistent/seedkit version
```

For security, **ONLY** use seedkit on Tails when the network is
disconnected/offline (i.e. you are air-gapped).

