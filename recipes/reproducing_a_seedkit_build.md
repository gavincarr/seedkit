
Reproducing a tagged seedkit build
==================================

Seedkit uses [reproducible builds](https://reproducible-builds.org/),
which allows users to personally reproduce an identical binary from
given source files.

This allows technical users who have reviewed a certain set of source
code to build local binaries and tar files directly from that source
code, and to verify that they are bit-for-bit identical with the published
versions.

This procedure does NOT need to be done on an air-gapped live system
like [Tails](https://tails.net/) - you can build and verify the build
artifacts on any system, and then confirm that the binary you are using
later on your secure system is identical.


## Dependencies

* Go: seedkit is written in Go, and a reproducible build requires the
  same version of Go as was used for the build, which is currently
  Go 1.22 (try `go version` to see if you have one already installed).

  If not, install the latest release of that version (e.g. 1.22.5,
  using the [official Go installation instructions](https://golang.org/doc/install).


* Goreleaser - seedkit uses [goreleaser](https://goreleaser.com) to
  build the seedkit releases, and this provides a convenient way to
  replicate an identical build process.

  Install 

  ```bash
  go get -u github.com/goreleaser/goreleaser
  ```

* A unix-like shell environment - this recipe should work directly on
  Linux and Mac, but on Windows will probably require a Windows
  Subsystem for Linux (WSL) environment.

  Install using the official [WSL installation instructions](https://docs.microsoft.com/en-us/windows/wsl/install).


## Procedure

* Check [the latest seedkit release](https://github.com/gavincarr/seedkit/releases/latest)
  in your browser and download the tar (or zip) file you are wanting to
  verify against. If you are wanting to verify a binary for use on Tails,
  you will want the Linux tar file that matches the architecture of the
  machine you will be using (probably x86_64 unless you're on a Mac or
  Raspberry Pi - check with `uname -m`).

* Then in a shell environment, do:

```bash
# Set VTAG and TAG variables for the seedkit release you want to reproduce
VTAG=v0.2.2
TAG=${VTAG#v}

# Clone the seedkit repository for that tag
git clone --depth 1 --branch $VTAG https://github.com/gavincarr/seedkit
# (ignore the warnings about being in `detached HEAD` state)

# Change to the seedkit directory
cd seedkit

# Use goreleaser to do a local build
goreleaser --skip=publish,sign --clean

# Calculate the sha256 checksum of the Linux tarfiles
sha256sum dist/seedkit_Linux_x86_64.tar.gz
sha256sum dist/seedkit_Linux_arm64.tar.gz
```

* Verify the checksums against the ones from the corresponding seedkit
  release page. If they match, you have verified that those tar files
  have been built from the source code you cloned, and that reviews of
  that source code are trustworthy for the binaries in those tar files.


* If you are using Tails, you can now download the tar file you verified
  from the seedkit releases page and set it up for use on Tails (or put
  the tar file you built on a webserver somewhere where Tails can access
  it).

