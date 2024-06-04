package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/tyler-smith/go-bip39"
)

const (
	GroupLimit = 16
)

var (
	reGroup = regexp.MustCompile(`^(\d{1,2})of(\d{1,2})$`)
)

type Context struct {
	Verbose bool
}

type SeedEntropyCmd struct {
	Seed []string `arg help:"BIP39 mnemonic seed phrase" required`
}

type EntropySeedCmd struct {
	Entropy string `arg help:"Hex-encoded entropy string" required`
}

type SharesEntropyCmd struct {
}

type EntropySharesCmd struct {
	Entropy string   `arg help:"Hex-encoded entropy string" required`
	Groups  []string `arg help:"Group definitions, as \"MofN\" strings e.g. 2of4, 3of5, etc." required`
}

var cli struct {
	Verbose bool `help:"Enable verbose mode."`

	SeedEntropy   SeedEntropyCmd   `cmd help:"Convert the given BIP39 mnemonic seed phrase to a hex-encoded entropy string"`
	EntropySeed   EntropySeedCmd   `cmd help:"Convert the given hex-encoded entropy string to a BIP39 mnemonic seed phrase"`
	SharesEntropy SharesEntropyCmd `cmd help:"Convert the given SLIP39 shares (stdin, one per line) to a hex-encoded entropy string"`
	EntropyShares EntropySharesCmd `cmd help:"Convert the given hex-encoded entropy string to a set of SLIP39 shares"`
}

type groupStruct struct {
	Threshold    int
	NumberShares int
}

func (c SeedEntropyCmd) Run(ctx *Context) error {
	seed := strings.Join(c.Seed, " ")
	entropy, err := bip39.EntropyFromMnemonic(seed)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", entropy)
	return nil
}

func (c EntropySeedCmd) Run(ctx *Context) error {
	entropy, err := hex.DecodeString(c.Entropy)
	if err != nil {
		return err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", mnemonic)
	return nil
}

func (c SharesEntropyCmd) Run(ctx *Context) error {
	return nil
}

func (c EntropySharesCmd) Run(ctx *Context) error {
	_, err := hex.DecodeString(c.Entropy)
	//entropy, err := hex.DecodeString(c.Entropy)
	if err != nil {
		return err
	}
	groups, err := parseGroups(c.Groups)
	if err != nil {
		return err
	}
	fmt.Printf("entropy %s, groups %v\n", c.Entropy, groups)
	return nil
}

func parseGroups(groupstr []string) ([]groupStruct, error) {
	groups := make([]groupStruct, len(groupstr))
	for i, g := range groupstr {
		matches := reGroup.FindStringSubmatch(g)
		if matches == nil {
			return nil, fmt.Errorf("invalid group definition: %q", g)
		}
		t, _ := strconv.Atoi(matches[1])
		n, _ := strconv.Atoi(matches[2])
		if t > GroupLimit || n > GroupLimit || t > n {
			return nil,
				fmt.Errorf("invalid group format: %q (not \"MofN\", M <= N, N <= %d)",
					g, GroupLimit)
		}
		groups[i].Threshold = t
		groups[i].NumberShares = n
	}
	return groups, nil
}

func runCLI() error {
	ctx := kong.Parse(&cli)
	return ctx.Run(&Context{Verbose: cli.Verbose})
}

func main() {
	err := runCLI()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: "+err.Error())
		os.Exit(2)
	}
}
