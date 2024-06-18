package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/gavincarr/go-slip39"
	"github.com/lmittmann/tint"
	"github.com/tyler-smith/go-bip39"
)

const (
	GroupLimit = 16
)

var (
	reGroup      = regexp.MustCompile(`^(\d{1,2})of(\d{1,2})$`)
	reWhitespace = regexp.MustCompile(`\s+`)
)

var cli struct {
	Verbose    bool   `short:"v" help:"Enable verbose mode."`
	Passphrase string `flag short:"p" long:"pass" help:"passphrase to use for BIP39 seeds and SLIP39 shares"`
	//Parse ParseCmd `cmd help:"Parse a BIP39 mnemonic seed phrase or a SLIP39 share"`
	Parse       ParseCmd       `cmd help:"Parse a SLIP39 share"`
	BipSlip     BipSlipCmd     `cmd name:"bs" help:"Convert the given BIP39 mnemonic seed phrase to a set of SLIP39 shares"`
	SlipBip     SlipBipCmd     `cmd name:"sb" help:"Convert the given SLIP39 mnemonic share phrase(s) to a BIP39 mnemonic"`
	BipEntropy  BipEntropyCmd  `cmd name:"be" help:"Convert the given BIP39 mnemonic seed phrase to a hex-encoded entropy string"`
	EntropyBip  EntropyBipCmd  `cmd name:"eb" help:"Convert the given hex-encoded entropy string to a BIP39 mnemonic seed phrase"`
	SlipEntropy SlipEntropyCmd `cmd name:"se" help:"Convert the given SLIP39 shares to a hex-encoded entropy string"`
	EntropySlip EntropySlipCmd `cmd name:"es" help:"Convert the given hex-encoded entropy string to a set of SLIP39 shares"`
}

type Context struct {
	Verbose bool
}

type ParseCmd struct {
	Share []string `arg help:"SLIP39 share mnemonic" required`
}

type BipSlipCmd struct {
	Groups []string `flag short:"g" long:"group" help:"Group definitions, as \"MofN\" strings e.g. 2of4, 3of5, etc." required`
	Seed   []string `arg help:"BIP39 mnemonic seed phrase" optional`
}

type SlipBipCmd struct {
	Shares []string `arg help:"SLIP39 share mnemonics (repeated quoted args, or one per line on stdin)" optional`
}

type BipEntropyCmd struct {
	Seed []string `arg help:"BIP39 mnemonic seed phrase" optional`
}

type EntropyBipCmd struct {
	Entropy string `arg help:"Hex-encoded entropy string" optional`
}

type SlipEntropyCmd struct {
	Shares []string `arg help:"SLIP39 share mnemonics (repeated quoted args, or one per line on stdin)" optional`
}

type EntropySlipCmd struct {
	Entropy string   `arg help:"Hex-encoded entropy string" required`
	Groups  []string `arg help:"Group definitions, as \"MofN\" strings e.g. 2of4, 3of5, etc." required`
}

func (c ParseCmd) Run(ctx *Context) error {
	mnemonic := strings.Join(c.Share, " ")
	s, err := slip39.ParseShare(mnemonic)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func (c BipSlipCmd) Run(ctx *Context) error {
	mnemonic, err := readMnemonic(c.Seed)
	if err != nil {
		return err
	}

	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return err
	}

	groups, err := parseGroups(c.Groups)
	if err != nil {
		return err
	}

	passphrase := []byte{}
	shareGroups, err := slip39.GenerateMnemonicsWithPassphrase(
		1, groups, entropy, passphrase,
	)

	for _, shares := range shareGroups {
		for _, s := range shares {
			fmt.Println(s)
		}
	}

	return nil
}

func (c SlipBipCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(c.Shares)
	if err != nil {
		return err
	}
	passphrase := []byte{}
	entropy, err := slip39.CombineMnemonicsWithPassphrase(mnemonics, passphrase)
	if err != nil {
		return err
	}
	slog.Info("", "entropy", entropy, "len", len(entropy))
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}
	fmt.Println(mnemonic)
	return nil
}

func (c BipEntropyCmd) Run(ctx *Context) error {
	mnemonic, err := readMnemonic(c.Seed)
	if err != nil {
		return err
	}
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(entropy))
	return nil
}

func (c EntropyBipCmd) Run(ctx *Context) error {
	var entropyString string
	if len(c.Entropy) > 0 {
		entropyString = c.Entropy
	} else {
		entropyBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		entropyString = strings.TrimSpace(string(entropyBytes))
		slog.Info("", "entropyString", entropyString, "len", len(entropyString))
	}
	entropy, err := hex.DecodeString(entropyString)
	if err != nil {
		return err
	}
	slog.Info("", "entropy", entropy, "len", len(entropy))
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}
	fmt.Println(mnemonic)
	return nil
}

func (c SlipEntropyCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(c.Shares)
	if err != nil {
		return err
	}
	passphrase := []byte{}
	entropy, err := slip39.CombineMnemonicsWithPassphrase(mnemonics, passphrase)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(entropy))
	return nil
}

func (c EntropySlipCmd) Run(ctx *Context) error {
	// TODO
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

func readStdinMnemonic() (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	mnemonic := reWhitespace.ReplaceAllString(strings.TrimSpace(string(data)), " ")
	return mnemonic, nil
}

func readMnemonic(args []string) (string, error) {
	var mnemonic string
	var err error
	if len(args) > 0 {
		mnemonic = strings.Join(args, " ")
	} else {
		mnemonic, err = readStdinMnemonic()
		if err != nil {
			return "", err
		}
	}
	slog.Info("readMnemonic", "mnemonic", mnemonic)
	return mnemonic, nil
}

func readShareMnemonics(args []string) ([]string, error) {
	var mnemonics []string
	// If we have args, but fewer than 20, assume they're quoted mnemonics
	if len(args) > 0 && len(args) < 20 {
		mnemonics = make([]string, 0, len(args))
		for _, m := range args {
			mnemonics = append(mnemonics, m)
		}
	} else if len(args) >= 20 {
		// Otherwise assume we have a single mnemonic with spaces
		mnemonics = []string{strings.Join(args, " ")}
	}

	// If we have no args, read mnemonics from stdin, one per line
	if len(mnemonics) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			m := strings.TrimSpace(scanner.Text())
			mnemonics = append(mnemonics, m)
		}
		if err := scanner.Err(); err != nil {
			return mnemonics, fmt.Errorf("scanning input: %w", err)
		}
	}
	slog.Info("readShareMnemonics", "mnemonics", mnemonics)

	return mnemonics, nil
}

func parseGroups(groupstr []string) ([]slip39.MemberGroupParameters, error) {
	groups := make([]slip39.MemberGroupParameters, 0, len(groupstr))
	for _, g := range groupstr {
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
		group := slip39.MemberGroupParameters{
			MemberThreshold: t,
			MemberCount:     n,
		}
		groups = append(groups, group)
	}
	slog.Info("parseGroups", "groups", groups)
	return groups, nil
}

func runCLI() error {
	ctx := kong.Parse(&cli)
	level := slog.LevelWarn
	if cli.Verbose {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level:      level,
			TimeFormat: " ",
		}),
	))
	return ctx.Run(&Context{Verbose: cli.Verbose})
}

func main() {
	err := runCLI()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: "+err.Error())
		os.Exit(2)
	}
}
