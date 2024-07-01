package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	Verbose    int    `flag type:"counter" short:"v" help:"enable verbose mode"`
	Passphrase string `flag short:"p" long:"pass" help:"passphrase to use for BIP39 seeds and SLIP39 shares"`
	//Parse ParseCmd `cmd help:"parse a BIP39 mnemonic seed phrase or a SLIP39 share"`
	Parse       ParseCmd       `cmd help:"parse a SLIP39 share"`
	ValBip      ValBipCmd      `cmd name:"vb" help:"validate the given BIP39 mnemonic seed phrase"`
	BipSlip     BipSlipCmd     `cmd name:"bs" help:"convert the given BIP39 mnemonic seed phrase to a set of SLIP39 shares"`
	SlipBip     SlipBipCmd     `cmd name:"sb" help:"convert the given SLIP39 mnemonic share phrase(s) to a BIP39 mnemonic"`
	BipEntropy  BipEntropyCmd  `cmd name:"be" help:"convert the given BIP39 mnemonic seed phrase to a hex-encoded entropy string"`
	EntropyBip  EntropyBipCmd  `cmd name:"eb" help:"convert the given hex-encoded entropy string to a BIP39 mnemonic seed phrase"`
	SlipEntropy SlipEntropyCmd `cmd name:"se" help:"convert the given SLIP39 shares to a hex-encoded entropy string"`
	EntropySlip EntropySlipCmd `cmd name:"es" help:"convert the given hex-encoded entropy string to a set of SLIP39 shares"`
}

type Context struct {
	Verbose int
}

type ParseCmd struct {
	Share []string `arg help:"SLIP39 share mnemonic" required`
}

type ValBipCmd struct {
	Quiet bool     `flag short:"q" long:"quiet" help:"suppress output, just set return code for result"`
	Seed  []string `arg help:"BIP39 mnemonic seed phrase" optional`
}

type BipSlipCmd struct {
	GroupThreshold  int      `flag short:"t" long:"threshold" help:"Group threshold (the number of groups required to combine)" default:"1"`
	Groups          []string `flag short:"g" long:"group" help:"Group definitions, as \"MofN\" strings e.g. 2of4, 3of5, etc. (repeatable)" required`
	EngravingFormat bool     `flag short:"e" long:"engraving" help:"output in 'engraving' format, one numbered word per line"`

	Seed []string `arg help:"BIP39 mnemonic seed phrase" optional`
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

func (cmd ParseCmd) Run(ctx *Context) error {
	mnemonic := strings.Join(cmd.Share, " ")
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

func (cmd BipSlipCmd) outputShareGroups(shareGroups [][]string) error {
	groupCount := len(shareGroups)
	for g, shares := range shareGroups {
		for s, share := range shares {
			// Standard format
			if !cmd.EngravingFormat {
				fmt.Println(share)
				continue
			}

			// Engraving format
			words, err := slip39.SplitMnemonicWords(share)
			if err != nil {
				return fmt.Errorf("splitting share %q words: %w", share, err)
			}
			for w, word := range words {
				if groupCount == 1 {
					fmt.Printf("%d%02d %s\n", s+1, w+1, word)
				} else {
					fmt.Printf("%d%d%02d %s\n", g+1, s+1, w+1, word)
				}
			}
		}
	}
	return nil
}

func (cmd ValBipCmd) Run(ctx *Context) error {
	mnemonic, err := readMnemonic(cmd.Seed)
	if err != nil {
		return err
	}

	ok := bip39.IsMnemonicValid(mnemonic)
	if !ok {
		if cmd.Quiet {
			os.Exit(2)
		}
		return errors.New("invalid mnemonic")
	}

	if !cmd.Quiet {
		fmt.Println("Mnemonic is good")
	}

	return nil
}

func (cmd BipSlipCmd) Run(ctx *Context) error {
	mnemonic, err := readMnemonic(cmd.Seed)
	if err != nil {
		return err
	}

	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return err
	}

	groups, err := parseGroups(cmd.Groups)
	if err != nil {
		return err
	}

	passphrase := []byte{}
	shareGroups, err := slip39.GenerateMnemonicsWithPassphrase(
		cmd.GroupThreshold, groups, entropy, passphrase,
	)

	err = cmd.outputShareGroups(shareGroups)
	if err != nil {
		return err
	}

	return nil
}

func (cmd SlipBipCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(cmd.Shares)
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

func (cmd BipEntropyCmd) Run(ctx *Context) error {
	mnemonic, err := readMnemonic(cmd.Seed)
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

func (cmd EntropyBipCmd) Run(ctx *Context) error {
	var entropyString string
	if len(cmd.Entropy) > 0 {
		entropyString = cmd.Entropy
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

func (cmd SlipEntropyCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(cmd.Shares)
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

func (cmd EntropySlipCmd) Run(ctx *Context) error {
	// TODO
	_, err := hex.DecodeString(cmd.Entropy)
	//entropy, err := hex.DecodeString(cmd.Entropy)
	if err != nil {
		return err
	}
	groups, err := parseGroups(cmd.Groups)
	if err != nil {
		return err
	}
	fmt.Printf("entropy %s, groups %v\n", cmd.Entropy, groups)
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
	if cli.Verbose >= 2 {
		level = slog.LevelDebug
	} else if cli.Verbose == 1 {
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
