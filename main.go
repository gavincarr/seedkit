package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"math"
	"math/big"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/gavincarr/go-slip39"
	"github.com/lmittmann/tint"
	"github.com/tyler-smith/go-bip39"
)

const (
	GroupLimit = 16
	tickGlyph  = "✔"
)

var version = "undefined"

var (
	reGroup      = regexp.MustCompile(`^(\d{1,2})of(\d{1,2})$`)
	reWhitespace = regexp.MustCompile(`\s+`)
)

var cli struct {
	Verbose      int             `flag type:"counter" short:"v" help:"Enable verbose mode"`
	BipCheckword BipCheckwordCmd `cmd name:"bc" help:"Generate one or more final checksum words for a BIP39 partial mnemonic"`
	BipVal       BipValCmd       `cmd name:"bv" help:"Validate a BIP39 mnemonic seed phrase"`
	BipSlip      BipSlipCmd      `cmd name:"bs" help:"Convert a BIP39 mnemonic seed to a set of SLIP39 shares"`
	BipEntropy   BipEntropyCmd   `cmd name:"be" help:"Convert a BIP39 mnemonic seed to a hex-encoded entropy string"`
	SlipVal      SlipValCmd      `cmd name:"sv" help:"Validate a full set of SLIP39 mnemonic shares"`
	SlipBip      SlipBipCmd      `cmd name:"sb" help:"Convert a minimal set of SLIP39 mnemonic shares to a BIP39 mnemonic seed"`
	SlipLabel    SlipLabelCmd    `cmd name:"sl" help:"Convert a full set of SLIP39 mnemonic shares to labelled word format"`
	LabelSlip    LabelSlipCmd    `cmd name:"ls" help:"Convert a labelled word set to a set of SLIP39 mnemonic shares"`
	SlipEntropy  SlipEntropyCmd  `cmd name:"se" help:"Convert the given SLIP39 shares to a hex-encoded entropy string"`
	EntropyBip   EntropyBipCmd   `cmd name:"eb" help:"Convert a hex-encoded entropy string to a BIP39 mnemonic seed"`
	EntropySlip  EntropySlipCmd  `cmd name:"es" help:"Convert a hex-encoded entropy string to a set of SLIP39 shares"`
	//Parse ParseCmd `cmd help:"Parse a SLIP39 share"`
	Version VersionCmd `cmd help:"Show version information"`
}

type Context struct {
	verbose int
	reader  io.Reader
	writer  io.Writer
}

type BipCheckwordCmd struct {
	Multi         bool `flag short:"m"  help:"output all valid mnemonics for the given partial seed, not just one" xor:"flags"`
	Word          bool `flag short:"w" help:"output just the final checksum word(s), not the full mnemonic"`
	Deterministic bool `flag short:"d"  help:"always use the first checksum word found (for testing)" xor:"flags"`

	PartialMnemonic []string `arg help:"BIP39 partial mnemonic seed phrase (11 or 23 words)" optional`
}

type BipValCmd struct {
	Quiet bool     `flag short:"q" help:"suppress output, just set return code for result"`
	Seed  []string `arg help:"BIP39 mnemonic seed phrase" optional`
}

type BipSlipCmd struct {
	GroupThreshold int      `flag short:"t" aliases:"threshold" help:"Group threshold (the number of groups required to combine)" default:"1"`
	Groups         []string `flag short:"g" help:"Group definitions, as \"MofN\" strings e.g. 1of1, 2of4, 3of5, etc. (repeatable)" required`
	Passphrase     string   `flag short:"p" help:"passphrase to use for BIP39 seed and SLIP39 shares"`

	Seed []string `arg help:"BIP39 mnemonic seed phrase" optional`
}

type SlipValCmd struct {
	Passphrase string `flag short:"p" help:"passphrase used with the SLIP39 shares"`
	CheckFile  string `flag short:"c" aliases:"cf" help:"check file with the source BIP39 mnemonic seed"`

	Shares []string `arg help:"full set of SLIP39 share mnemonics (repeated quoted args, or one per line on stdin)" optional`
}

type SlipBipCmd struct {
	Passphrase string `flag short:"p" help:"passphrase to use for BIP39 seed and SLIP39 shares"`

	Shares []string `arg help:"minimal set of SLIP39 share mnemonics (repeated quoted args, or one per line on stdin)" optional`
}

type SlipLabelCmd struct {
	Upper bool `flag short:"u" help:"output words in uppercase"`

	Shares []string `arg help:"minimal set of SLIP39 share mnemonics (repeated quoted args, or one per line on stdin)" optional`
}

type LabelSlipCmd struct {
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

type ParseCmd struct {
	Share []string `arg help:"SLIP39 share mnemonic" optional`
}

type VersionCmd struct {
}

func (cmd BipCheckwordCmd) Run(ctx *Context) error {
	mnemonic, err := readSeedMnemonic(ctx, cmd.PartialMnemonic)
	if err != nil {
		return fmt.Errorf("reading mnemonic: %w", err)
	}

	partialWords := strings.Fields(mnemonic)
	if len(partialWords) == 0 {
		return errors.New("no mnemonic seed provided")
	}
	if len(partialWords) != 11 && len(partialWords) != 23 {
		return fmt.Errorf("invalid mnemonic seed length %d (must be 11 or 23)",
			len(partialWords))
	}

	checksumWords, err := bip39ChecksumWords(partialWords)
	if err != nil {
		return err
	}

	if cmd.Multi {
		// Validate all the checksumWords
		for _, w := range checksumWords {
			seed := strings.Join(append(partialWords, w), " ")
			ok := bip39.IsMnemonicValid(seed)
			if !ok {
				return fmt.Errorf("generated invalid mnemonic: %q", seed)
			}
		}

		// Output
		for _, w := range checksumWords {
			seed := strings.Join(append(partialWords, w), " ")
			if cmd.Word {
				fmt.Fprintln(ctx.writer, w)
			} else {
				fmt.Fprintln(ctx.writer, seed)
			}
		}
		return nil
	}

	// Select, validate, and output using a random checksum word
	i := 0
	if !cmd.Deterministic {
		i = rand.Intn(len(checksumWords))
	}
	seed := strings.Join(append(partialWords, checksumWords[i]), " ")
	ok := bip39.IsMnemonicValid(seed)
	if !ok {
		return fmt.Errorf("generated invalid mnemonic: %q", seed)
	}
	if cmd.Word {
		fmt.Fprintln(ctx.writer, checksumWords[i])
	} else {
		fmt.Fprintln(ctx.writer, seed)
	}

	return nil
}

func (cmd BipValCmd) Run(ctx *Context) error {
	mnemonic, err := readSeedMnemonic(ctx, cmd.Seed)
	if err != nil {
		return err
	}

	ok := bip39.IsMnemonicValid(mnemonic)
	if !ok {
		if cmd.Quiet {
			return errors.New("")
		}
		return errors.New("invalid BIP-39 mnemonic")
	}

	if !cmd.Quiet {
		fmt.Fprintf(ctx.writer, "%s BIP-39 mnemonic is %s\n",
			color.GreenString(tickGlyph), color.GreenString("good"))
	}

	return nil
}

func (cmd BipSlipCmd) Run(ctx *Context) error {
	mnemonic, err := readSeedMnemonic(ctx, cmd.Seed)
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
	if cmd.Passphrase != "" {
		passphrase = []byte(cmd.Passphrase)
	}
	shareGroups, err := slip39.GenerateMnemonicsWithPassphrase(
		cmd.GroupThreshold, groups, entropy, passphrase,
	)
	if err != nil {
		return err
	}

	fmt.Fprint(ctx.writer, shareGroups.String())

	return nil
}

func (cmd SlipValCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(ctx, cmd.Shares)
	if err != nil {
		return err
	}

	shareGroups, err := slip39.CollateShareGroups(mnemonics)
	if err != nil {
		return fmt.Errorf("collating share groups: %w", err)
	}

	passphrase := []byte{}
	if cmd.Passphrase != "" {
		passphrase = []byte(cmd.Passphrase)
	}
	entropy, combinations, err := shareGroups.ValidateMnemonicsWithPassphrase(
		passphrase)
	if err != nil {
		return fmt.Errorf("validating mnemonics: %w", err)
	}
	plural := ""
	if combinations > 1 {
		plural = "s"
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}

	// If cmd.CheckFile is supplied, it should contain the expected BIP39 mnemonic
	if cmd.CheckFile != "" {
		data, err := ioutil.ReadFile(cmd.CheckFile)
		if err != nil {
			return fmt.Errorf("reading check file: %w", err)
		}

		expectedMnemonic := strings.TrimSpace(string(data))
		if mnemonic != expectedMnemonic {
			return fmt.Errorf("all SLIP-39 combinations agreed, but on an unexpected mnemonic (passphrase?):\ngot: %s\ncf:  %s",
				mnemonic, expectedMnemonic)
		}

		fmt.Fprintf(ctx.writer,
			"%s All SLIP-39 shares are %s - %d combination%s produced the %q mnemonic\n",
			color.GreenString(tickGlyph), color.GreenString("good"),
			combinations, plural, cmd.CheckFile)

		return nil
	}

	fmt.Fprintf(ctx.writer,
		"%s All SLIP-39 shares are %s - %d combination%s produced the same BIP-39 mnemonic:\n%s\n",
		color.GreenString(tickGlyph), color.GreenString("good"),
		combinations, plural, mnemonic)

	return nil
}

func (cmd SlipBipCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(ctx, cmd.Shares)
	if err != nil {
		return err
	}

	passphrase := []byte{}
	if cmd.Passphrase != "" {
		passphrase = []byte(cmd.Passphrase)
	}
	entropy, err := slip39.CombineMnemonicsWithPassphrase(mnemonics, passphrase)
	if err != nil {
		return err
	}
	//slog.Info("", "entropy", entropy, "len", len(entropy))

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.writer, mnemonic)

	return nil
}

func (cmd SlipLabelCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(ctx, cmd.Shares)
	if err != nil {
		return err
	}

	shareGroups, err := slip39.CollateShareGroups(mnemonics)
	if err != nil {
		return fmt.Errorf("collating share groups: %w", err)
	}

	words, err := shareGroups.StringLabelled()
	if err != nil {
		return fmt.Errorf("formatting labelled words: %w", err)
	}

	if cmd.Upper {
		words = strings.ToUpper(words)
	}

	fmt.Fprint(ctx.writer, words)

	return nil
}

func (cmd LabelSlipCmd) Run(ctx *Context) error {
	reader := ctx.reader
	if reader == nil {
		reader = os.Stdin
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}

	shareGroups, err := slip39.CombineLabelledShares(strings.ToLower(string(data)))
	if err != nil {
		return fmt.Errorf("combining labelled words: %w", err)
	}

	shares := shareGroups.String()
	fmt.Fprint(ctx.writer, shares)

	return nil
}

func (cmd BipEntropyCmd) Run(ctx *Context) error {
	mnemonic, err := readSeedMnemonic(ctx, cmd.Seed)
	if err != nil {
		return err
	}
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.writer, hex.EncodeToString(entropy))
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
		//slog.Info("", "entropyString", entropyString, "len", len(entropyString))
	}
	entropy, err := hex.DecodeString(entropyString)
	if err != nil {
		return err
	}
	//slog.Info("", "entropy", entropy, "len", len(entropy))
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.writer, mnemonic)
	return nil
}

func (cmd SlipEntropyCmd) Run(ctx *Context) error {
	mnemonics, err := readShareMnemonics(ctx, cmd.Shares)
	if err != nil {
		return err
	}
	passphrase := []byte{}
	entropy, err := slip39.CombineMnemonicsWithPassphrase(mnemonics, passphrase)
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.writer, hex.EncodeToString(entropy))
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
	fmt.Fprintf(ctx.writer, "entropy %s, groups %v\n", cmd.Entropy, groups)
	return nil
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
	fmt.Fprintln(ctx.writer, string(data))
	return nil
}

func (cmd VersionCmd) Run(ctx *Context) error {
	fmt.Fprintf(ctx.writer, "seedkit version %s\n", version)
	return nil
}

func readStdinSeedMnemonic(ctx *Context) (string, error) {
	reader := ctx.reader
	if reader == nil {
		reader = os.Stdin
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	// Recombine the input into a single line with single spaces
	mnemonic := reWhitespace.ReplaceAllString(strings.TrimSpace(string(data)), " ")
	return mnemonic, nil
}

func readSeedMnemonic(ctx *Context, args []string) (string, error) {
	var mnemonic string
	var err error
	if len(args) > 0 {
		mnemonic = strings.Join(args, " ")
	} else {
		mnemonic, err = readStdinSeedMnemonic(ctx)
		if err != nil {
			return "", err
		}
	}
	//slog.Info("readSeedMnemonic", "mnemonic", mnemonic)
	return mnemonic, nil
}

// convertWordsToShares converts a slice of mnemonic words to a slice of SLIP39
// share mnemonics
func convertWordsToShares(words []string) ([]string, error) {
	if len(words) == 0 {
		return nil, errors.New("no SLIP39 mnemonic words provided")
	}

	mlen := 0
	if len(words)%33 == 0 {
		mlen = 33
	} else if len(words)%20 == 0 {
		mlen = 20
	}

	if mlen == 0 {
		return nil,
			fmt.Errorf("invalid SLIP39 word list length - %d is not a multiple of 33 or 20",
				len(words))
	}

	mnemonics := make([]string, 0, len(words)/mlen)
	for i := 0; i < len(words); i += mlen {
		mnemonics = append(mnemonics, strings.Join(words[i:i+mlen], " "))
	}

	return mnemonics, nil
}

func readShareMnemonics(ctx *Context, args []string) ([]string, error) {
	var mnemonics []string
	var err error

	// If we have args, but fewer than 20, assume they're quoted mnemonics
	if len(args) > 0 && len(args) < 20 {
		mnemonics = make([]string, 0, len(args))
		for _, m := range args {
			mnemonics = append(mnemonics, strings.ToLower(m))
		}
	} else if len(args) >= 20 {
		// Otherwise assume we have a single mnemonic with spaces
		mnemonics = []string{strings.ToLower(strings.Join(args, " "))}
	}

	// If we have no args, read mnemonics from ctx.reader/stdin, one share
	// per line, or possibly one word per line
	if len(mnemonics) == 0 {
		reader := ctx.reader
		if reader == nil {
			reader = os.Stdin
		}
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			m := strings.TrimSpace(scanner.Text())
			mnemonics = append(mnemonics, strings.ToLower(m))
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scanning input: %w", err)
		}
	}
	// If the first mnemonic contains no spaces, assume we have one word per line
	if !strings.Contains(strings.TrimSpace(mnemonics[0]), " ") {
		mnemonics, err = convertWordsToShares(mnemonics)
		if err != nil {
			return nil, err
		}
	}
	//slog.Info("readShareMnemonics", "mnemonics", mnemonics)

	return mnemonics, nil
}

func bip39Entropy(partialWords []string) (*big.Int, error) {
	i := big.NewInt(0)
	for _, w := range partialWords {
		idx, ok := bip39.GetWordIndex(w)
		if !ok {
			return nil, fmt.Errorf("invalid mnemonic word %q", w)
		}
		i.Lsh(i, 11)
		i.Or(i, big.NewInt(int64(idx)))
	}
	return i, nil
}

// bip39ChecksumWords generates a slice of possible checksum words for the
// BIP39 partial mnemonic in partialWords
// Based on https://github.com/avsync/bip39chk
func bip39ChecksumWords(partialWords []string) ([]string, error) {
	entropy, err := bip39Entropy(partialWords)
	if err != nil {
		return nil, err
	}

	size := len(partialWords) + 1
	checksumBits := size / 3
	entropySize := (size*11 - checksumBits) / 8
	entropyToFill := 11 - checksumBits
	entropyBase := entropy.Lsh(entropy, uint(entropyToFill))

	// Generate the full set of possible checksum words
	iterations := int(math.Pow(2, float64(entropyToFill)))
	checksums := make([]string, 0, iterations)
	wordlist := bip39.GetWordList()
	entropyCandidate := entropyBase
	buf := make([]byte, entropySize)
	for i := range iterations {
		entropyBytes := entropyCandidate.FillBytes(buf)
		h := sha256.New()
		h.Write(entropyBytes)
		hash := h.Sum(nil)
		checksum := int(hash[0]) >> (8 - checksumBits)
		idx := (i << checksumBits) + checksum
		checkword := wordlist[idx]
		checksums = append(checksums, checkword)
		entropyCandidate.Add(entropyCandidate, big.NewInt(1))
	}

	return checksums, nil
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
	//slog.Info("parseGroups", "groups", groups)
	return groups, nil
}

func runCLI(wtr io.Writer) error {
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
	return ctx.Run(&Context{writer: wtr, verbose: cli.Verbose})
}

func main() {
	err := runCLI(os.Stdout)
	if err != nil {
		errstr := err.Error()
		if errstr != "" {
			fmt.Fprintf(os.Stderr, "%s %s\n",
				color.RedString("Error:"), errstr)
		}
		os.Exit(2)
	}
}
