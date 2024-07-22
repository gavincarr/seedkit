package main

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBip39ChecksumWords(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		input string
		want  []string
	}{
		// 11-word mnemonics
		{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			[]string{"about", "actual", "age", "alpha", "angle", "argue", "artwork", "attract", "bachelor", "bean", "behind", "blind", "bomb", "brand", "broken", "burger", "cactus", "carbon", "cereal", "cheese", "city", "click", "coach", "cool", "coyote", "cricket", "cruise", "cute", "degree", "describe", "diesel", "disagree", "donor", "drama", "dune", "edit", "enemy", "energy", "escape", "exhaust", "express", "fashion", "field", "fiscal", "flavor", "food", "fringe", "furnace", "genius", "glue", "goddess", "grocery", "hand", "high", "holiday", "huge", "illness", "inform", "insect", "jacket", "kangaroo", "knock", "lamp", "lemon", "length", "lobster", "lyrics", "marble", "mass", "member", "metal", "moment", "mouse", "near", "noise", "obey", "offer", "once", "organ", "own", "parent", "phrase", "pill", "pole", "position", "process", "project", "question", "rail", "record", "remind", "render", "return", "ritual", "rubber", "sand", "scout", "sell", "share", "shoot", "simple", "slice", "soap", "solid", "speed", "square", "stereo", "street", "sugar", "surprise", "tank", "tent", "they", "toddler", "tongue", "trade", "truly", "turtle", "umbrella", "urge", "vast", "vendor", "void", "voyage", "wear", "wife", "world", "wrap"}},
		{"legal winner thank year wave sausage worth useful legal winner thank",
			[]string{"about", "admit", "age", "amazing", "analyst", "apple", "ask", "author", "awkward", "basket", "beyond", "blame", "boring", "brave", "broom", "busy", "call", "casual", "celery", "check", "churn", "clever", "code", "cool", "cost", "crime", "cross", "daughter", "debate", "derive", "differ", "display", "domain", "drill", "dynamic", "either", "employ", "ensure", "essay", "exchange", "express", "father", "feature", "fine", "flip", "forget", "frequent", "funny", "general", "give", "gold", "grid", "habit", "help", "holiday", "huge", "identify", "impulse", "into", "jealous", "joy", "kind", "latin", "leisure", "library", "lizard", "lunar", "manage", "marriage", "melt", "method", "mix", "much", "nature", "noise", "nut", "object", "open", "output", "panic", "path", "phrase", "pizza", "pole", "prepare", "process", "pudding", "quarter", "radar", "record", "reform", "result", "retreat", "ring", "saddle", "sand", "science", "sell", "setup", "shrug", "six", "slide", "soccer", "solve", "speed", "stadium", "staff", "stuff", "sun", "swift", "tail", "test", "thrive", "tobacco", "tomato", "trade", "truth", "twenty", "under", "upper", "valid", "version", "virtual", "want", "wedding", "wife", "worry", "yellow"}},
		{"letter advice cage absurd amount doctor acoustic avoid letter advice cage",
			[]string{"above", "add", "afford", "among", "anchor", "any", "army", "attack", "ball", "become", "bicycle", "blind", "bone", "brave", "buffalo", "busy", "candy", "castle", "cereal", "champion", "civil", "close", "code", "comic", "cousin", "creek", "cruel", "daring", "defense", "depth", "device", "dish", "doll", "draw", "earth", "ecology", "end", "envelope", "eternal", "exact", "explain", "fatigue", "federal", "fire", "fly", "forum", "frequent", "future", "genuine", "glass", "grape", "grief", "hat", "heart", "holiday", "hover", "illness", "include", "inspire", "involve", "keep", "kid", "ladder", "lawn", "letter", "logic", "loud", "marble", "match", "media", "milk", "monster", "motion", "myself", "news", "nuclear", "observe", "onion", "orphan", "oyster", "peace", "physical", "piece", "plastic", "potato", "primary", "pull", "quit", "ramp", "rebuild", "reform", "response", "rich", "room", "saddle", "sail", "scheme", "seek", "shaft", "shiver", "size", "skin", "smart", "solve", "spare", "split", "stereo", "style", "suit", "sweet", "talk", "that", "thing", "time", "tongue", "trade", "trigger", "twice", "undo", "update", "vacant", "venture", "village", "wave", "way", "win", "world", "zero"}},
		// 23-word mnemonics
		{"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt",
			[]string{"alcohol", "diamond", "during", "gym", "noise", "reform", "staff", "valid"}},
		{"beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away",
			[]string{"aware", "coconut", "feature", "keen", "option", "peasant", "seed", "wheel"}},
		{"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic",
			[]string{"bless", "deer", "door", "hub", "mesh", "pledge", "sting", "wild"}},
	}

	for _, tc := range tests {
		got, err := bip39ChecksumWords(strings.Fields(tc.input))
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("record mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestBipCheckword(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		cmd      BipCheckwordCmd
		want     string
		wantFile string
	}{
		// 11 words
		// Test no flags (except required Deterministic)
		{BipCheckwordCmd{
			Deterministic: true,
			PartialMnemonic: []string{
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"},
		}, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n", ""},
		// Test Word: true
		{BipCheckwordCmd{
			Word:          true,
			Deterministic: true,
			PartialMnemonic: []string{
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"},
		}, "about\n", ""},
		// Test Multi: true
		{BipCheckwordCmd{
			Multi: true,
			PartialMnemonic: []string{
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"},
		}, "", "bipCheckwordsMnemonics1.txt"},
		// Test Multi: true, Word: true
		{BipCheckwordCmd{
			Multi: true,
			Word:  true,
			PartialMnemonic: []string{
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"},
		}, "", "bipCheckwordsWords1.txt"},

		// 23 words
		// Test no flags (except required Deterministic)
		{BipCheckwordCmd{
			Deterministic: true,
			PartialMnemonic: []string{
				"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt"},
		}, "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt alcohol\n", ""},
		// Test Word: true
		{BipCheckwordCmd{
			Word:          true,
			Deterministic: true,
			PartialMnemonic: []string{
				"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt"},
		}, "alcohol\n", ""},
		// Test Multi: true
		{BipCheckwordCmd{
			Multi: true,
			PartialMnemonic: []string{
				"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt"},
		}, "", "bipCheckwordsMnemonics2.txt"},
		// Test Multi: true, Word: true
		{BipCheckwordCmd{
			Multi: true,
			Word:  true,
			PartialMnemonic: []string{
				"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt"},
		}, "", "bipCheckwordsWords2.txt"},
	}

	for _, tc := range tests {
		var buf bytes.Buffer
		ctx := Context{
			writer:  &buf,
			verbose: 0,
		}

		err := tc.cmd.Run(&ctx)
		if err != nil {
			t.Fatal(err)
		}

		got := buf.String()
		want := tc.want
		if tc.wantFile != "" {
			data, err := ioutil.ReadFile("testdata/" + tc.wantFile)
			if err != nil {
				t.Fatal(err)
			}
			want = string(data)
		}
		if got != want {
			t.Errorf("want %q, got %q", want, got)
		}
	}
}

func TestBipValidate_Success(t *testing.T) {
	t.Parallel()

	// Load all testdata `bipNs.txt` files (good mnemonics)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/bip?s.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	for _, quiet := range []bool{true, false} {
		for tf, mnemonic := range tests {
			cmd := BipValCmd{
				Quiet: quiet,
				Seed:  strings.Fields(strings.TrimSpace(mnemonic)),
			}
			var buf bytes.Buffer
			ctx := Context{
				writer:  &buf,
				verbose: 0,
			}

			err := cmd.Run(&ctx)
			if err != nil {
				t.Errorf("mnemonic %q reported as invalid", tf)
			}

			got := buf.String()
			if quiet {
				if got != "" {
					t.Errorf("mnemonic %q returned output in quiet mode: %s",
						tf, got)
				}
				continue
			}
			if !strings.Contains(got, "good") {
				t.Errorf("mnemonic %q returned no error but outputs invalid", tf)
			}
		}
	}
}

func TestBipValidate_Failure(t *testing.T) {
	t.Parallel()

	// Load all testdata `bipMfN.txt` files (bad mnemonics)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/bip?f?.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	for _, quiet := range []bool{false, true} {
		for tf, mnemonic := range tests {
			cmd := BipValCmd{
				Quiet: quiet,
				Seed:  strings.Fields(strings.TrimSpace(mnemonic)),
			}
			var buf bytes.Buffer
			ctx := Context{
				writer:  &buf,
				verbose: 0,
			}

			err := cmd.Run(&ctx)
			if err == nil {
				t.Errorf("mnemonic %q reported as valid", tf)
			}

			got := buf.String()
			if got != "" {
				t.Errorf("mnemonic %q invalid but returned output: %s",
					tf, got)
			}
		}
	}
}

// Test round-tripping between BIP-39 mnemonics and SLIP-39 shares
func TestBipSlip(t *testing.T) {
	t.Parallel()

	// Load all testdata `bipNs.txt` files (good mnemonics)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/bip?s.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	for _, passphrase := range []string{"", "TREZOR"} {
		for tf, mnemonic := range tests {
			//t.Logf("testing %s with passphrase %q", tf, passphrase)

			cmd := BipSlipCmd{
				GroupThreshold: 1,
				Groups:         []string{"2of3"},
				Passphrase:     passphrase,
				Seed:           strings.Fields(strings.TrimSpace(mnemonic)),
			}
			var buf bytes.Buffer
			ctx := Context{
				writer: &buf,
			}

			err := cmd.Run(&ctx)
			if err != nil {
				t.Errorf("mnemonic %q reported as invalid: %s", tf, err.Error())
				continue
			}

			got := buf.String()
			//t.Logf("mnemonic %q converted to SLIP-39 shares:\n%s", tf, got)

			shares := strings.Split(strings.TrimSpace(got), "\n")
			cmd2 := SlipBipCmd{
				Passphrase: passphrase,
				Shares:     shares[:2],
			}

			buf.Reset()
			err = cmd2.Run(&ctx)
			if err != nil {
				t.Errorf("mnemonic %q reported as invalid: %s", tf, err.Error())
				break
				continue
			}

			got = buf.String()
			//t.Logf("mnemonic %q converted back to BIP-39 seed:\n%s", tf, got)
			if got != mnemonic {
				t.Errorf("round-trip mismatch on %q - got:\n%sexpected:\n%s",
					tf, got, mnemonic)
			}
		}
	}
}

// Test validation of good SLIP-39 shares
func TestSlipVal_Success(t *testing.T) {
	t.Parallel()

	skipTests := make(map[string]bool)
	skipTests["testdata/slip5s.txt"] = true
	skipTests["testdata/slip6s.txt"] = true

	// Load all testdata `slipMs.txt` files (good shares)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/slip?s*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		if skipTests[tf] {
			continue
		}

		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	for tf, shares := range tests {
		buf1 := bytes.NewBufferString(shares)
		var buf2 bytes.Buffer
		cmd := SlipValCmd{}
		ctx := Context{
			reader: buf1,
			writer: &buf2,
		}

		err := cmd.Run(&ctx)
		if err != nil {
			t.Errorf("SlipVal error on %q: %s", tf, err.Error())
			continue
		}

		got := buf2.String()
		if !strings.Contains(got, "good") {
			t.Errorf("unexpected output on successful sv for %q: %s", tf, got)
		}
	}
}

// Test validation of bad SLIP-39 shares
func TestSlipVal_Failure(t *testing.T) {
	t.Parallel()

	// Load all testdata `slipNf.txt` files (bad shares)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/slip?f*.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		if strings.Contains(tf, "todo") {
			continue
		}
		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	for tf, shares := range tests {
		buf1 := bytes.NewBufferString(shares)
		var buf2 bytes.Buffer
		cmd := SlipValCmd{}
		ctx := Context{
			reader: buf1,
			writer: &buf2,
		}

		err := cmd.Run(&ctx)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded!", tf)
			continue
		}
		//t.Logf("%q produced an error, as expected: %s", tf, err.Error())
	}
}

// Test round-tripping between SLIP-39 shares and labelled words
func TestSlipLabel_Success(t *testing.T) {
	t.Parallel()

	// Load all testdata `slipMs.txt` files (good shares)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/slip?s.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	reWords := regexp.MustCompile(`(?m)^\d{3,6} [a-z]+$`)
	for tf, shares := range tests {
		// Convert slip shares to labelled words
		buf1 := bytes.NewBufferString(shares)
		var buf2 bytes.Buffer
		cmd := SlipLabelCmd{}
		ctx := Context{
			reader: buf1,
			writer: &buf2,
		}

		err := cmd.Run(&ctx)
		if err != nil {
			t.Errorf("SlipLabel error on %q: %s", tf, err.Error())
			continue
		}

		words := buf2.String()
		if !reWords.MatchString(words) {
			t.Errorf("test file %q returned invalid words: %s", tf, words)
		}

		// Convert labelled words back to slip shares
		cmd2 := LabelSlipCmd{}
		ctx = Context{
			reader: &buf2,
			writer: buf1,
		}

		err = cmd2.Run(&ctx)
		if err != nil {
			t.Errorf("LabelSlip error on %q: %s", tf, err.Error())
			continue
		}

		out := buf1.String()
		if out != shares {
			t.Errorf("round-trip mismatch on %q - got:\n%sexpected:\n%s",
				tf, out, shares)
		}
	}
}

// Test trying to convert bad sets labelled words
func TestSlipLabel_Failure(t *testing.T) {
	t.Parallel()

	// Load all testdata `slabelsMf.txt` files (bad labelled words)
	tests := make(map[string]string)
	testfiles, err := filepath.Glob("testdata/slabels?f.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, tf := range testfiles {
		data, err := ioutil.ReadFile(tf)
		if err != nil {
			t.Fatal(err)
		}
		tests[tf] = string(data)
	}

	for tf, shares := range tests {
		// Convert labelled words to slip shares
		buf1 := bytes.NewBufferString(shares)
		var buf2 bytes.Buffer
		cmd := LabelSlipCmd{}
		ctx := Context{
			reader: buf1,
			writer: &buf2,
		}

		err = cmd.Run(&ctx)
		if err == nil {
			t.Errorf("LabelSlip on %q unexpectedly suceeded!", tf)
			continue
		}

		t.Logf("LabelSlip on %q produced an error, as expected: %s", tf, err.Error())
	}
}
