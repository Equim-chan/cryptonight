package main // import "ekyu.moe/cryptonight/cmd/cnhash"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"ekyu.moe/cryptonight"
)

func main() {
	var (
		inHex       bool
		outBinary   bool
		includeDiff bool
		inFile      string
		outFile     string
		variant     int

		in  io.Reader = os.Stdin
		out io.Writer = os.Stdout
	)

	flag.BoolVar(&includeDiff, "include-diff", false, "Append the difficulty of the result hash to the output. If -out-binary is not given, it is appened to the output in decimal with comma separated, otherwise it will appened to the hash binary (which is 32 bytes long) directly, in 8 bytes little endian.")
	flag.BoolVar(&inHex, "in-hex", false, "Read input in hex instead of binary.")
	flag.BoolVar(&outBinary, "out-binary", false, "Produce output in binary (little endian) instead of hex.")
	flag.StringVar(&inFile, "in-file", "", "Read input from file instead of stdin.")
	flag.StringVar(&outFile, "out-file", "", "Produce output to file instead of stdout.")
	flag.IntVar(&variant, "variant", 0, "Set CryptoNight variant.")
	flag.Parse()

	if inFile != "" {
		f, err := os.Open(inFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		in = f
	}

	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		out = f
	}

	blob, err := ioutil.ReadAll(in)
	if err != nil {
		log.Fatal(err)
	}
	if inHex {
		blob = bytes.TrimSpace(blob)
		h := make([]byte, hex.DecodedLen(len(blob)))
		if _, err := hex.Decode(h, blob); err != nil {
			log.Fatal(err)
		}
		blob = h
	}

	if variant == 1 && len(blob) < 43 {
		log.Fatal("variant 1 requires at least 43 bytes of input.")
	}

	sum := cryptonight.Sum(blob, variant)
	diff := uint64(0)
	if includeDiff {
		diff = cryptonight.Difficulty(sum)
	}

	if outBinary {
		if _, err := out.Write(sum); err != nil {
			log.Fatal(err)
		}

		if includeDiff {
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, diff)
			if _, err := out.Write(buf); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		if includeDiff {
			if _, err := fmt.Fprintf(out, "%x,%v\n", sum, diff); err != nil {
				log.Fatal(err)
			}
		} else {
			if _, err := fmt.Fprintf(out, "%x\n", sum); err != nil {
				log.Fatal(err)
			}
		}
	}
}
