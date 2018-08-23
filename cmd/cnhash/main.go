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
	os.Exit(realMain())
}

func realMain() int {
	var (
		inHex       bool
		outBinary   bool
		includeDiff bool
		inFile      string
		outFile     string
		variant     int

		in  io.Reader = os.Stdin
		out io.Writer = os.Stdout

		stderr = log.New(os.Stderr, "cnhash: ", 0)
	)

	flag.BoolVar(&includeDiff, "include-diff", false, "Append the difficulty of the result hash to the output. If -out-binary is not given, the difficulty will be appeneded to the output in decimal with comma separated (CSV friendly), otherwise it will be appeneded to the hash binary (which is 32 bytes long) directly, in 8 bytes little endian.")
	flag.BoolVar(&inHex, "in-hex", false, "Read input in hex instead of binary.")
	flag.BoolVar(&outBinary, "out-binary", false, "Produce output in binary (little endian) instead of hex.")
	flag.StringVar(&inFile, "in-file", "", "Read input from file instead of stdin.")
	flag.StringVar(&outFile, "out-file", "", "Produce output to file instead of stdout.")
	flag.IntVar(&variant, "variant", 0, "Set CryptoNight variant, default 0.")
	flag.Parse()

	if inFile != "" {
		f, err := os.Open(inFile)
		if err != nil {
			stderr.Println("open input file:", err)
			return 1
		}
		defer f.Close()
		in = f
	}
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			stderr.Println("create output file:", err)
			return 1
		}
		defer f.Close()
		out = f
	}

	blob, err := ioutil.ReadAll(in)
	if err != nil {
		stderr.Println("read input:", err)
		return 1
	}
	if inHex {
		blob = bytes.TrimSpace(blob)
		h := make([]byte, hex.DecodedLen(len(blob)))
		if _, err := hex.Decode(h, blob); err != nil {
			stderr.Println("decode hex:", err)
			return 1
		}
		blob = h
	}

	if variant == 1 && len(blob) < 43 {
		stderr.Println("variant 1 requires at least 43 bytes of input.")
		return 1
	}

	sum := cryptonight.Sum(blob, variant)
	diff := uint64(0)
	if includeDiff {
		diff = cryptonight.Difficulty(sum)
	}

	if outBinary {
		if _, err := out.Write(sum); err != nil {
			stderr.Println("write output:", err)
			return 1
		}

		if includeDiff {
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, diff)
			_, err = out.Write(buf)
		}
	} else {
		if includeDiff {
			_, err = fmt.Fprintf(out, "%x,%v\n", sum, diff)
		} else {
			_, err = fmt.Fprintf(out, "%x\n", sum)
		}
	}

	if err != nil {
		stderr.Println("write output:", err)
		return 1
	}

	return 0
}
