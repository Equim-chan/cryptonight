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
	"runtime"
	"sync/atomic"
	"time"

	"ekyu.moe/cryptonight"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	var (
		bench       bool
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

	flag.BoolVar(&bench, "bench", false, "Benchmark mode, don't do anything else.")
	flag.BoolVar(&includeDiff, "include-diff", false, "Append the difficulty of the result hash to the output. If -out-binary is not given, the difficulty will be appeneded to the output in decimal with comma separated (CSV friendly), otherwise it will be appeneded to the hash binary (which is 32 bytes long) directly, in 8 bytes little endian.")
	flag.BoolVar(&inHex, "in-hex", false, "Read input in hex instead of binary.")
	flag.BoolVar(&outBinary, "out-binary", false, "Produce output in binary (little endian) instead of hex.")
	flag.StringVar(&inFile, "in-file", "", "Read input from file instead of stdin.")
	flag.StringVar(&outFile, "out-file", "", "Produce output to file instead of stdout.")
	flag.IntVar(&variant, "variant", 0, "Set CryptoNight variant, default 0. This applies to benchmark mode as well.")
	flag.Parse()

	if bench {
		// picked from cryptonight_test.go, see comment there
		benchData := [4][]byte{
			{0x91, 0xf4, 0xb7, 0x5, 0x13, 0xd5, 0xe1, 0x49, 0x40, 0x67, 0x3a, 0x5d, 0xba, 0x49, 0x2c, 0x5d, 0xd1, 0x57, 0xc4, 0x95, 0xef, 0xdc, 0x5c, 0x87, 0x4f, 0x17, 0x80, 0x17, 0x25, 0x3e, 0x7c, 0x21, 0xc0, 0x83, 0x16, 0xd7, 0x57, 0x45, 0xfe, 0x4f, 0x31, 0xbb, 0x5b, 0x1a, 0x3e, 0x94, 0xc8, 0xee},
			{0xb8, 0xd1, 0xfd, 0xeb, 0x39, 0xd4, 0xac, 0x67, 0xac, 0x52, 0xa7, 0x78, 0x0, 0x6d, 0x27, 0x81, 0xca, 0xf4, 0x3, 0x4e, 0x27, 0xa, 0xa7, 0x88, 0xd5, 0xce, 0xa2, 0x30, 0xb9, 0x3d, 0xca, 0x8, 0xb, 0xa3, 0x14, 0x41, 0x33, 0xe1, 0x1d, 0xaf, 0xd9, 0xed, 0xf1, 0x6, 0x83, 0x7a, 0x9e, 0xf3},
			{0x7e, 0xe, 0xb9, 0x37, 0x7b, 0x5c, 0xff, 0x3b, 0xcf, 0xaa, 0xc1, 0x0, 0x4d, 0xf6, 0x6b, 0x26, 0xe8, 0xc1, 0x65, 0xe3, 0x34, 0x2f, 0xba, 0x79, 0xd2, 0x58, 0xf5, 0xd, 0x9c, 0x70, 0x2a, 0x65, 0x60, 0x63, 0x9f, 0x42, 0x92, 0x55, 0x4d, 0x72, 0xfa, 0xda, 0x16, 0x52, 0xfd, 0x2, 0x81, 0xe3},
			{0x29, 0x16, 0xb0, 0x97, 0xd1, 0xee, 0x55, 0x50, 0xf9, 0x9c, 0xad, 0x53, 0x6e, 0x84, 0x2a, 0x39, 0xc8, 0xf6, 0x3f, 0x63, 0xad, 0x58, 0x33, 0x30, 0x1e, 0x53, 0x3b, 0xe4, 0xb, 0x57, 0xc4, 0x5c, 0x9d, 0xea, 0x85, 0x5c, 0x7b, 0x65, 0x20, 0xf0, 0x67, 0xff, 0xd0, 0xc1, 0x2b, 0x9a, 0x8c, 0x3d},
		}

		hashes := uint64(0)
		lastSnap := hashes
		t := runtime.GOMAXPROCS(0)
		fmt.Println("GOMAXPROCS =", t)
		fmt.Println("variant =", variant)
		fmt.Println()
		fmt.Println("last 5 seconds (overall)")
		fmt.Println("------------------------")

		for i := 0; i < t; i++ {
			go func() {
				for j := 0; true; j++ {
					cryptonight.Sum(benchData[j&0x03], variant)
					atomic.AddUint64(&hashes, 1)
				}
			}()
		}

		i := uint64(0)
		for range time.Tick(5 * time.Second) {
			i++
			snap := atomic.LoadUint64(&hashes)
			fmt.Printf("%.2f H/s  (%.2f H/s)\n", float64(snap-lastSnap)/5, float64(snap)/float64(5*i))
			lastSnap = snap
		}

		return 0
	}

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
