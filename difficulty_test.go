package cryptonight

import (
	"encoding/hex"
	"testing"
)

type diffSpec struct {
	input  string // in hex
	output uint64
}

var diffSpecs = []diffSpec{
	// From monero-stratum: util/util_test.go
	{"8e3c1865f22801dc3df0a688da80701e2390e7838e65c142604cc00eafe34000", 1009},

	{"d3c693d2083888c03bc8dfbca4f32d9692e094722d8cbf4a90aa4c1400000000", 54164528257},
	{"0000000000000000000000000000000000000000000000000000000000000000", 0},
	{"0000000000000000000000000000000000000000000000000000000000000001", 255},
	{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0", 1},
	{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1},
}

func TestDifficulty(t *testing.T) {
	for i, v := range diffSpecs {
		in, _ := hex.DecodeString(v.input)
		diff := Difficulty(in)
		if diff != v.output {
			t.Errorf("\n[%d] expected:\n\t%v\ngot:\n\t%v\n", i, v.output, diff)
		}
	}

	if diff := Difficulty([]byte("Obviously less than 32 bytes")); diff != 0 {
		t.Errorf("\nexpected:\n\t%v\ngot:\n\t%v\n", 0, diff)
	}
	if diff := Difficulty([]byte("Here it is obviously more than 32 bytes")); diff != 0 {
		t.Errorf("\nexpected:\n\t%v\ngot:\n\t%v\n", 0, diff)
	}
}

func TestCheckHash(t *testing.T) {
	for i, v := range diffSpecs[:2] {
		in, _ := hex.DecodeString(v.input)
		if !CheckHash(in, 0) {
			t.Errorf("\n[%d] check hash goes wrong", i)
		}
		if !CheckHash(in, v.output-1) {
			t.Errorf("\n[%d] check hash goes wrong", i)
		}
		if !CheckHash(in, v.output) {
			t.Errorf("\n[%d] check hash goes wrong", i)
		}
		if CheckHash(in, v.output+1) {
			t.Errorf("\n[%d] check hash goes wrong", i)
		}
	}

	if CheckHash([]byte("Obviously less than 32 bytes"), 0) {
		t.Errorf("\nexpected:\n\tfalse\ngot:\n\ttrue\n")
	}
	if CheckHash([]byte("Here it is obviously more than 32 bytes"), 0) {
		t.Errorf("\nexpected:\n\tfalse\ngot:\n\ttrue\n")
	}
}

func BenchmarkDifficulty(b *testing.B) {
	in, _ := hex.DecodeString("d3c693d2083888c03bc8dfbca4f32d9692e094722d8cbf4a90aa4c1400000000")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		Difficulty(in)
	}
}

func BenchmarkCheckHash(b *testing.B) {
	in, _ := hex.DecodeString("d3c693d2083888c03bc8dfbca4f32d9692e094722d8cbf4a90aa4c1400000000")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		CheckHash(in, 54164528257)
	}
}
