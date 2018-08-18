package cryptonight

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

type hashSpec struct {
	input, output string // both in hex
	variant       int
}

type diffSpec struct {
	input  string // in hex
	output uint64
}

var (
	hashSpecsV0 = []hashSpec{
		// From cns008
		{"", "eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11", 0},
		{
			"5468697320697320612074657374", // "This is a test"
			"a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605",
			0,
		},

		// From monero: tests/hash/tests-slow.txt
		{"6465206f6d6e69627573206475626974616e64756d", "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5", 0},
		{"6162756e64616e732063617574656c61206e6f6e206e6f636574", "722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4", 0},
		{"63617665617420656d70746f72", "bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87", 0},
		{"6578206e6968696c6f206e6968696c20666974", "b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05", 0},
	}
	hashSpecsV1 = []hashSpec{
		// From monero: tests/hash/tests-slow-1.txt
		{"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "b5a7f63abb94d07d1a6445c36c07c7e8327fe61b1647e391b4c7edae5de57a3d", 1},
		{"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "80563c40ed46575a9e44820d93ee095e2851aa22483fd67837118c6cd951ba61", 1},
		{"8519e039172b0d70e5ca7b3383d6b3167315a422747b73f019cf9528f0fde341fd0f2a63030ba6450525cf6de31837669af6f1df8131faf50aaab8d3a7405589", "5bb40c5880cef2f739bdb6aaaf16161eaae55530e7b10d7ea996b751a299e949", 1},
		{"37a636d7dafdf259b7287eddca2f58099e98619d2f99bdb8969d7b14498102cc065201c8be90bd777323f449848b215d2977c92c4c1c2da36ab46b2e389689ed97c18fec08cd3b03235c5e4c62a37ad88c7b67932495a71090e85dd4020a9300", "613e638505ba1fd05f428d5c9f8e08f8165614342dac419adc6a47dce257eb3e", 1},
		{"38274c97c45a172cfc97679870422e3a1ab0784960c60514d816271415c306ee3a3ed1a77e31f6a885c3cb", "ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8ab49459b", 1},

		// Produced by monero: src/crypto/slow-hash.c:cn_slow_hash
		{
			"e5ad98e59ca8e8a8bce6988ee38292e38081e38193e381aee682b2e9b3b4e38292e38081e68896e38184e381afe6ad8ce38292",
			"24aa73ab3b1e74bf119b31c62470e5cf29dde98c9a8af33ac243d3103ebca0e5",
			1,
		},
	}

	diffSpecs = []diffSpec{
		// From monero-stratum: util/util_test.go
		{"8e3c1865f22801dc3df0a688da80701e2390e7838e65c142604cc00eafe34000", 1009},

		{"d3c693d2083888c03bc8dfbca4f32d9692e094722d8cbf4a90aa4c1400000000", 54164528257},
		{"0000000000000000000000000000000000000000000000000000000000000000", 0},
		{"0000000000000000000000000000000000000000000000000000000000000001", 256},
		{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0", 1},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1},
	}
)

func run(t *testing.T, hashSpecs []hashSpec) {
	for i, v := range hashSpecs {
		in, _ := hex.DecodeString(v.input)
		result := Sum(in, v.variant)
		if hex.EncodeToString(result) != v.output {
			t.Fatalf("\n[%d] expected:\n\t%s\ngot:\n\t%x\n", i, v.output, result)
		}
	}
}

func runCached(t *testing.T, hashSpecs []hashSpec) {
	cache := new(Cache)
	for i, v := range hashSpecs {
		in, _ := hex.DecodeString(v.input)
		result := cache.Sum(in, v.variant)
		if hex.EncodeToString(result) != v.output {
			t.Fatalf("\n[%d] expected:\n\t%s\ngot:\n\t%x\n", i, v.output, result)
		}
	}
}

func TestSum(t *testing.T) {
	t.Run("v0", func(t *testing.T) { run(t, hashSpecsV0) })
	t.Run("v1", func(t *testing.T) {
		run(t, hashSpecsV1)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected to panic, got nothing.")
				}
			}()

			Sum([]byte("Obviously less than 43 bytes"), 1)
		}()
	})
}

func TestSumCached(t *testing.T) {
	t.Run("v0", func(t *testing.T) { runCached(t, hashSpecsV0) })
	t.Run("v1", func(t *testing.T) { runCached(t, hashSpecsV1) })
}

func TestDifficulty(t *testing.T) {
	for i, v := range diffSpecs {
		in, _ := hex.DecodeString(v.input)
		result := Difficulty(in)
		if result != v.output {
			t.Fatalf("\n[%d] expected:\n\t%v\ngot:\n\t%v\n", i, v.output, result)
		}
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected to panic, got nothing.")
			}
		}()

		Difficulty([]byte("Obviously less than 32 bytes"))
	}()
}

func BenchmarkSum(b *testing.B) {
	data := make([]byte, 70)
	rand.Read(data)

	b.Run("v0", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sum(data, 0)
		}
	})
	b.Run("v0-cached", func(b *testing.B) {
		cache := new(Cache)
		for i := 0; i < b.N; i++ {
			cache.Sum(data, 0)
		}
	})

	b.Run("v1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sum(data, 1)
		}
	})
	b.Run("v1-cached", func(b *testing.B) {
		cache := new(Cache)
		for i := 0; i < b.N; i++ {
			cache.Sum(data, 1)
		}
	})
}
