package cryptonight

import (
	"encoding/hex"
	"testing"

	"github.com/aead/skein"
	"github.com/dchest/blake256"

	"ekyu.moe/cryptonight/groestl"
	"ekyu.moe/cryptonight/jh"
)

type hashSpec struct {
	input, output string // both in hex
	variant       int
}

var (
	hashSpecsV0 = []hashSpec{
		// From CNS008
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
	hashSpecsV2 = []hashSpec{
		// From monero: tests/hash/test-slow-2.txt
		{"5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374", "353fdc068fd47b03c04b9431e005e00b68c2168a3cc7335c8b9b308156591a4f", 2},
		{"4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67", "72f134fc50880c330fe65a2cb7896d59b2e708a0221c6a9da3f69b3a702d8682", 2},
		{"656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265", "410919660ec540fc49d8695ff01f974226a2a28dbbac82949c12f541b9a62d2f", 2},
		{"657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c", "4472fecfeb371e8b7942ce0378c0ba5e6d0c6361b669c587807365c787ae652d", 2},
		{"71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369", "577568395203f1f1225f2982b637f7d5e61b47a0f546ba16d46020b471b74076", 2},
		{"757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465", "f6fd7efe95a5c6c4bb46d9b429e3faf65b1ce439e116742d42b928e61de52385", 2},
		{"697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974", "422f8cfe8060cf6c3d9fd66f68e3c9977adb683aea2788029308bbe9bc50d728", 2},
		{"657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e", "512e62c8c8c833cfbd9d361442cb00d63c0a3fd8964cfd2fedc17c7c25ec2d4b", 2},
		{"4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c", "12a794c1aa13d561c9c6111cee631ca9d0a321718d67d3416add9de1693ba41e", 2},
		{"73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e", "2659ff95fc74b6215c1dc741e85b7a9710101b30620212f80eb59c3c55993f9d", 2},
	}

	// This test data set is specially picked, as the final hash functions for
	// all v0, v1, v2 when they are passed through are the same, and they cover
	// all the four final hashes, so it can just be more fair.
	//
	// Also, each row is 76 bytes long, matching the size of hashingBlob.
	benchData = [4][]byte{
		{0xa8, 0xab, 0xb6, 0xb, 0x87, 0xa3, 0x49, 0x26, 0x72, 0xbf, 0x9d, 0x18, 0xd4, 0xd5, 0x2c, 0x4c, 0x7b, 0x3f, 0x5a, 0xdd, 0x25, 0xdd, 0x8c, 0xd5, 0xe5, 0xd7, 0x85, 0xcd, 0x30, 0xde, 0x5f, 0x10, 0xb7, 0x32, 0xce, 0x45, 0xb8, 0x74, 0x5d, 0xf5, 0x2a, 0x87, 0x93, 0xcb, 0x51, 0x2b, 0xf7, 0x77, 0xc2, 0xa7, 0xcc, 0xc0, 0xb4, 0x96, 0x3e, 0x43, 0x8f, 0x3f, 0xbf, 0x16, 0x78, 0xf7, 0xa8, 0xb4, 0x5d, 0xb, 0x4d, 0xdf, 0xc5, 0x10, 0xbe, 0xaa, 0xd1, 0xf3, 0xef, 0x29},
		{0xe, 0xa3, 0x74, 0x46, 0xbf, 0x65, 0x53, 0xb4, 0xab, 0xc0, 0x11, 0x3e, 0x2b, 0x5b, 0x9, 0x26, 0xb8, 0x59, 0xf6, 0xb9, 0xbf, 0x5a, 0xb, 0x43, 0x95, 0x45, 0x8a, 0xa, 0x5f, 0xed, 0xb9, 0x9c, 0x79, 0xce, 0x6c, 0xbc, 0x7f, 0xa, 0x4a, 0xe3, 0x6f, 0x67, 0xb9, 0x89, 0xe6, 0x4, 0x2f, 0xe9, 0xe0, 0xd6, 0x8a, 0x50, 0x9f, 0x44, 0x7d, 0x96, 0x3f, 0xee, 0xc2, 0x71, 0x27, 0xfc, 0xf1, 0x43, 0xcd, 0xe8, 0x36, 0x34, 0x29, 0x8e, 0xd, 0xe9, 0x89, 0xb4, 0xae, 0xfd},
		{0xc5, 0xf0, 0x6f, 0xd5, 0x8, 0xe, 0x1d, 0x60, 0xb2, 0x6b, 0xe0, 0xd7, 0x7e, 0xa, 0x56, 0xef, 0x6c, 0xfb, 0x3b, 0xc7, 0x2d, 0xc5, 0x7b, 0x8, 0xb6, 0x54, 0x1, 0x65, 0xe1, 0x20, 0x22, 0xf2, 0x26, 0x5e, 0x4b, 0xe2, 0x49, 0x6c, 0x10, 0x1b, 0x8c, 0x43, 0xcb, 0xd5, 0xbd, 0x1e, 0x7c, 0x61, 0xd8, 0x6e, 0xe2, 0x47, 0x8c, 0x46, 0x44, 0xc3, 0x1a, 0x5, 0xb7, 0x5f, 0x85, 0x8b, 0x2a, 0x68, 0x55, 0xb0, 0x5f, 0xe4, 0xc8, 0xc3, 0xac, 0x52, 0x1e, 0x3f, 0xe3, 0x18},
		{0xfc, 0x11, 0x56, 0x9f, 0xae, 0xe8, 0x99, 0xd3, 0x62, 0xb8, 0x1a, 0xf6, 0xd3, 0xdc, 0x29, 0x69, 0x34, 0xd3, 0x98, 0x3c, 0x7f, 0x27, 0x93, 0x3, 0x3f, 0xf4, 0x28, 0x42, 0xcb, 0xe9, 0x9d, 0x5e, 0xc6, 0xad, 0x89, 0x36, 0x61, 0x87, 0x72, 0x30, 0x3c, 0xd5, 0x57, 0x91, 0xc6, 0xca, 0x54, 0x7a, 0xa9, 0xe3, 0x5e, 0x83, 0xd0, 0x8a, 0x58, 0xa1, 0x90, 0xe5, 0x5d, 0x7e, 0x3f, 0x31, 0xc3, 0xd8, 0xad, 0x12, 0x3, 0xdd, 0xd6, 0x36, 0xf1, 0x52, 0x5d, 0x5d, 0x4a, 0x36},
	}
)

func testSum(t *testing.T, sum func(data []byte, variant int) []byte) {
	run := func(t *testing.T, hashSpecs []hashSpec) {
		for i, v := range hashSpecs {
			in, _ := hex.DecodeString(v.input)
			result := sum(in, v.variant)
			if hex.EncodeToString(result) != v.output {
				t.Errorf("\n[%d] expected:\n\t%s\ngot:\n\t%x\n", i, v.output, result)
			}
		}
	}

	t.Run("v0", func(t *testing.T) { run(t, hashSpecsV0) })
	t.Run("v1", func(t *testing.T) {
		run(t, hashSpecsV1)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected to panic, got nothing.")
				}
			}()

			sum([]byte("Obviously less than 43 bytes"), 1)
		}()
	})
	t.Run("v2", func(t *testing.T) { run(t, hashSpecsV2) })
}

// Here we don't make a seperate template function, as we want the function address
// to be known at link time so the result can be more accurate.
func BenchmarkSum(b *testing.B) {
	b.Run("v0", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			Sum(benchData[i&0x03], 0)
		}
	})
	b.Run("v1", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			Sum(benchData[i&0x03], 1)
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			Sum(benchData[i&0x03], 2)
		}
	})

	b.Run("v0-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				Sum(benchData[i&0x03], 0)
				i++
			}
		})
	})
	b.Run("v1-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				Sum(benchData[i&0x03], 1)
				i++
			}
		})
	})
	b.Run("v2-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				Sum(benchData[i&0x03], 2)
				i++
			}
		})
	})
}

func BenchmarkFinalHash(b *testing.B) {
	// exactly 200 bytes
	in, _ := hex.DecodeString("54aed57f88c00ccd0ed596ea7a119eab614e4a618d6777e3a7e61b8eb5c10373cf01826848e5036f6a03d4b37f0952679559dd7badfe91aa53edf7a029a4f5ecdd77ca2522357401749d20e53f89251a1e1e617851c1862c1e6008d3874368b07ea6ac411031a2fb95536c6bf5e1d7c991418b5ed4c3174212637249410213fb8cf06be61b77644b9b46d005287b0c6513cf67450b5a924ac69d0cb68680022a394fbc4d5a92d91aba9bc32f54b5a1d176337f167986bc9c04b54ce6a5b81420c0ee28031e731981")
	b.ResetTimer()

	b.Run("BLAKE-256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := blake256.New()
			h.Write(in)
			h.Sum(nil)
		}
	})
	b.Run("Grøstl-256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := groestl.New256()
			h.Write(in)
			h.Sum(nil)
		}
	})
	b.Run("JH-256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := jh.New256()
			h.Write(in)
			h.Sum(nil)
		}
	})
	b.Run("Skein-256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := skein.New256(nil)
			h.Write(in)
			h.Sum(nil)
		}
	})
}
