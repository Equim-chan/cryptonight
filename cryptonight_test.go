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
		{"5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374", "2e6ee8cc718c61d3a59ecdfca6e56ca5f560b4bb75c201ed3bb001c407833e79", 2},
		{"4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67", "35957227ce70064db4c1b5ece364282fd5425bf4fee5a0e3595b9f3f5067b90b", 2},
		{"656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265", "f6398c333cb775cbf81fbb1043f0d7c791dac5bf6182f6ad782ba11fe6c7234f", 2},
		{"657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c", "5bb096fc037aabc50d7e84b356ea673357684e7d29395bd32b876440efcbaf72", 2},
		{"71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369", "f3e44470ff4bc947c4cb020168d636fc894c3c07629266b93e2fbcf42d9664a5", 2},
		{"757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465", "13d3dc2794414932050ff7b165de51b283018990f111c3191bca66fe986fdab9", 2},
		{"697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974", "9fcaa9892f1faef36624d865cb7e7588b4b74fc581b7195b586b3b0e802b72b8", 2},
		{"657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e", "30c262cf4592136088dcf1064b732c29550b46accf54d7993d8532f5a5a9e0f3", 2},
		{"4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c", "88536691d2d8eb6c8dfbb2597ab50fbbd9f8c2834281e1bb70616f48094d68c8", 2},
		{"73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e", "5964da99f4a273393e464f40070122f045eecfed1309ac25dd322e1fb052dc45", 2},
	}
)

func run(t *testing.T, hashSpecs []hashSpec) {
	for i, v := range hashSpecs {
		in, _ := hex.DecodeString(v.input)
		result := Sum(in, v.variant)
		if hex.EncodeToString(result) != v.output {
			t.Errorf("\n[%d] expected:\n\t%s\ngot:\n\t%x\n", i, v.output, result)
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
	t.Run("v2", func(t *testing.T) { run(t, hashSpecsV2) })
}

func BenchmarkSum(b *testing.B) {
	// the data is special, when run into all v0, v1, v2 proccess, the final hash
	// function is the same (blake-256), so that it can just be a bit more fair.
	data, _ := hex.DecodeString("84cef46e501d92b6c76baa3cae99b142b0a2b9f3ada6c7e438be5b069702659b7e596ab33157a8d325ebb39c56e9906c8e68")

	b.Run("v0", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sum(data, 0)
		}
	})
	b.Run("v1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sum(data, 1)
		}
	})
	b.Run("v2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Sum(data, 2)
		}
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
	b.Run("Groestl-256", func(b *testing.B) {
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
