package cryptonight

import (
	"encoding/hex"
	"testing"
)

func runAsm(t *testing.T, hashSpecs []hashSpec) {
	for i, v := range hashSpecs {
		in, _ := hex.DecodeString(v.input)
		result := new(cache).sumAsm(in, v.variant)
		if hex.EncodeToString(result) != v.output {
			t.Errorf("\n[%d] expected:\n\t%s\ngot:\n\t%x\n", i, v.output, result)
		}
	}
}

func TestSumAsm(t *testing.T) {
	if !hasAES {
		t.Skip("host does not support AES-NI")
	}

	t.Run("v0", func(t *testing.T) { runAsm(t, hashSpecsV0) })
	t.Run("v1", func(t *testing.T) {
		runAsm(t, hashSpecsV1)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected to panic, got nothing.")
				}
			}()

			new(cache).sumAsm([]byte("Obviously less than 43 bytes"), 1)
		}()
	})
	t.Run("v2", func(t *testing.T) { runAsm(t, hashSpecsV2) })
}

func BenchmarkSumAsm(b *testing.B) {
	if !hasAES {
		b.Skip("host does not support AES-NI")
	}

	b.Run("v0", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			new(cache).sumAsm(benchData[i&0x03], 0)
		}
	})
	b.Run("v1", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			new(cache).sumAsm(benchData[i&0x03], 1)
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			new(cache).sumAsm(benchData[i&0x03], 2)
		}
	})

	b.Run("v0-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				new(cache).sumAsm(benchData[i&0x03], 0)
				i++
			}
		})
	})
	b.Run("v1-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				new(cache).sumAsm(benchData[i&0x03], 1)
				i++
			}
		})
	})
	b.Run("v2-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				new(cache).sumAsm(benchData[i&0x03], 2)
				i++
			}
		})
	})
}
