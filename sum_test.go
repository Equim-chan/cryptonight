package cryptonight

import (
	"encoding/hex"
	"testing"
)

func runRef(t *testing.T, hashSpecs []hashSpec) {
	for i, v := range hashSpecs {
		in, _ := hex.DecodeString(v.input)
		result := new(cache).sumGo(in, v.variant)
		if hex.EncodeToString(result) != v.output {
			t.Errorf("\n[%d] expected:\n\t%s\ngot:\n\t%x\n", i, v.output, result)
		}
	}
}

func TestSumRef(t *testing.T) {
	t.Run("v0", func(t *testing.T) { runRef(t, hashSpecsV0) })
	t.Run("v1", func(t *testing.T) {
		runRef(t, hashSpecsV1)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected to panic, got nothing.")
				}
			}()

			new(cache).sumGo([]byte("Obviously less than 43 bytes"), 1)
		}()
	})
	t.Run("v2", func(t *testing.T) { runRef(t, hashSpecsV2) })
}

func BenchmarkSumRef(b *testing.B) {
	b.Run("v0", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			new(cache).sumGo(benchData[i&0x03], 0)
		}
	})
	b.Run("v1", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			new(cache).sumGo(benchData[i&0x03], 1)
		}
	})
	b.Run("v2", func(b *testing.B) {
		b.N = 100
		for i := 0; i < b.N; i++ {
			new(cache).sumGo(benchData[i&0x03], 2)
		}
	})

	b.Run("v0-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				new(cache).sumGo(benchData[i&0x03], 0)
				i++
			}
		})
	})
	b.Run("v1-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				new(cache).sumGo(benchData[i&0x03], 1)
				i++
			}
		})
	})
	b.Run("v2-parallel", func(b *testing.B) {
		b.N = 100
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				new(cache).sumGo(benchData[i&0x03], 2)
				i++
			}
		})
	})
}
