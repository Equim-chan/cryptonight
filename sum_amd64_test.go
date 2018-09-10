package cryptonight

import (
	"testing"
)

func TestSumWithoutAESNI(t *testing.T) {
	if hasAES {
		hasAES = false
		TestSum(t)
		hasAES = true
	}
}

func TestSumAsm(t *testing.T) {
	if !hasAES {
		t.Skip("host does not support AES-NI")
	}

	t.Run("v0", func(t *testing.T) { run(t, new(cache).sumAsm, hashSpecsV0) })
	t.Run("v1", func(t *testing.T) {
		run(t, new(cache).sumAsm, hashSpecsV1)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected to panic, got nothing.")
				}
			}()

			new(cache).sumAsm([]byte("Obviously less than 43 bytes"), 1)
		}()
	})
	t.Run("v2", func(t *testing.T) { run(t, new(cache).sumAsm, hashSpecsV2) })
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
