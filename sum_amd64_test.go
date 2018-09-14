package cryptonight

import (
	"testing"
)

func TestSumWithoutAESNI(t *testing.T) {
	if !hasAES {
		t.Skip("host does not support AES-NI")
	}

	hasAES = false
	testSum(t, new(cache).sum)
	hasAES = true
}

func TestSumAsm(t *testing.T) {
	if !hasAES {
		t.Skip("host does not support AES-NI")
	}

	testSum(t, new(cache).sumAsm)
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
