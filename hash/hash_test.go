package hash

import "testing"

func BenchmarkHash(b *testing.B) {
	msg := make([]byte, 256 * 66)

	b.Run("sha256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = Sha256(msg)
		}
	})

	b.Run("sha512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = Sha512(msg)
		}
	})
}
