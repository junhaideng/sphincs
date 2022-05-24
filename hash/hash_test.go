package hash

import "testing"

type HashArgs struct {
	msg [][]byte
}

func BenchmarkHash(b *testing.B) {
	block := []int{34, 67, 133, 265, 66, 131, 261, 522}
	data := make([][]byte, len(block)*2)
	for i, b := range block {
		data[i*2] = make([]byte, b*256/8)
		data[i*2+1] = make([]byte, b*512/8)
	}

	for j, v := range block {
		b.Logf("block num: %d\n", v)
		b.Run("sha256", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = Sha256(data[j*2])
			}
		})

		b.Run("sha512", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = Sha512(data[j*2+1])
			}
		})
	}
}
