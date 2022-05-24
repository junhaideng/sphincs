package signature

import (
	"math/rand"
	"testing"

	"github.com/junhaideng/sphincs/hash"
)

func genRandBytes(n int) []byte {
	res := make([]byte, n)
	for i := 0; i < len(res); i++ {
		res[i] = byte(rand.Intn(128))
	}
	return res
}

func BenchmarkSignature(b *testing.B) {
	msg := make([]byte, 512/8)
	msg = hash.Sha512(msg) // horst 的输入直接为 512 bits，和 sphincs 中的对齐，需要自己先 hash 一波

	var signatureList = make([]Signature, 0)
	//  256, 512, 60, 12, 4, 16, 32

	s, err := NewLamportSignature(256)
	if err != nil {
		panic(err)
	}
	signatureList = append(signatureList, s)

	s, err = NewWinternitzSignature(4, 256)
	if err != nil {
		panic(err)
	}
	signatureList = append(signatureList, s)

	s, err = NewWOTSPlusSignature(4, 256, genRandBytes(32), genRandBytes(32*15))
	if err != nil {
		panic(err)
	}
	signatureList = append(signatureList, s)

	s, err = NewHorsSignature(16, 32)
	if err != nil {
		panic(err)
	}
	signatureList = append(signatureList, s)

	s, err = NewHorstSignature(16, 32, genRandBytes(32), genRandBytes(32*2*16))
	if err != nil {
		panic(err)
	}
	signatureList = append(signatureList, s)

	for i, signature := range signatureList {
		b.Logf("===> %d\n", i)
		b.Run("key-gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = signature.GenerateKey()
			}
		})

		sk, pk := signature.GenerateKey()
		b.Run("msg-sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = signature.Sign(msg, sk)
			}
		})
		sigma := signature.Sign(msg, sk)
		b.Run("sign-verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = signature.Verify(msg, pk, sigma)
			}
		})
	}
}
