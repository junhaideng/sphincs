package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHorsSignature(t *testing.T) {
	assert := assert.New(t)
	h, err := NewHorsSignature(16, 32)
	assert.Nil(err)

	sk, pk := h.GenerateKey()

	msg := []byte("Hello World")
	signature := h.Sign(msg, sk)

	assert.True(h.Verify(msg, pk, signature))
}

func TestHorsSignature2(t *testing.T) {
	assert := assert.New(t)
	h, err := NewHorsSignature(8, 64)
	assert.Nil(err)

	sk, pk := h.GenerateKey()

	msg := []byte("Hello World")
	signature := h.Sign(msg, sk)

	assert.True(h.Verify(msg, pk, signature))
}

func TestHorsSignatureError(t *testing.T) {
	assert := assert.New(t)
	_, err := NewHorsSignature(4, 64)
	assert.NotNil(err)
}

func BenchmarkHors(b *testing.B) {
	t := []int{16, 8}
	k := []int{32, 64}
	n := 256
	for i, v := range t {
		// WOTS 签名算法
		hors, err := NewHorsSignature(v, k[i])
		if err != nil {
			panic(err)
		}
		b.Run("key-gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = hors.GenerateKey()
				//sk, pk := w.GenerateKey()
				//b.Log(len(sk), len(pk))
			}
		})
		sk, pk := hors.GenerateKey()
		b.Logf("sk: %d, pk: %d\n", len(sk), len(pk))

		msg := make([]byte, n)
		b.Run("msg-sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = hors.Sign(msg, sk)
			}
		})

		sigma := hors.Sign(msg, pk)
		b.Logf("sigma: %d\n", len(sigma))

		b.Run("verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = hors.Verify(msg, pk, sigma)
			}
		})
	}
}
