package signature

import (
	"math/rand"
	"testing"

	"github.com/junhaideng/sphincs/common"
	"github.com/stretchr/testify/assert"
)

// go test -v -run TestWinternitzPlus.* ./...
func TestWinternitzPlushSignature(t *testing.T) {
	// mask 的大小为 n  * (2^w-1) bits
	mask := make([]byte, 256/8*(1<<4-1))
	for i := 0; i < len(mask); i++ {
		mask[i] = byte(rand.Intn(128))
	}
	assert := assert.New(t)
	w, err := NewWOTSPlusSignature(4, Size256, []byte("fda"), mask)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

func TestWinternitzPlusSignature2(t *testing.T) {
	// mask 的大小为 n  * (2^w-1) bits
	mask := make([]byte, 512/8*(1<<4-1))
	assert := assert.New(t)
	w, err := NewWOTSPlusSignature(4, Size512, []byte("fa"), mask)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

func TestWinternitzPlusSignature3(t *testing.T) {
	// mask 的大小为 n  * (2^w-1) bits
	mask := make([]byte, 256/8*(1<<8-1))
	assert := assert.New(t)
	w, err := NewWOTSPlusSignature(8, Size256, []byte("fdsa"), mask)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

func TestWinternitzPlusSignature4(t *testing.T) {
	// mask 的大小为 n  * (2^w-1) bits
	mask := make([]byte, 512/8*(1<<8-1))
	assert := assert.New(t)
	w, err := NewWOTSPlusSignature(8, Size512, []byte("hello"), mask)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

type wotsArgs struct {
	w    int
	n    common.Size
	seed []byte
	mask []byte
}

func BenchmarkWOTSPlus(b *testing.B) {
	args := []wotsArgs{
		{
			1, 256, make([]byte, 256/8), make([]byte, 256*(1<<1-1)/8),
		},
		{
			2, 256, make([]byte, 256/8), make([]byte, 256*(1<<2-1)/8),
		},
		{
			4, 256, make([]byte, 256/8), make([]byte, 256*(1<<4-1)/8),
		},
	}
	msg := make([]byte, 512)
	for _, v := range args {
		// WOTS+ 签名算法
		w, err := NewWOTSPlusSignature(v.w, v.n, v.seed, v.mask)
		if err != nil {
			panic(err)
		}
		b.Run("key-gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = w.GenerateKey()
				//sk, pk := w.GenerateKey()
				//b.Log(len(sk), len(pk))
			}
		})
		sk, pk := w.GenerateKey()
		b.Logf("sk: %d, pk: %d\n", len(sk), len(pk))

		b.Run("msg-sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = w.Sign(msg, sk)
			}
		})

		sigma := w.Sign(msg, pk)
		b.Logf("sigma: %d\n", len(sigma))

		b.Run("verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = w.Verify(msg, pk, sigma)
			}
		})
	}
}
