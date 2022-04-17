package signature

import (
	"math/rand"
	"testing"

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
