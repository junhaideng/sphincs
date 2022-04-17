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
