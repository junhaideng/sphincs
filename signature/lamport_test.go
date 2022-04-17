package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLamportSignature256(t *testing.T) {
	assert := assert.New(t)
	l, err := NewLamportSignature(Size256)
	assert.Nil(err, "Create lamport signature failed: %s", err)

	msg := []byte("Hello World")
	sk, pk := l.GenerateKey()

	signature := l.Sign(msg, sk)
	// t.Logf("msg: %s, signature: %x", msg, signature)

	assert.True(l.Verify(msg, pk, signature), "Verify message failed")
}

func TestLamportSignature512(t *testing.T) {
	assert := assert.New(t)
	l, err := NewLamportSignature(Size512)
	assert.Nil(err, "Create lamport signature failed: %s", err)

	msg := []byte("Hello World")
	sk, pk := l.GenerateKey()

	signature := l.Sign(msg, sk)
	// t.Logf("msg: %s, signature: %x", msg, signature)

	assert.True(l.Verify(msg, pk, signature), "Verify message failed")
}
