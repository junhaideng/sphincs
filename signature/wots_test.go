package signature

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

// just for test
func newWinternitzSignature(w int, n Size) (*Winternitz, error) {
	if 8%w != 0 {
		return nil, errors.New("w should be a divisor of 8")
	}
	if n != Size256 && n != Size512 {
		return nil, ErrSizeNotSupport
	}
	// meet above conditions, then n can be divided by w
	l1 := int(n) / w

	l2_ := l2(l1, w)
	win := &Winternitz{
		n:    n,
		w:    w,
		hash: Sha256,
		l1:   l1,
		l2:   l2_,
	}
	if n == Size512 {
		win.hash = Sha512
	}
	return win, nil
}

func TestBaseW2(t *testing.T) {
	assert := assert.New(t)
	w, _ := newWinternitzSignature(2, Size256)
	input := []byte("a") // 0110_0001
	res := []byte{0x1, 0x2, 0x0, 0x1}
	assert.Equal(res, w.baseW(input))
}

func TestBaseW4(t *testing.T) {
	assert := assert.New(t)
	w, _ := newWinternitzSignature(4, Size256)
	input := []byte("a") // 0110_0001
	res := []byte{0x6, 0x1}
	assert.Equal(res, w.baseW(input))
}

func TestBaseW8(t *testing.T) {
	assert := assert.New(t)
	w, _ := newWinternitzSignature(8, Size256)
	input := []byte("a") // 0110_0001
	res := []byte{'a'}
	assert.Equal(res, w.baseW(input))
}

func TestWinternitzSignature(t *testing.T) {
	assert := assert.New(t)
	w, err := NewWinternitzSignature(4, Size256)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

func TestWinternitzSignature2(t *testing.T) {
	assert := assert.New(t)
	w, err := NewWinternitzSignature(4, Size512)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

func TestWinternitzSignature3(t *testing.T) {
	assert := assert.New(t)
	w, err := NewWinternitzSignature(8, Size256)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}

func TestWinternitzSignature4(t *testing.T) {
	assert := assert.New(t)
	w, err := NewWinternitzSignature(8, Size512)
	assert.Nil(err)

	msg := []byte("Hello World")
	sk, pk := w.GenerateKey()

	signature := w.Sign(msg, sk)

	assert.True(w.Verify(msg, pk, signature))
}
