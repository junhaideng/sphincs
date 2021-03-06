package signature

import (
	"errors"
	"testing"

	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
	"github.com/stretchr/testify/assert"
)

// just for test
func newWinternitzSignature(w int, n Size) (*Winternitz, error) {
	if 8%w != 0 {
		return nil, errors.New("w should be a divisor of 8")
	}
	if n != Size256 && n != Size512 {
		return nil, common.ErrSizeNotSupport
	}
	// meet above conditions, then n can be divided by w
	l1 := int(n) / w

	l2_ := l2(l1, w)
	win := &Winternitz{
		n:    n,
		w:    w,
		hash: hash.Sha256,
		l1:   l1,
		l2:   l2_,
	}
	if n == Size512 {
		win.hash = hash.Sha512
	}
	return win, nil
}

func TestBaseW2(t *testing.T) {
	assert := assert.New(t)
	w, _ := newWinternitzSignature(2, Size256)
	input := []byte{'a'} // 0110_0001
	res := []byte{0x1, 0x2, 0x0, 0x1}
	assert.Equal(res, w.baseW(input, 4))
}

func TestBaseW4(t *testing.T) {
	assert := assert.New(t)
	w, _ := newWinternitzSignature(4, Size256)
	input := []byte("a") // 0110_0001
	res := []byte{0x6, 0x1}
	assert.Equal(res, w.baseW(input, 2))
}

func TestBaseW8(t *testing.T) {
	assert := assert.New(t)
	w, _ := newWinternitzSignature(8, Size256)
	input := []byte("a") // 0110_0001
	res := []byte{'a'}
	assert.Equal(res, w.baseW(input, 1))
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

// benchmarks
// go test github.com/junhaideng/sphincs/signature -bench BenchmarkWOTSGenerateKey -benchtime=100000x -benchmem -count=1 -timeout=60m
func BenchmarkWOTS(b *testing.B) {
	values := []int{1, 2, 4} // ?????? w ????????? 2, 4, 16
	for _, v := range values {
		// WOTS ????????????
		w, err := NewWinternitzSignature(v, 256)
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

		msg := make([]byte, 256)
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
