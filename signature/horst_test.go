package signature

import (
	"math/rand"
	"testing"

	"github.com/junhaideng/sphincs/hash"
	"github.com/stretchr/testify/assert"
)

func Test_calc(t *testing.T) {
	assert := assert.New(t)

	// for SPHINCS-256
	assert.Equal(6, calc(32, 16))
}

func TestHorstSignature(t *testing.T) {
	assert := assert.New(t)
	seed := make([]byte, 256/8)
	// 2*n*tau/8
	mask := make([]byte, 2*256*16/8)
	for i := 0; i < len(mask); i++ {
		mask[i] = byte(rand.Intn(128))
	}
	horst, err := NewHorstSignature(16, 32, seed, mask)
	assert.Nil(err)
	sk, pk := horst.GenerateKey()

	// msg 应该有 512 bits
	msg := make([]byte, 512/8)
	msg = hash.Sha512(msg)
	sign := horst.Sign(msg, sk)
	//t.Logf("%x\n%x\n", pk, sign)
	assert.Equal(true, horst.Verify(msg, pk, sign))

	msg = hash.Sha512([]byte("hello world"))
	sign = horst.Sign(msg, sk)
	//t.Logf("%x\n%x\n", pk, sign)
	assert.Equal(true, horst.Verify(msg, pk, sign))

	msg = hash.Sha512([]byte("horst signature"))
	sign = horst.Sign(msg, sk)
	//t.Logf("%x\n%x\n", pk, sign)
	assert.Equal(true, horst.Verify(msg, pk, sign))

}

func TestGetIndex(t *testing.T) {
	assert := assert.New(t)

	// 假设一棵树，高度为 4
	//           0
	//     1            2
	//  3    4       5     6
	// 7 8  9 10   11 12  13 14
	assert.Equal(1, getIndex(7, 2))
	assert.Equal(0, getIndex(8, 3))
	assert.Equal(2, getIndex(11, 2))

	assert.Equal(4, getIndex(9, 1))
	assert.Equal(2, getIndex(13, 2))
}

type horstArgs struct {
	tau, k     int
	seed, mask []byte
}

func BenchmarkHorst(b *testing.B) {
	args := []horstArgs{
		{
			16, 32, make([]byte, 32), make([]byte, 32*2*16),
		},
		{
			8, 64, make([]byte, 32), make([]byte, 32*2*8),
		},
		{
			16, 16, make([]byte, 32), make([]byte, 32*2*16),
		},
		{
			8, 32, make([]byte, 32), make([]byte, 32*2*8),
		},
	}
	msg := make([]byte, 512)
	for _, v := range args {
		// HORST 签名算法
		horst, err := NewHorstSignature(v.tau, v.k, v.seed, v.mask)
		if err != nil {
			panic(err)
		}
		b.Run("key-gen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = horst.GenerateKey()
				//sk, pk := w.GenerateKey()
				//b.Log(len(sk), len(pk))
			}
		})
		sk, pk := horst.GenerateKey()
		b.Logf("sk: %d, pk: %d\n", len(sk), len(pk))

		b.Run("msg-sign", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = horst.Sign(msg, sk)
			}
		})

		sigma := horst.Sign(msg, pk)
		b.Logf("sigma: %d\n", len(sigma))

		b.Run("verify", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = horst.Verify(msg, pk, sigma)
			}
		})
	}
}
