package signature

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSphincs(t *testing.T) {
	assert := assert.New(t)
	seed := make([]byte, 32)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(rand.Intn(128))
	}
	// w 为 4，和论文中稍有不太，这里采用的是指数
	// 仅支持 n = 256 ，m = 512
	sphincs, err := NewSphincs(256, 512, 60, 12, 4, 16, 32, seed)
	assert.Nil(err)

	sk, pk := sphincs.GenerateKey()
	//t.Logf("sk: %d, pk: %d \n", len(sk), len(pk))
	//t.Logf("sk:\n %x\n, pk:\n %x\n\n", sk, pk)
	message := []byte("hello world")
	sign := sphincs.Sign(message, sk)
	//t.Logf("len: %d\n", len(sign))

	assert.True(sphincs.Verify(message, pk, sign))

	message = []byte("sphincs")
	sign = sphincs.Sign(message, sk)
	assert.True(sphincs.Verify(message, pk, sign))

	// 创建一个新的，用来校验
	sphincs, err = NewSphincs(256, 512, 60, 12, 4, 16, 32, seed)
	assert.True(sphincs.Verify(message, pk, sign))

}

type sphincsArgs struct {
	n, m, h, d, w, tau, k uint64
	seed                  []byte
}

func BenchmarkSphincs(b *testing.B) {
	args := []sphincsArgs{
		{
			256, 512, 60, 12, 4, 16, 32, make([]byte, 256), // SPHINCS-256
		},
		{
			256, 512, 60, 6, 4, 16, 32, make([]byte, 256), // 调整 d
		},
		{
			256, 512, 60, 10, 4, 16, 32, make([]byte, 256), // 调整 d
		},
		{
			256, 512, 60, 12, 2, 16, 32, make([]byte, 256), // 调整 w
		},
		{
			256, 512, 60, 12, 8, 16, 32, make([]byte, 256), // 调整 w
		},
		{
			256, 512, 60, 12, 4, 8, 64, make([]byte, 256), // 调整 t, k
		},
	}
	msg := make([]byte, 512)
	for _, v := range args {
		// HORST 签名算法
		horst, err := NewSphincs(v.n, v.m, v.h, v.d, v.w, v.tau, v.k, v.seed)
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
