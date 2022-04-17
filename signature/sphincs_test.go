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
