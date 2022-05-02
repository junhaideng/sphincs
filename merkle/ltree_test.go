package merkle

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/junhaideng/sphincs/hash"
	"github.com/stretchr/testify/assert"
)

func TestLTree1(t *testing.T) {
	assert := assert.New(t)
	// 叶子节点都是 ASCII 编码 0
	pk := make([]byte, 16*256/8)
	n := 256
	assert.Equal("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c", hex.EncodeToString(LTree(pk, n, hash.Sha256)))
}

func TestLTree2(t *testing.T) {
	assert := assert.New(t)
	// 叶子节点都是 ASCII 编码 0
	pk := make([]byte, 16*512/8)
	n := 512
	assert.Equal("287738662c91f7b10df589979c43737d5dd0d9c516152c3361964ee6c2f50b3c80646a313d90567df0f34cd7dcad215821a819bb9404b4d9aa210599c8673023", hex.EncodeToString(LTree(pk, n, hash.Sha512)))
}

func TestLTree3(t *testing.T) {
	assert := assert.New(t)
	// 叶子节点都是 ASCII 编码 0
	pk := make([]byte, 16*256/8)
	for i := 0; i < len(pk); i++ {
		pk[i] = '-'
	}
	n := 256
	assert.Equal("e13818e0c3bde75b907cab6696ab297d60e3c17b7bd5ff21c3d7d20f79e5b1d6", hex.EncodeToString(LTree(pk, n, hash.Sha256)))
}

func TestLTree4(t *testing.T) {
	assert := assert.New(t)
	// 叶子节点都是 ASCII 编码 0
	pk := make([]byte, 16*512/8)
	for i := 0; i < len(pk); i++ {
		pk[i] = '-'
	}
	n := 512
	assert.Equal("b32aaaa44a979603301a530fe4c5e8e70abfb4075c2bd5ef0a7636041b97f9cf6ac007ce57b47a109cd361f893ba5a806d6e366724060902ad03977a69f58063", hex.EncodeToString(LTree(pk, n, hash.Sha512)))
}

// bytes 中的每一个元素长度都是一致的
func chainHash(bytes []byte, h hash.Hash) []byte {
	return h(bytes)
}

func genBytes(row, col int) []byte {
	ret := make([]byte, row*col)
	rand.Read(ret)
	return ret
}

type TreeAndChainHash struct {
	pk []byte
	n  int
	h  hash.Hash
}

func BenchmarkTreeHashAndChainHash(b *testing.B) {
	args := make([]TreeAndChainHash, 0)
	start := 6 
	end := 14
	for i := start; i <= end; i++ {
		args = append(args, TreeAndChainHash{
			genBytes(1<<i, 32), // 32 bytes = 256 bits
			256,
			hash.Sha256,
		})
	}

	for i := start; i <= end; i++ {
		args = append(args, TreeAndChainHash{
			genBytes(1<<i, 64),  // 64 bytes = 512 bits
			512,
			hash.Sha512,
		})
	}

	for _, arg := range args {
		b.Run("chain hash", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = chainHash(arg.pk, arg.h)
			}
		})

		b.Run("tree hash", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = LTree(arg.pk, arg.n, arg.h)
			}
		})
	}
}
