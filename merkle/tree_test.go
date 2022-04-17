package merkle

import (
	"crypto/sha256"
	"crypto/sha512"
	"math/rand"
	"testing"

	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
	"github.com/stretchr/testify/assert"
)

func TestMerkleTree(t *testing.T) {
	assert := assert.New(t)
	tree, err := NewTree(3, 256)
	assert.Nil(err)

	sk := [128]byte{}
	err = tree.SetSk(sk[:])
	assert.Nil(err)
}

func TestTreeAuthenticationPath(t *testing.T) {
	assert := assert.New(t)

	tree, err := NewTree(3, 256)
	assert.Nil(err)

	// 每一个节点包含的哈希值长度为 32 bytes
	// 高度为3，底部一共 4 个节点，共 32*4 bytes
	sk := [128]byte{}
	err = tree.SetSk(sk[:])
	assert.Nil(err)

	value := [][]byte{
		{102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37},     // 叶子节点的哈希值
		{46, 235, 116, 166, 23, 127, 88, 141, 128, 192, 199, 82, 185, 149, 86, 144, 45, 223, 150, 130, 208, 185, 6, 245, 170, 42, 219, 175, 132, 102, 164, 233}, // height = 1 的节点哈希值
	}

	path2 := tree.AuthenticationPath(2, 0)
	assert.Equal(0, len(path2))

	path3 := tree.AuthenticationPath(1, 0)
	assert.Equal(1, len(path3))
	assert.Equal(path3, value[:1])
	//
	path4 := tree.AuthenticationPath(1, 1)
	assert.Equal(1, len(path4))
	assert.Equal(path4, value[:1])

	path5 := tree.AuthenticationPath(0, 0)
	assert.Equal(2, len(path5))
	assert.Equal(value[:2], path5)

	path6 := tree.AuthenticationPath(1, 3)
	assert.Equal(1, len(path6))
	assert.Equal(path6, value[:1])
}

func TestTree_SetSkWithMask(t *testing.T) {
	// 256 bits * 2(layer) * 2 (left, right)
	mask := make([]byte, 32*2*2)
	for i := 0; i < len(mask); i++ {
		mask[i] = byte(rand.Intn(128))
	}

	sk := make([]byte, 128)
	for i := 0; i < len(sk); i++ {
		sk[i] = byte(rand.Intn(128))
	}

	tree, err := NewTreeWithMask(3, 256, mask)
	assert.Nil(t, err)

	err = tree.SetSkWithMask(sk)
	assert.Nil(t, err)

	path := tree.AuthenticationPath(0, 0)

	assert.Equal(t, 2, len(path))

	root, err := tree.GetPk()
	assert.Nil(t, err)

	sk_, err := tree.GetLeaf(0)
	assert.Nil(t, err)

	assert.True(t, common.Equal(sk_, hash.Sha256(sk[:32])))

	root_ := ComputeRootWithMask(sk[:32], 3, path, hash.Sha256, common.Ravel(mask, 256/8))

	assert.True(t, common.Equal(root, root_))
	t.Logf("tree: %x\n", tree.Nodes())
	t.Logf("auth: %x\n", path)
	t.Logf("root: %x", root)
	t.Logf("root_: %x", root_)
}

func TestTree_GetLeaf(t *testing.T) {
	leaf := []byte{102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37}

	assert := assert.New(t)

	tree, err := NewTree(3, 256)
	assert.Nil(err)

	// 每一个节点包含的哈希值长度为 32 bytes
	// 高度为3，底部一共 4 个节点，共 32*4 bytes
	sk := [128]byte{}
	err = tree.SetSk(sk[:])
	assert.Nil(err)

	ret, _ := tree.GetLeaf(0)
	assert.Equal(ret, leaf)

	ret, _ = tree.GetLeaf(1)
	assert.Equal(ret, leaf)

	ret, _ = tree.GetLeaf(2)
	assert.Equal(ret, leaf)

	ret, _ = tree.GetLeaf(3)
	assert.Equal(ret, leaf)

	ret, err = tree.GetLeaf(4)
	t.Logf("%#v\n", err)
	assert.Nil(ret)
	assert.NotNil(err)
}

func TestComputeRoot(t *testing.T) {
	assert := assert.New(t)

	tree, err := NewTree(3, 256)
	assert.Nil(err)

	sk := [128]byte{}
	err = tree.SetSk(sk[:])
	assert.Nil(err)

	value := [][]byte{
		{102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37},     // 叶子节点的哈希值
		{46, 235, 116, 166, 23, 127, 88, 141, 128, 192, 199, 82, 185, 149, 86, 144, 45, 223, 150, 130, 208, 185, 6, 245, 170, 42, 219, 175, 132, 102, 164, 233}, // height = 1 的节点哈希值
	}

	path := tree.AuthenticationPath(0, 0)
	assert.Equal(2, len(path))
	assert.Equal(value[:2], path)

	root, _ := tree.GetPk()
	root_ := ComputeRoot(make([]byte, 32), 0+1<<(tree.height-1)-1, path, hash.Sha256)
	assert.Equal(root, root_)

	// ----
	path = tree.AuthenticationPath(0, 2)
	assert.Equal(2, len(path))
	assert.Equal(value[:2], path)

	root, _ = tree.GetPk()
	root_ = ComputeRoot(make([]byte, 32), 2+1<<(tree.height-1)-1, path, hash.Sha256)
	assert.Equal(root, root_)
}

func BenchmarkTreeAuthenticationPath(b *testing.B) {

	tree, _ := NewTree(3, 256)

	sk := [128]byte{}
	tree.SetSk(sk[:])

	b.Run("3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.AuthenticationPath(3, 3)
		}
	})

	b.Run("2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.AuthenticationPath(2, 0)
		}
	})
	b.Run("1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.AuthenticationPath(1, 0)
		}
	})
	b.Run("4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tree.AuthenticationPath(1, 1)
		}
	})

}

func BenchmarkCompare(b *testing.B) {
	sk := make([]byte, 0)
	for i := 0; i < 16; i++ {
		sk = append(sk, []byte("0123456789_0123456789_0123456789_0123456789")[:32]...)
	}

	// 16 * 32
	b.Run("256-tree", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			t, _ := NewTree(4, 256)
			_ = t.SetSk(sk)
			_, _ = t.GetPk()
		}
	})

	b.Run("256-chain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := sha256.New()
			h.Write(sk)
			_ = h.Sum(nil)
		}
	})

	for i := 0; i < 16; i++ {
		sk = append(sk, []byte("0123456789_0123456789_0123456789_0123456789")[:32]...)
	}

	b.Run("512-tree", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			t, _ := NewTree(4, 512)
			_ = t.SetSk(sk)
			_, _ = t.GetPk()
		}
	})

	b.Run("512-chain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			h := sha512.New()
			h.Write(sk)
			_ = h.Sum(nil)
		}
	})
}
