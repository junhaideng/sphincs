package merkle

import (
	"github.com/stretchr/testify/assert"
	"testing"
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

	sk := [128]byte{}
	err = tree.SetSk(sk[:])
	assert.Nil(err)

	// height 3, 2, 1 , as the sk is the same, each level hash value(pk) is the same
	// 0 -> height 3
	// 1 2 -> height 2
	// 3 4 5 6 -> height 1

	value := [][]byte{{18, 35, 52, 154, 64, 210, 238, 16, 189, 27, 235, 181, 136, 158, 248, 1, 140, 139, 193, 51, 89, 237, 148, 179, 135, 129, 10, 249, 108, 110, 66, 104}, {46, 235, 116, 166, 23, 127, 88, 141, 128, 192, 199, 82, 185, 149, 86, 144, 45, 223, 150, 130, 208, 185, 6, 245, 170, 42, 219, 175, 132, 102, 164, 233}, {102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37}}

	path := tree.AuthenticationPath(3, 0)
	assert.True(len(path) == 0)

	path2 := tree.AuthenticationPath(2, 0)
	assert.Equal(1, len(path2))
	assert.Equal(path2[0], value[1])

	path3 := tree.AuthenticationPath(1, 0)
	assert.Equal(2, len(path3))
	assert.Equal(path3, value[1:])

	path4 := tree.AuthenticationPath(1, 1)
	assert.Equal(2, len(path4))
	assert.Equal(path4, value[1:])
}
