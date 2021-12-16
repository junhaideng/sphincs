package merkle

import (
	"errors"
	"fmt"
	"github.com/junhaideng/sphincs/hash"
)

// Node represents Merkle node
type Node struct {
	// index in merkle tree
	index int
	value *Value
}

// Tree is a Merkle tree
type Tree struct {
	nodes  []*Node
	height int
	total  int
	hash   hash.Hash
	n      int
	// TODO: bytes pool, for tree.h function
	// bytes length is n/8
}

// NewTree returns a tree with height h
func NewTree(height int, n int) (*Tree, error) {
	if n != 512 && n != 256 {
		return nil, errors.New("n should be 256 or 512")
	}
	if height < 1 {
		return nil, errors.New("height should not less than 1")
	}
	total := 1<<height - 1
	nodes := make([]*Node, total)
	for i := 0; i < total; i++ {
		nodes[i] = &Node{
			index: i,
			value: &Value{},
		}
	}
	t := &Tree{
		nodes:  nodes,
		height: height,
		total:  total,
		hash:   hash.Sha256,
		n:      n,
	}

	if n == 512 {
		t.hash = hash.Sha512
	}

	return t, nil
}

// SetSk sets secret key, each secret key has n bytes
func (t *Tree) SetSk(sk []byte) error {
	n := t.n / 8
	if len(sk) != (1<<(t.height-1))*n {
		return fmt.Errorf("sk should have %d bytes, but got %d", (1<<(t.height-1))*n, len(sk))
	}

	nodes := t.nodes

	diff := 1<<(t.height-1) - 1
	for i := diff; i < t.total; i++ {
		// leave are the hash value of secret key
		nodes[i].value.sk = sk[(i-diff)*n : (i-diff+1)*n]
		nodes[i].value.pk = t.hash(sk[(i-diff)*n : (i-diff+1)*n])
	}

	// compute root
	for i := diff - 1; i >= 0; i-- {
		left := t.nodes[2*i+1].value.pk
		right := t.nodes[2*i+2].value.pk
		nodes[i].value.pk = t.h(left, right)
	}
	return nil
}

func (t *Tree) h(a []byte, b []byte) []byte {
	tmp := make([]byte, len(a)+len(b))
	copy(tmp[:len(a)], a)
	copy(tmp[len(a):], b)
	return t.hash(tmp)
}

// AuthenticationPath get authentication path
// h is the node height, leaves is 1
// where index is the leave's index from left to right, starts with 0
func (t *Tree) AuthenticationPath(h int, index int) [][]byte {
	// index in the tree
	i := 1<<(t.height-h) - 1 + index
	res := make([][]byte, t.height-h)
	k := len(res) - 1
	for j := i; j > 0; j = (j - 1) / 2 {
		if j&1 != 0 {
			// odd
			res[k] = t.nodes[j+1].value.pk
		} else {
			// even
			res[k] = t.nodes[j-1].value.pk
		}
		k--
	}
	return res
}

func (t *Tree) GetPk() ([]byte, error) {
	pk := t.nodes[0].value.pk
	if t.nodes[0].value.pk == nil {
		return nil, errors.New("please set secret keys firstly")
	}
	return pk, nil
}

func (t Tree) Print() {
	for i := 1; i <= t.height; i++ {
		for j := 0; j < (1 << (i - 1)); j++ {
			fmt.Print(t.nodes[1<<(i-1)-1+j].value.pk, "\t")
		}
		fmt.Println()
	}
}
