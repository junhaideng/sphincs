package merkle

import (
	"errors"
	"fmt"
	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
)

// Node represents Merkle node
type Node struct {
	value []byte
}

// Tree is a Merkle tree
// height = 3
// layer 0         *
// layer 1     *       *
// layer 2   *   *   *    *
type Tree struct {
	nodes  []*Node
	height int
	total  int
	hash   hash.Hash
	n      int
	// TODO: bytes pool, for tree.h function
	// bytes length is n/8
	mask []byte
}

// NewTree returns a tree with height h
// n specifies hash function
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
		nodes[i] = &Node{}
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

func NewTreeWithMask(height, n int, mask []byte) (*Tree, error) {
	t, err := NewTree(height, n)
	if err != nil {
		return nil, err
	}
	t.mask = mask
	return t, nil
}

// SetSk sets secret key, each secret key has n bits
func (t *Tree) SetSk(sk []byte) error {
	n := t.n / 8
	if len(sk) != (1<<(t.height-1))*n {
		return fmt.Errorf("sk should have %d bytes, but got %d", (1<<(t.height-1))*n, len(sk))
	}

	// 叶子节点第一个节点的索引值
	diff := 1<<(t.height-1) - 1

	// 设置叶子节点的私钥
	for i := diff; i < t.total; i++ {
		// leave are the hash value of secret key
		t.nodes[i].value = t.hash(sk[(i-diff)*n : (i-diff+1)*n])
	}

	// compute root
	for i := diff - 1; i >= 0; i-- {
		left := t.nodes[2*i+1].value
		right := t.nodes[2*i+2].value
		t.nodes[i].value = t.h(left, right)
	}
	return nil
}

// SetSkWithMask sets secret key, each secret key has n bits
func (t *Tree) SetSkWithMask(sk []byte) error {
	n := t.n / 8
	if len(sk) != (1<<(t.height-1))*n {
		return fmt.Errorf("sk should have %d bytes, but got %d", (1<<(t.height-1))*n, len(sk))
	}

	// 叶子节点第一个节点的索引值
	diff := 1<<(t.height-1) - 1

	// 设置叶子节点的私钥
	for i := diff; i < t.total; i++ {
		// leave are the hash value of secret key
		t.nodes[i].value = t.hash(sk[(i-diff)*n : (i-diff+1)*n])
	}

	// compute root
	// TODO 加入 mask 进行计算
	// mask 一共是 2 * height * n bits
	// 每一个 mask block 是 n bits
	// 每一层使用一对 mask
	// 左节点和 mask_i[0] 进行异或
	// 右结点和 mask_i[1] 进行异或
	xor := common.Xor
	for i := diff - 1; i >= 0; i-- {
		// 判断是第几层，从 0 开始，根节点为 0 层
		layer := common.BitCount(uint64(i+1)) - 1
		left := t.nodes[2*i+1].value
		right := t.nodes[2*i+2].value

		t.nodes[i].value = t.h(
			xor(left, t.mask[(2*layer)*t.n/8:(2*layer+1)*t.n/8]),
			xor(right, t.mask[(2*layer+1)*t.n/8:(2*layer+2)*t.n/8]),
		)
	}
	return nil
}

func (t *Tree) h(a []byte, b []byte) []byte {
	tmp := make([]byte, len(a)+len(b))
	copy(tmp[:len(a)], a)
	copy(tmp[len(a):], b)
	return t.hash(tmp)
}

// AuthenticationPath 返回私钥的鉴权路径
// h 表示到第 h 层结束，这里设根节点层级为 0
// index 从 0 开始
// 如果存在路径(指路径不为0)，则叶子节点为返回值的第一个位置
func (t *Tree) AuthenticationPath(h int, index int) [][]byte {
	if h == t.height-1 {
		return [][]byte{}
	}
	// 首先找到节点在数组中的位置
	// 最底层第一个节点的索引值
	start := 1<<(t.height-1) - 1

	i := start + index

	res := make([][]byte, t.height-1-h)
	k := 0

	// 第 h 层的最后一个节点索引
	end := 1<<(h+1) - 2
	// j > end 就表示 j 还没有到 h 层
	// 鉴权路径是不会包含第 h 层的节点数据的
	for j := i; j > end; j = (j - 1) / 2 {
		if j&1 != 0 {
			// j 是奇数，那么肯定是左节点
			res[k] = t.nodes[j+1].value
		} else {
			//	j 是偶数，为右结点
			res[k] = t.nodes[j-1].value
		}
		k++
	}

	return res
}

func (t *Tree) GetPk() ([]byte, error) {
	pk := t.nodes[0].value
	if t.nodes[0].value == nil {
		return nil, errors.New("please set secret keys firstly")
	}
	return pk, nil
}

// GetLeaf 获取叶子节点的值
func (t *Tree) GetLeaf(index int) ([]byte, error) {
	// 叶子节点包含的数量:
	max := 1 << (t.height - 1)
	if index < 0 || index >= max {
		return nil, errors.New("叶子节点索引非法")
	}
	start := 1<<(t.height-1) - 1
	return t.nodes[start+index].value, nil
}

func (t Tree) Print() {
	for i := 1; i <= t.height; i++ {
		for j := 0; j < (1 << (i - 1)); j++ {
			fmt.Print(t.nodes[1<<(i-1)-1+j].value, "\t")
		}
		fmt.Println()
	}
}

// ComputeRoot 通过鉴权路径和私钥，计算出根节点
// 注意这里的 path 中的节点数据从上到下
// index 为 sk 在树中的总索引，并不一定从 0 开始
func ComputeRoot(sk []byte, index int, path [][]byte, h hash.Hash) []byte {
	ret := make([]byte, len(sk))
	copy(ret, h(sk))

	for i := 0; i < len(path); i++ {
		// 奇数
		if index&1 != 0 {
			ret = hash.CombineAndHash(ret, path[i], h)
		} else {
			ret = hash.CombineAndHash(path[i], ret, h)
		}
		index = (index - 1) / 2
	}

	return ret
}

// Layer 返回树中第 i 层的节点数据
// i 从 0 开始
func (t *Tree) Layer(i int) [][]byte {
	// 这一层节点个数
	num := 1 << i
	res := make([][]byte, num)
	start := 1<<i - 1
	for k := 0; k < num; k++ {
		res[k] = t.nodes[start+k].value
	}
	return res
}

func (t *Tree) Nodes() [][]byte {
	res := make([][]byte, len(t.nodes))
	for i := 0; i < len(t.nodes); i++ {
		res[i] = t.nodes[i].value
	}
	return res
}
