package merkle

import (
	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
)

// LTree 计算 L-Tree 的根节点值
// pk 是所有的公钥块，n 表示每一个公钥块的 bit 数
// 则一共存在 pk / n * 8 个公钥块
// 并且 n 与 hash 函数对应
func LTree(pk []byte, n int, hash hash.Hash) []byte {
	num := len(pk) * 8 / n
	// 找到最接近的 2 的指数数字
	power, _ := common.NearestPowerOf2(num)
	tree := make([][]byte, power)
	// 将 pk 拷贝过去
	for i := 0; i < num; i++ {
		tree[i] = pk[i*(n/8) : (i+1)*(n/8)]
	}

	for power != 1 {
		for i := 0; i < power/2; i += 1 {
			tree[i] = h(hash, tree[2*i], tree[2*i+1])
		}
		power /= 2
	}
	return tree[0]
}

func h(hash hash.Hash, a, b []byte) []byte {
	return hash(append(a, b...))
}

// LTreeWithMask 计算 L-Tree 的根节点值
func LTreeWithMask(pk []byte, n int, hash hash.Hash, mask []byte) []byte {
	size := n / 8
	num := len(pk) * 8 / n
	// 找到最接近的 2 的指数数字
	value, power := common.NearestPowerOf2(num)
	tree := make([][]byte, value)
	// 将 pk 拷贝过去
	for i := 0; i < num; i++ {
		tree[i] = pk[i*size : (i+1)*size]
	}

	// 首先使用 mask 的前一部分的数据，还是后面的？
	//
	for j := power - 1; j >= 0; j-- {
		for i := 0; i < value/2; i += 1 {
			tree[i] = h(hash, common.Xor(tree[2*i], mask[(2*j)*size:(2*j+1)*size]), common.Xor(tree[2*i+1], mask[(2*j+1)*size:(2*j+2)*size]))
		}
	}
	return tree[0]
}
