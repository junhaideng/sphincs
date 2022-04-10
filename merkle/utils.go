package merkle

import (
	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
)

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

func ComputeRootWithMask(sk []byte, index int, path [][]byte, h hash.Hash, mask [][]byte) []byte {
	if 2*len(path) != len(mask) {
		panic("掩码长度应该是鉴权路径的两倍")
	}
	//ret := make([]byte, len(sk))
	//copy(ret, h(sk))
	ret := h(sk)
	//fmt.Printf("ret: %x\n", ret)
	//fmt.Println(index)
	xor := common.Xor
	for i := 0; i < len(path); i++ {
		// 奇数
		if index&1 != 0 {
			//fmt.Printf("[mask-utils.go], 奇数 left: [node %x] [mask %x], right: [node %x] [mask %x]\n", ret, mask[2*(len(path)-i-1)], path[i], mask[2*(len(path)-1-i)+1])
			ret = hash.CombineAndHash(xor(ret, mask[2*(len(path)-i-1)]), xor(path[i], mask[2*(len(path)-1-i)+1]), h)
		} else {
			//fmt.Printf("[mask-utils.go], 偶数 left: [node %x] [mask %x], right: [node %x] [mask %x]\n", path[i], mask[2*(len(path)-i-1)], ret, mask[2*(len(path)-1-i)+1])
			ret = hash.CombineAndHash(xor(path[i], mask[2*(len(path)-i-1)]), xor(ret, mask[2*(len(path)-1-i)+1]), h)
		}
		//fmt.Printf("compute: %d, %x\n", i, ret)
		index = (index - 1) / 2
	}

	return ret
}
