package hash

import "github.com/junhaideng/sphincs/common"

// 哈希函数 FOR SPHINCS-256
// 见论文的 表1(p22) 定义，这里并没严格实现，不过保证输出的长度相同

// HashMessage 对消息进行哈希，加了一个随机数，生成随机摘要值
func HashMessage(rand, message []byte) []byte {
	tmp := make([]byte, len(message)+len(rand))
	copy(tmp, rand)
	copy(tmp[len(rand):], message)
	return Sha512(tmp)
}

// FuncAlpha PRG Fα
func FuncAlpha(address, key []byte) []byte {
	tmp := make([]byte, len(address)+len(key))
	copy(tmp, address)
	copy(tmp[len(address):], key)
	return Sha256(tmp)
}

// Func PRG F
// 对消息进行处理，生成 512 bit 的摘要值
func Func(message, key []byte) []byte {
	tmp := make([]byte, len(message)+len(key))
	copy(tmp, key)
	copy(tmp[len(key):], message)
	return Sha512(tmp)
}

// F hash function F
func F(message []byte) []byte {
	return Sha256(message)
}

// H hash function H
func H(m1, m2 []byte) []byte {
	tmp := common.Xor(m1, m2)
	return Sha256(tmp)
}
