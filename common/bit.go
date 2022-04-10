package common

import (
	"encoding/binary"
)

// GetBit gets the `ith` bit of byte `b`
func GetBit(b byte, n int) int {
	return int(b >> (BitSize - n - 1) & 1)
}

// BitCount get significant bits counter
// for example 'a'= 110_0001, result should be 7
func BitCount(n uint64) int {
	res := 0
	for n > 0 {
		n >>= 1
		res++
	}
	return res
}

// NearestPowerOf2 找到大于 n 的最小的 2 的指数
// 同时会返回指数项
func NearestPowerOf2(n int) (int, int) {
	if isPowerOf2(n) {
		return n, BitCount(uint64(n - 1))
	}
	num := BitCount(uint64(n))
	return 1 << num, num
}

func isPowerOf2(n int) bool {
	return n&(n-1) == 0
}

func ToInt(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(b[0])<<8 | uint64(b[1])
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	}
	panic("byte array length should be one of {1,2,4,8}")
}

func Xor(a, b []byte) []byte {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if len(a) != len(b) {
		panic("xor 操作的两个 byte 数组长度应该一样长")
	}
	tmp := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		tmp[i] = a[i] ^ b[i]
	}
	return tmp
}

// Chop 从 b 中截取前 h 位
func Chop(b []byte, h uint64) (uint64, []byte) {
	// h 之前已经限制过大小了，h <= 64
	// Uint64 函数不会修改变量的值
	ret := binary.BigEndian.Uint64(b[:8]) >> (64 - h) & (1<<h - 1)
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, ret)
	return ret, bytes
}

// Cut 从 begin 开始截取 i 的 bits 个比特
// i 一共有 total 个比特位
func Cut(i, total, begin, bits uint64) uint64 {
	// 计算需要移动多少位
	move := total - begin - bits
	return i >> move & (1<<bits - 1)
}
