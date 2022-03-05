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

// NearestPowerOf2 找到与 n 最相近的 2 的指数幂数
func NearestPowerOf2(n int) int {
	if isPowerOf2(n) {
		return n
	}
	num := BitCount(uint64(n))
	return 1 << num
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
	if len(a) != len(b) {
		panic("xor 操作的两个 byte 数组长度应该一样长")
	}
	tmp := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		tmp[i] = a[i] ^ b[i]
	}
	return tmp
}