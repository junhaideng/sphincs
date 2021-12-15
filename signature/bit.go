package signature

import "encoding/binary"

// get the `ith` bit of byte `b`
func getBit(b byte, n int) int {
	return int(b >> (bitSize - n - 1) & 1)
}

// get significant bits counter
// for example 'a'= 110_0001, result should be 7
func bitCount(n uint64) int {
	res := 0
	for n > 0 {
		n >>= 1
		res++
	}
	return res
}

func isPowerOf2(n int) bool {
	return n&(n-1) == 0
}

func toInt(b []byte) uint64 {
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
