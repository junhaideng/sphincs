package signature

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
