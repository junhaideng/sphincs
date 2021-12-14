package signature

// get the `ith` bit of byte `b`
func getBit(b byte, n int) int {
	return int(b >> (bitSize - n - 1) & 1)
}

//func getBitRange(b []byte, start int, length int) []byte {
//
//}
