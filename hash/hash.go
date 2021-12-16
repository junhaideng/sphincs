package hash

import (
	"crypto/sha256"
	"crypto/sha512"
)

// Hash maps data of arbitrary size to fixed-size values
type Hash func([]byte) []byte

// Sha256 maps data to 256 bits
func Sha256(b []byte) []byte {
	s := sha256.New()
	s.Write(b)
	return s.Sum(nil)
}

// Sha512 maps data to 512 bits
func Sha512(b []byte) []byte {
	s := sha512.New()
	s.Write(b)
	return s.Sum(nil)
}

// HashTimes hash message n times using hash function
func HashTimes(message []byte, n int, hash Hash) []byte {
	res := make([]byte, len(message))
	copy(res, message)
	for i := 0; i < n; i++ {
		res = hash(res)
	}
	return res
}
