package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"sync"
)

var pool = sync.Pool{New: func() interface{} {
	return sha256.New()
}}

// Hash maps data of arbitrary size to fixed-size values
type Hash func([]byte) []byte

// Sha256 maps data to 256 bits
func Sha256(b []byte) []byte {
	s := pool.Get().(hash.Hash)
	defer func() {
		s.Reset()
		pool.Put(s)
	}()
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

// 将 a ^ b ，然后进行哈希
func h(hash Hash, a, b []byte) []byte {
	if len(a) != len(b) {
		panic("长度应该一致")
	}
	tmp := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		tmp[i] = a[i] ^ b[i]
	}
	return hash(tmp)
}

// HashTimesWithMask 哈希消息 end-start 次，同时会加入掩码计算
// 假设 message n bits ，那么掩码 (end-start) * n bits
func HashTimesWithMask(message []byte, start, end int, hash Hash, mask []byte) []byte {
	n := len(message)
	//fmt.Println(len(mask), (end-start)*n, end-start)
	//if len(mask) != (end-start)*n {
	//	panic("长度对应错误")
	//}
	res := make([]byte, len(message))
	copy(res, message)
	for i := start; i < end; i++ {
		res = h(hash, res, mask[i*n:(i+1)*n])
	}
	return res
}
