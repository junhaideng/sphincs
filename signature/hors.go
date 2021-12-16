package signature

import (
	"crypto/rand"
	"errors"
	"github.com/junhaideng/sphincs/hash"
)

// Hors implements Hors OTS
// see: https://www.cs.bu.edu/~reyzin/papers/one-time-sigs.pdf
type Hors struct {
	// k * log2(t) = n
	n Size
	// t should be a power of 2
	t int
	// base = log2(t)
	base int
	k    int
	hash hash.Hash
}

// NewHorsSignature return Hors signature algorithm
// where t is exponential, and t * k = 256 or t * k = 512
func NewHorsSignature(t, k int) (Signature, error) {
	if !(t > 0 && t%8 == 0 && t <= 64) {
		return nil, errors.New("t should a positive integer which is divisible by 8 and not greater than 64")
	}
	n := Size(t * k)

	if n != Size256 && n != Size512 {
		return nil, errors.New("t * k should be 256 or 512")
	}

	h := &Hors{
		n:    n,
		t:    1 << t,
		base: t,
		k:    k,
		hash: hash.Sha256,
	}
	if n == Size512 {
		h.hash = hash.Sha512
	}
	return h, nil
}

func (h *Hors) GenerateKey() ([]byte, []byte) {
	size := int(h.n) / 8 // n bits => n/8 byte
	sk := make([]byte, 0, h.t*size)
	pk := make([]byte, 0, h.t*size)

	r := make([]byte, size)

	for i := 0; i < h.t; i++ {
		rand.Read(r)
		sk = append(sk, r...)
		pk = append(pk, h.hash(r)...)
	}

	return sk, pk
}

func (h *Hors) Sign(message []byte, sk []byte) []byte {
	digest := h.hash(message)
	// split digest to k substring, each log2(t) bits
	index := h.split(digest)

	// signature length is k * n bits
	signature := make([]byte, 0, h.k*int(h.n)/8)

	size := uint64(h.n) / 8
	// signature has k secret keys
	for i := 0; i < h.k; i++ {
		j := index[i]
		signature = append(signature, sk[j*size:(j+1)*size]...)
	}
	return signature
}

func (h *Hors) Verify(message []byte, pk []byte, signature []byte) bool {
	digest := h.hash(message)
	index := h.split(digest)

	size := uint64(h.n) / 8
	var i uint64
	for i = 0; i < uint64(h.k); i++ {
		j := index[i]
		if !equal(h.hash(signature[i*size:(i+1)*size]), pk[j*size:(j+1)*size]) {
			return false
		}
	}
	return true
}

// log2(t) should be divided by 8
// ensured by constructor
func (h *Hors) split(digest []byte) []uint64 {
	// digest has n bits, split into k substrings, each log2(t) bits
	res := make([]uint64, h.k*h.base/8)

	by := h.base / 8 // each substring length
	for i := 0; i < h.k; i++ {
		res[i] = toInt(digest[by*i : (i+1)*by])
	}
	return res
}
