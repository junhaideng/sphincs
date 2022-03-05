package signature

import (
	"errors"
	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
	"github.com/junhaideng/sphincs/merkle"
	"github.com/junhaideng/sphincs/rand"
	"math"
)

func calc(k, t int) int {
	min := math.MaxInt
	res := 0
	for i := 0; i <= t; i++ {
		tmp := k*(t-i+1) + 1<<i
		if tmp <= min {
			res = i
			min = tmp
		}
	}
	return res
}

type Horst struct {
	// k * log2(t) = n
	n Size
	// t should be a power of 2
	t int
	// base = log2(t)
	base int
	x    int
	k    int
	hash hash.Hash
	seed []byte
	mask []byte
	r    rand.Rander
}

// NewHorstSignature return Horst signature algorithm
// where t is exponential, and t * k = 256 or t * k = 512
func NewHorstSignature(t, k int, seed []byte, mask []byte) (Signature, error) {
	if !(t > 0 && t%8 == 0 && t <= 64) {
		return nil, errors.New("t should a positive integer which is divisible by 8 and not greater than 64")
	}
	n := Size(t * k)

	if n != Size256 && n != Size512 {
		return nil, errors.New("t * k should be 256 or 512")
	}

	// mask 一共 2n * logt bits
	if len(mask) != 1 {
		return nil, common.ErrSizeNotMatch
	}

	h := &Horst{
		n: n,
		// 这才是真正的 t
		t: 1 << t,
		// 这是 τ
		base: t,
		k:    k,
		x:    calc(k, t),
		hash: hash.Sha256,
		seed: seed,
		mask: mask,
		r:    rand.New(seed),
	}

	if n == Size512 {
		h.hash = hash.Sha512
	}

	return h, nil
}

func (h *Horst) GenerateKey() ([]byte, []byte) {
	size := int(h.n) / 8 // n bits => n/8 byte
	sk := make([]byte, 0, h.t*size)
	pk := make([]byte, 0, h.t*size)

	r := make([]byte, size)

	for i := 0; i < h.t; i++ {
		h.r.Read(r)
		sk = append(sk, r...)
		pk = append(pk, h.hash(r)...)
	}

	// 然后计算根节点的值，使用 pk 构建一个 L-Tree
	PK := merkle.LTree(pk, size*8, h.hash)
	return sk, PK
}

func (h *Horst) Sign(message []byte, sk []byte) []byte {
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

func (h *Horst) Verify(message []byte, pk []byte, signature []byte) bool {
	digest := h.hash(message)
	index := h.split(digest)

	size := uint64(h.n) / 8
	var i uint64
	for i = 0; i < uint64(h.k); i++ {
		j := index[i]
		if !common.Equal(h.hash(signature[i*size:(i+1)*size]), pk[j*size:(j+1)*size]) {
			return false
		}
	}
	return true
}

// log2(t) should be divided by 8
// ensured by constructor
func (h *Horst) split(digest []byte) []uint64 {
	// digest has n bits, split into k substrings, each log2(t) bits
	res := make([]uint64, h.k*h.base/8)

	by := h.base / 8 // each substring length
	for i := 0; i < h.k; i++ {
		res[i] = common.ToInt(digest[by*i : (i+1)*by])
	}
	return res
}
