package signature

import (
	"crypto/rand"

	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
)

// Lamport signature
// reference: https://en.wikipedia.org/wiki/Lamport_signature
type Lamport struct {
	n    Size
	hash hash.Hash
}

// NewLamportSignature returns lamport signature algorithm
func NewLamportSignature(n Size) (Signature, error) {
	if n != Size256 && n != Size512 {
		return nil, common.ErrSizeNotSupport
	}
	lp := &Lamport{n: n, hash: hash.Sha256}
	if n == Size512 {
		lp.hash = hash.Sha512
	}
	return lp, nil
}

func (l *Lamport) GenerateKey() ([]byte, []byte) {
	n := int(l.n)

	// n * n * 2 bits <=> n * n * 2 / 8 byte
	size := n * 2 * n / 8
	private := make([]byte, 0, size)
	public := make([]byte, 0, size)

	// each sk n bits, n/8 bytes
	sk := make([]byte, n/8)

	// n pairs
	for i := 0; i < n*2; i++ {
		rand.Read(sk)
		private = append(private, sk...)
		public = append(public, l.hash(sk)...)
	}
	return private, public
}

func (l *Lamport) Sign(message []byte, sk []byte) []byte {
	n := int(l.n)
	// hash message to n bits
	digest := l.hash(message)

	res := make([]byte, 0, n*n/8)

	// hash => 32 bytes -> 256 bits
	for i := 0; i < len(digest); i++ {
		bits := digest[i]

		// for each bit
		for j := 0; j < BitSize; j++ {
			// bit index in 256 bits
			index := i*BitSize + j

			start := index * 2 * n / 8
			// if bit is 0
			if common.GetBit(bits, j) == 0 {
				res = append(res, sk[start:start+n/8]...)
			} else {
				res = append(res, sk[start+n/8:start+n/8*2]...)
			}
		}
	}
	return res
}

func (l *Lamport) Verify(message []byte, pk []byte, signature []byte) bool {
	n := int(l.n)
	// hash message to n bits
	digest := l.hash(message)

	// hash => 32 bytes -> 256 bits
	for i := 0; i < len(digest); i++ {
		bits := digest[i]
		// for each bit
		for j := 0; j < BitSize; j++ {
			// bit index in 256 bits
			index := i*BitSize + j

			var p []byte
			start := index * 2 * n / 8

			// if last bit is 0
			if common.GetBit(bits, j) == 0 {
				p = pk[start : start+n/8]
			} else {
				p = pk[start+n/8 : start+n/8*2]
			}
			sk := signature[index*n/8 : (index+1)*n/8]
			if !common.Equal(p, l.hash(sk)) {
				return false
			}
		}
	}

	// each n/8 bytes is a sk, there are total n sk
	return true
}
