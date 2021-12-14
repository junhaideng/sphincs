package signature

import (
	"crypto/rand"
	"errors"
	"math"
)

// Winternitz signature
// reference: http://www.e-reading-lib.org/bookreader.php/135832/Post_Quantum_Cryptography.pdf
type Winternitz struct {
	n    Size
	w    int
	hash Hash
	l1   int
	l2   int
}

// NewWinternitzSignature return winternitz one time signature algorithm
// w should be a divisor of 8
func NewWinternitzSignature(w int, n Size) (Signature, error) {
	if 8%w != 0 {
		return nil, errors.New("w should be a divisor of 8")
	}
	if n != Size256 && n != Size512 {
		return nil, ErrSizeNotSupport
	}

	// meet above conditions, then n can be divided by w
	l1 := int(n) / w

	l2_ := l2(l1, w)
	win := &Winternitz{
		n:    n,
		w:    w,
		hash: Sha256,
		l1:   l1,
		l2:   l2_,
	}

	if n == Size512 {
		win.hash = Sha512
	}
	return win, nil
}

func (w *Winternitz) GenerateKey() ([]byte, []byte) {
	n := int(w.n)

	// generate l1+l2 keys
	l := w.l1 + w.l2

	private := make([]byte, 0, n/8*l)
	public := make([]byte, 0, n/8*l)

	// each secret key n bits, n/8 bytes
	sk := make([]byte, n/8)

	// key generation's iteration
	for i := 0; i < l; i++ {
		rand.Read(sk)
		private = append(private, sk...)
		public = append(public, hashTimes(sk, 1<<w.w-1, w.hash)...)
	}

	return private, public
}

func (w *Winternitz) Sign(message []byte, sk []byte) []byte {
	digest := w.hash(message)

	// w bits as an integer, so after hash the message
	// there will be l1 integers
	// and each integer <= 2^w-1
	block := w.baseW(digest)

	// TODO calculate checksum, length should be l2
	block = append(block, w.checksum(block)...)

	l := w.l1 + w.l2
	res := make([]byte, 0, l)

	n := int(w.n)
	for i := 0; i < l; i++ {
		res = append(res, hashTimes(sk[i*n/8:(i+1)*n/8], 1<<w.w-1-int(block[i]), w.hash)...)
	}
	return res
}

func (w *Winternitz) Verify(message []byte, pk []byte, signature []byte) bool {
	digest := w.hash(message)
	block := w.baseW(digest)

	block = append(block, w.checksum(block)...)

	l := w.l1 + w.l2
	n := int(w.n)
	for i := 0; i < l; i++ {
		s := signature[i*n/8 : (i+1)*n/8]
		p := pk[i*n/8 : (i+1)*n/8]
		if !equal(p, hashTimes(s, int(block[i]), w.hash)) {
			return false
		}
	}
	return true
}

// sphincs l2 calculation
func l2(t1, w int) int {
	up := math.Log2(float64(t1 * (1<<w - 1)))
	return int(math.Floor(up/float64(w))) + 1
}

// interprets an array of bytes as integers in base w.
// w should be a divisor of 8, ensured by constructor `NewWinternitzSignature`
func (w Winternitz) baseW(input []byte) []byte {
	res := make([]byte, 0, len(input)*bitSize/w.w)

	// for each bit
	for i := 0; i < len(input); i++ {
		b := input[i]
		// split each bit
		for j := 0; j < bitSize/w.w; j++ {
			res = append(res, b>>(8-(j+1)*w.w)&(1<<w.w-1))
		}
	}
	return res
}

// checksum calculate checksum of base w byte array
func (w Winternitz) checksum(input []byte) []byte {
	var sum uint64
	for i := 0; i < len(input); i++ {
		sum += 1<<w.w - 1 - uint64(input[i])
	}

	// make sure expected empty zero bits are the least significant bits
	// or just think this is padding
	sum = sum << (bitSize - (w.l2*w.w)%bitSize)

	// convert sum to bytes
	b := make([]byte, (w.l2*w.w+7)/8)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] = byte(sum & 0xff)
		sum >>= 8
	}
	// /* Iterate over out in decreasing order, for big-endianness. */
	//    for (i = outlen - 1; i >= 0; i--) {
	//        out[i] = in & 0xff;
	//        in = in >> 8;
	//    }

	// convert checksum to base w
	return w.baseW(b)
}
