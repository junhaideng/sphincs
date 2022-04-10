package signature

import (
	"errors"
	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
	"github.com/junhaideng/sphincs/rand"
)

// WOTSPlus 签名
// 在 WOTS+ 中，为了适应 SPHINCS，创建的时候
// 我们使用种子来初始化随机数生成器
type WOTSPlus struct {
	n    Size
	w    int
	hash hash.Hash
	l1   int
	l2   int
	// 掩码
	mask []byte
	// 随机数生成器
	r rand.Rander
	// 种子
	seed []byte
}

func newWOTSPlus(w, n int, mask []byte) (*WOTSPlus, error) {
	if 8%w != 0 {
		return nil, errors.New("w should be a divisor of 8")
	}
	if n != 256 && n != 512 {
		return nil, common.ErrSizeNotSupport
	}

	// 进行掩码操作，掩码和单个私钥 block 必须一样长
	if len(mask)*BitSize != n*(1<<w-1) {
		return nil, common.ErrSizeNotMatch
	}

	// meet above conditions, then n can be divided by w
	l1 := n / w

	l2_ := l2(l1, w)

	win := &WOTSPlus{
		n:    Size(n),
		w:    w,
		hash: hash.Sha256,
		l1:   l1,
		l2:   l2_,
		mask: mask,
	}

	if n == 512 {
		win.hash = hash.Sha512
	}
	return win, nil
}

// NewWOTSPlusSignature return WOTS+
// w should be a divisor of 8
func NewWOTSPlusSignature(w int, n Size, seed []byte, mask []byte) (Signature, error) {
	win, err := newWOTSPlus(w, int(n), mask)
	if err != nil {
		return nil, err
	}
	win.seed = seed
	win.r = rand.New(seed)
	return win, nil
}

func (w *WOTSPlus) GenerateKey() ([]byte, []byte) {
	n := int(w.n)

	// generate l1+l2 keys
	l := w.l1 + w.l2

	// 公私钥，我们可以实现确定公私钥的大小
	private := make([]byte, 0, n/8*l)
	public := make([]byte, 0, n/8*l)

	// each secret key n bits, n/8 bytes
	sk := make([]byte, n/8)

	// key generation's iteration
	for i := 0; i < l; i++ {
		w.r.Read(sk)
		private = append(private, sk...)
		public = append(public, hash.HashTimesWithMask(sk, 0, 1<<w.w-1, w.hash, w.mask)...)
	}

	return private, public
}

func (w *WOTSPlus) Sign(message []byte, sk []byte) []byte {
	digest := w.hash(message)

	// w bits as an integer, so after hash the message
	// there will be l1 integers
	// and each integer <= 2^w-1
	block := w.baseW(digest, w.l1)

	block = append(block, w.checksum(block)...)

	l := w.l1 + w.l2
	res := make([]byte, 0, l*(int(w.n)/8))

	n := int(w.n)
	for i := 0; i < l; i++ {
		res = append(res, hash.HashTimesWithMask(sk[i*n/8:(i+1)*n/8], 0, 1<<w.w-1-int(block[i]), w.hash, w.mask)...)
	}
	return res
}

func (w *WOTSPlus) Verify(message []byte, pk []byte, signature []byte) bool {
	pk_ := w.verify(message, signature)
	return common.Equal(pk, pk_)
}

func (w *WOTSPlus) verify(message []byte, signature []byte) []byte {
	digest := w.hash(message)
	block := w.baseW(digest, w.l1)

	block = append(block, w.checksum(block)...)

	l := w.l1 + w.l2
	n := int(w.n)
	pk := make([]byte, 0, l*n/8)
	for i := 0; i < l; i++ {
		s := signature[i*n/8 : (i+1)*n/8]
		pk = append(pk, hash.HashTimesWithMask(s, 1<<w.w-1-int(block[i]), 1<<w.w-1, w.hash, w.mask)...)
	}
	return pk
}

//// sphincs l2 calculation
//func l2(t1, w int) int {
//	up := math.Log2(float64(t1 * (1<<w - 1)))
//	return int(math.Floor(up/float64(w))) + 1
//}

// interprets an array of bytes as integers in tau w.
// w should be a divisor of 8, ensured by constructor `NewWOTSPlusSignature`
func (w WOTSPlus) baseW(input []byte, length int) []byte {
	res := make([]byte, length)

	index := 0 // index in input

	// index -> bit
	var bit = input[index] // current work on

	shift := BitSize
	for i := 0; i < length; i++ {
		if shift == 0 {
			shift = BitSize
			index++
			bit = input[index]
		}
		res[i] = bit >> (shift - w.w) & (1<<w.w - 1)
		shift -= w.w
	}
	return res
}

//
//func ceil(n1, n2 int) int {
//	res := n1 / n2
//	if n1%n2 != 0 {
//		res += 1
//	}
//	return res
//}

// checksum calculate checksum of tau w byte array
// 计算出来的 sum，首先进行填充，bit 数能够被 w 整除
func (w WOTSPlus) checksum(input []byte) []byte {
	var sum uint64

	for i := 0; i < len(input); i++ {
		sum += 1<<w.w - 1 - uint64(input[i])
	}

	count := common.BitCount(sum)
	// make sure expected empty zero bits are the least significant bits
	// or just think this is padding
	// eg: 1101_01 => 1101_0100, 1101_0001_110 => 1101_0001_1100_0000
	if count%BitSize != 0 {
		shift := (count/BitSize+1)*BitSize - count
		sum = sum << shift
	}

	// convert sum to bytes
	b := make([]byte, ceil(w.l2*w.w, BitSize))

	for i := len(b) - 1; i >= 0; i-- {
		b[i] = byte(sum & 0xff)
		sum >>= 8
	}

	// convert checksum to tau w
	return w.baseW(b, w.l2)
}
