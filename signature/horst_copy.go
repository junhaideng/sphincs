package signature

import (
	"errors"

	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
	"github.com/junhaideng/sphincs/merkle"
	"github.com/junhaideng/sphincs/rand"
)

// HorstTest .
// 注意：形成的树的高度实际上为 1 + h.tau !!!!
type HorstTest struct {
	// k * log2(t) = n
	n Size
	// t should be a power of 2
	t int
	// tau = log2(t)
	tau  int
	x    int
	k    int
	hash hash.Hash
	seed []byte
	mask []byte
	r    rand.Rander
	tree *merkle.Tree
}

// 为了方便 SHPINCS 调用
func newHorstTest(tau, k int, n int, mask []byte) (*HorstTest, error) {

	if !(tau > 0 && tau%8 == 0 && tau <= 64) {
		return nil, errors.New("t should a positive integer which is divisible by 8 and not greater than 64")
	}

	// tau +1 的高度，叶子节点可以容纳 2 ^ tau 个私钥块
	tree, err := merkle.NewTreeWithMask(tau+1, n, mask)
	if err != nil {
		return nil, err
	}
	h := &HorstTest{
		n: Size(n),
		// 这才是真正的 t
		t: 1 << tau,
		// 这是 τ
		tau:  tau,
		k:    k,
		x:    calc(k, tau),
		hash: hash.Sha256,
		mask: mask, // TODO 其实可以不进行保存
		tree: tree,
	}

	if n == 512 {
		h.hash = hash.Sha512
	}
	return h, nil
}

// NewHorstTestSignature return Horst signature algorithm
// where tau is exponential, and tau * k = 256 or tau * k = 512
// tau 就是树的高度
// tau * k 是消息摘要的长度，并不是中间哈希值进行哈希得到的摘要长度
// 在 SPHINCS-256 中 tau*k = 512 = m, n = 256
func NewHorstTestSignature(tau, k int, seed, mask []byte) (Signature, error) {

	n := Size(len(seed) * 8)

	if n != Size256 && n != Size512 {
		return nil, errors.New("seed size should be 256 or 512")
	}

	// mask 一共 2n * logt bits
	// n = len(seed) * 8
	if len(mask) != 2*len(seed)*tau {
		return nil, common.ErrSizeNotMatch
	}

	h, err := newHorst(tau, k, int(n), mask)
	if err != nil {
		return nil, err
	}

	h.seed = seed
	h.r = rand.New(seed)

	return h, nil
}

func (h *HorstTest) GenerateKey() ([]byte, []byte) {
	size := int(h.n) / 8 // n bits => n/8 byte
	sk := make([]byte, 0, h.t*size)
	pk := make([]byte, 0, h.t*size)

	r := make([]byte, size)

	for i := 0; i < h.t; i++ {
		h.r.Read(r)
		sk = append(sk, r...)
		pk = append(pk, h.hash(r)...)
	}
	//err := h.tree.SetSkWithMask(sk)
	//if err != nil {
	//	panic(err)
	//}
	//PK, _ := h.tree.GetPk()
	PK := merkle.LTreeWithMask(pk, int(h.n), h.hash, h.mask)
	return sk, PK
}

// Sign 对消息进行签名
// 这里的 message 其实是已经经历过哈希处理的
func (h *HorstTest) Sign(message []byte, seed []byte) []byte {
	rander := rand.New(seed)
	size := uint64(h.n) / 8 // n bits => n/8 byte

	sk := make([]byte, 0, uint64(h.t)*size)
	r := make([]byte, size)

	for i := 0; i < h.t; i++ {
		rander.Read(r)
		sk = append(sk, r...)
	}

	// split message to k substring, each log2(t) bits
	index := h.split(message)

	// k 个密钥块，k 个对应的 auth path，τ-x 层的所有节点
	// 每一个单独的 block 都是 n bits
	// 构建的 merkle tree 高度实际为 tau + 1
	signature := make([]byte, 0, (h.k+(h.tau-h.x)*h.k+1<<h.x)*int(h.n)/8)

	// signature has k secret keys
	for i := 0; i < h.k; i++ {
		j := index[i]
		sk_ := sk[j*size : (j+1)*size]
		// σi= (skMi,AuthMi)
		signature = append(signature, sk_...)
		// 到达 x 层，和算法描述不同的是，这里的根节点为 0 层
		auth := h.tree.AuthenticationPath(h.x, int(j))
		signature = append(signature, common.Flatten(auth)...)

		// 这个结果应该是 x 层的
		//x := merkle.ComputeRootWithMask(sk_, int(j), auth, h.hash, common.Ravel(h.mask[len(h.mask)-(h.tau-h.x)*int(h.n)/8*2:], int(h.n)/8))
		//fmt.Printf("layer x node: %x\n", x)
	}

	// 包含 x 层的所有节点，一共有 2^x 个
	signature = append(signature, common.Flatten(h.tree.Layer(h.x))...)
	//fmt.Printf("layer x: %x\n", common.Flatten(h.tree.Layer(h.x)))
	return signature
}

// Verify .
func (h *HorstTest) Verify(message []byte, pk []byte, signature []byte) bool {
	ltree, flag := h.verify(message, signature)
	if !flag {
		return false
	}

	return common.Equal(pk, ltree)
}

// log2(t) should be divided by 8
// ensured by constructor
func (h *HorstTest) split(digest []byte) []uint64 {
	// digest has n bits, split into k substrings, each log2(t) bits
	res := make([]uint64, h.k*h.tau/8)

	by := h.tau / 8 // each substring length
	for i := 0; i < h.k; i++ {
		res[i] = common.ToInt(digest[by*i : (i+1)*by])
	}
	return res
}

// verify 实现 SPHINCS 中的函数签名，校验之后返回 pk
// mask 通过构造函数传入
func (h *HorstTest) verify(message []byte, signature []byte) ([]byte, bool) {
	index := h.split(message)
	n := int(h.n)
	size := (1 + h.tau - h.x) * n / 8
	// x 层的节点值
	// DONE：nodes 和 layer x 节点已经对应
	nodes := signature[size*h.k:]
	start := 1<<h.tau - 1
	// signature 一共有 k + 1 份，最后一份是 x 层的所有节点
	for i := 0; i < h.k; i++ {
		j := int(index[i])
		part := signature[i*size : (i+1)*size]

		// 签名部分[0] 即私钥部分，每一个私钥 n bits 即 n / 8 byte
		sk := part[:int(h.n)/8]

		// 私钥对应的鉴权路径部分, h.tau-h.x-1 个节点值
		// 即，每一个路径都是 (h.tau-h.x-1) * n bits
		auth := common.Ravel(part[int(h.n)/8:], n/8)

		// data 对应的 x 层的节点值
		// path 的长度为 h.tau-h.x ，mask 只需要取对应的即可
		// 注意计算的顺序，需要先用后一部分的mask和path的前面的计算
		// 因为path中的数据，先取下面层级的，然后取上面的
		mask := h.mask[len(h.mask)-(h.tau-h.x)*int(h.n)/8*2:]
		data := merkle.ComputeRootWithMask(sk, start+j, auth, h.hash, common.Ravel(mask, int(h.n)/8))

		// 私钥在叶子节点的位置为 1 << h.tau - 1 + j (总索引)
		// 叶子节点和 h.x 层相差了 h.tau-h.x+1 距离
		nodeIndex := getIndex(1<<h.tau-1+j, h.tau-h.x) - 1<<h.x + 1

		// 每一个 node 都是 n/8 bytes
		node := nodes[nodeIndex*n/8 : (nodeIndex+1)*n/8]
		// 计算出来的 data 应该
		if !common.Equal(data, node) {
			return nil, false
		}
	}

	// 计算根节点
	ltree := merkle.LTreeWithMask(nodes, int(h.n), h.hash, h.mask)

	return ltree, true
}
