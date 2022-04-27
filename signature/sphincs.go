package signature

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/junhaideng/sphincs/common"
	"github.com/junhaideng/sphincs/hash"
	"github.com/junhaideng/sphincs/merkle"
	"github.com/junhaideng/sphincs/rand"
)

// SPHINCS-256
// n: 256
// m: 512
// h: 60
// d: 12
// w: 16 = 2^4
// tau: 16 -> t = 2^16
// k: 32
// 签名大小 41000 bytes
// pk 1056 bytes
// sk 1088 bytes
// TODO: 论文中声明的签名大小 p 取的是 32？ 2*h 都大于 2*tau了
// 论文不一定正确 ):

// Sphincs .
// 注意！！！！
// 这里的 d 算层数的时候，根节点的层数为 d-1
// WOTS+ 的叶子节点层数记为 0
// HORST 所在的位置层数记为 d
// 这里为了简单，不设置缓存，仅提供方法思路
// YOU CAN DO:
// 1. 设置缓存，避免重复计算 (在计算过程中，很多部分可能是重复的，同一棵 HORST 下的私钥，可能对应同一棵 WOTS 节点，那么这两个密钥对很大部分内容的计算都是一致的)
type Sphincs struct {
	n   uint64 // HORST 和 WOTS+ 中哈希值的长度
	m   uint64 // 消息哈希值长度
	h   uint64 // hyper tree 的高度
	d   uint64 // hyper tree 的层数
	w   uint64 // Winternitz 参数, 这里采用的是指数
	tau uint64 // t=2^tau 为 HORST 中私钥的元素个数
	// t = 2^tau 保存 tau 更加方便
	k    uint64 // 在 HORST 签名中公开的私钥元素个数
	seed []byte
	r    rand.Rander
	p    uint64 // 掩码的个数
	mask [][]byte
	//
	ltree     uint64 // l-tree 需要使用的掩码部分
	l         uint64 // l wots+ 中的签名块数
	signature Signature
}

// NewSphincs 创建一个新的签名算法
func NewSphincs(n, m, h, d, w, tau, k uint64, seed []byte) (*Sphincs, error) {
	//
	if tau*k != m {
		return nil, errors.New("tau *k 应该等于 m")
	}

	if h > 64 {
		// h 如果过大，签名的时候截取 h bit 时，无法保存到一个整数中
		panic("h 过大")
	}

	if h%d != 0 {
		panic("h 应该时 d 的倍数")
	}
	if n != 256 && m != 512 {
		// 因为需要使用的哈希函数生成的哈希值长度不同
		// 这里仅仅采用了 256 和 512 的
		panic("暂未实现该参数")
	}
	sphincs := &Sphincs{
		n:    n,
		m:    m,
		h:    h,
		d:    d,
		w:    w,
		tau:  tau,
		k:    k,
		seed: seed,
		r:    rand.New(seed),
	}
	sphincs.calculateP()

	return sphincs, nil
}

func (s *Sphincs) GenerateKey() ([]byte, []byte) {
	// 首先取两个私钥值
	// SK_1
	// for pseudorandom key generation
	sk1 := make([]byte, s.n/8)

	// SK_2
	// 1. unpredictable index in `sign`
	// 2. pseudorandom values to randomize the message hash in sign
	sk2 := make([]byte, s.n/8)

	s.r.Read(sk1)
	s.r.Read(sk2)

	// 生成 p 个掩码，每一份大小为 n/8
	for i := uint64(0); i < s.p; i++ {
		s.mask[i] = make([]byte, s.n/8)
		s.r.Read(s.mask[i])
	}

	// 生成根节点
	// 注意了，在 SPHINCS 中，根节点的层数为 s.d-1，最下面的 WOTS+ 密钥对层为 0
	// 最底层的 HORST 密钥对层记为 d 层
	layer := s.d - 1

	// 在 SPHINCS virtual structure 中的一个节点
	// 并不是说只有一个 node，而是很多个 node
	// 这些 node 组成一个 binary hash tree
	// 根节点是 WOTS+ pk 构成的 l-tree 的根节点
	// 然后这些所有的根节点通过 binary hash tree
	// 得到 virtual structure 中的一个节点
	leaf := make([][]byte, 1<<(s.h/s.d)-1)
	leaf_ := make([][]byte, 1<<(s.h/s.d)-1)
	for i := uint64(0); i < 1<<(s.h/s.d); i++ {
		address := s.address(layer, 0, i)
		seed := hash.FuncAlpha(address, sk1)

		// 获取到 WOTS+ l 个 pk 块构成的 L-Tree 的根节点
		wots, err := NewWOTSPlusSignature(int(s.w), Size(s.n), seed, common.Flatten(s.getMask(WOTS_Mask)))
		if err != nil {
			panic(err)
		}

		_, pk := wots.GenerateKey()
		leaf = append(leaf, hash.Sha256(merkle.LTreeWithMask(pk, int(s.n), hash.F, common.Flatten(s.getMask(LTREE_Mask)))))
		leaf_ = append(leaf_, merkle.LTreeWithMask(pk, int(s.n), hash.F, common.Flatten(s.getMask(LTREE_Mask))))
		//fmt.Printf("1. leaf: %x\n", merkle.LTreeWithMask(pk, int(s.n), hash.F, common.Flatten(s.getMask(LTREE_Mask))))
	}

	// 得到所有的叶子 node 之后，计算得到 binary hash tree 的根节点
	// 其实也是一个 L-Tree ，只不过比较特殊罢了
	// 这里我们只需要计算根节点，就不使用 Merkel Tree 结构计算了
	// 不过也是可以的，不过比较重，因为会需要消耗更多的资源
	// 一般用于 Authentication Path 的计算
	// 使用 L-Tree 需要上面的 leaf 求 hash

	// 这里使用的掩码是 Q_{L-Tree} 后面的 2h 个
	// root 即论文中的 PK1

	mask := s.getMask(TREE_Mask)
	root := merkle.LTreeWithMask(common.Flatten(leaf), int(s.n), hash.Sha256, common.Flatten(mask[len(mask)-int(2*(s.h/s.d)):]))

	//fmt.Printf("root: %x\n", root)
	// sk = (SK_1, SK_2, Q)
	sk := make([]byte, 0, (s.n+s.n+s.n*s.p)/8) // (2+p) * n bits

	sk = append(sk, sk1...)
	sk = append(sk, sk2...)
	sk = append(sk, common.Flatten(s.mask)...)

	// pk = (PK1, Q)
	pk := make([]byte, 0, (s.n+s.n*s.p)/8) // (1+p) * n bits
	pk = append(pk, root...)
	pk = append(pk, common.Flatten(s.mask)...)

	return sk, pk
}

func (s *Sphincs) Sign(message []byte, sk []byte) []byte {
	// 我们可以首先计算出签名的大小
	// signature = (i, R1, σH, σW,0, Auth_{A_0}, ..., σ_{W,d-1}, Auth_{A_{d-1}}
	// i 为 8 bytes，R1 为 n/8 bytes
	// σH 大小为 (h.k+(h.tau-h.x)*h.k+1<<h.x)*int(h.n)/8 bytes
	// σw =
	signature := make([]byte, 0, 0)

	// 取出 sk1
	sk1 := sk[0 : s.n/8]

	// 1. 对于任意长度的消息，计算 randomized message digest
	// 首先计算出伪随机数 R= (R1, R2) = {0,1}^512
	r := hash.Func(message, sk1)

	// 随机摘要值
	d := hash.HashMessage(r[:s.n/8], message)

	// 2. 截取 h bits 的值，来选择一个 HORST 密钥对
	index, bytes := common.Chop(r[s.n/8:s.n/4], s.h)

	// 3. 计算出 HORST 地址
	bits := (s.d - 1) * s.h / s.d
	address := s.address(s.d, common.Cut(index, s.h, 0, bits), common.Cut(index, s.h, bits, s.h/s.d))

	// 4. 计算出随机数种子
	seed := hash.FuncAlpha(address, sk1)

	// 5. 生成 (σ,pkH)
	horst, err := NewHorstSignature(int(s.tau), int(s.k), seed, common.Flatten(s.getMask(HORST_Mask)))

	if err != nil {
		panic(err)
	}
	s.signature = horst
	sk, pkH := horst.GenerateKey()
	//fmt.Printf("pkH: \n%x\n", pkH)
	// HORST 签名
	sigma := horst.Sign(d, sk)

	//fmt.Printf("d: %x\n", d)
	//fmt.Printf("signature: \n%x\n", sigma)

	// signature = (i, R1, σH, σW,0, Auth_{A_0}, ..., σ_{W,d-1}, Auth_{A_{d-1}}
	// i
	// TODO 在这里实现的时候 bytes 大小实际上已经被确定了，并不是严格的 h bits
	//  并且在实现的时候不可能出现最小单位为比特的变量
	// 因为我们需要考虑到 h 不是 8 的倍数，在实际编程的时候并不方便
	signature = append(signature, bytes...)
	// R1
	signature = append(signature, r[:s.n/8]...)

	// σH
	signature = append(signature, sigma...)

	// 计算 0 到 d-1 层的 σ 以及对应的 鉴权路径
	for j := uint64(0); j < s.d; j++ {
		// 计算 address
		tmp := (s.d - 1 - j) * s.h / s.d
		address := s.address(j, common.Cut(index, s.h, 0, tmp), common.Cut(index, s.h, tmp, s.h/s.d))
		seed := hash.FuncAlpha(address, sk1)
		wots, err := NewWOTSPlusSignature(int(s.w), Size(s.n), seed, common.Flatten(s.getMask(WOTS_Mask)))
		if err != nil {
			panic(err)
		}
		//sk, p_ := wots.GenerateKey()
		sk, _ := wots.GenerateKey()
		//fmt.Printf("1. wots pk, index: %d, key: %x\n", j, p_)
		//pkW := merkle.LTreeWithMask(p_, int(s.n), hash.F, common.Flatten(s.getMask(LTREE_Mask)))
		//fmt.Printf("1. wots 公钥的L-Tree根节点, index: %d, key: %x\n", j, pkW)

		// 对 pkH 进行签名
		sign := wots.Sign(pkH, sk)

		sks := make([][]byte, 1<<(s.h/s.d))
		// 将这一个大 node 计算出来
		// 层数为 j，index 为 i(0, (d-1-j)h/d)
		// 这一个大 node 一共 1<<h/d-1 个 WOTS 密钥对
		// 类似 GenerateKey 中的
		for i := uint64(0); i < 1<<(s.h/s.d); i++ {
			//if j == s.d-1 {
			//	fmt.Println("----", common.Cut(index, s.h, 0, tmp), common.Cut(index, s.h, tmp, s.h/s.d), i)
			//}
			address := s.address(j, common.Cut(index, s.h, 0, tmp), i)
			seed := hash.FuncAlpha(address, sk1)
			wots, err := NewWOTSPlusSignature(int(s.w), Size(s.n), seed, common.Flatten(s.getMask(WOTS_Mask)))
			if err != nil {
				panic(err)
			}
			_, pk := wots.GenerateKey()
			// 对 pk 求 L-Tree 的根节点
			root := merkle.LTreeWithMask(pk, int(s.n), hash.F, common.Flatten(s.getMask(LTREE_Mask)))
			sks[i] = root
			//if j == s.d-1 {
			//	fmt.Printf("2. leaf: %x\n", root)
			//}
		}
		// TODO 这里的 mask 还需要在处理一下，因为 TREE_Mask 是整棵树的掩码 done
		// 需要计算每 layer 使用的, 当前层数为 j
		tree, err := merkle.NewTreeWithMask(int(s.h/s.d)+1, int(s.n), common.Flatten(s.getMask(TREE_Mask)[2*j*(s.h/s.d):(2*j+2)*(s.h/s.d)]))
		if err != nil {
			panic(err)
		}

		//fmt.Printf("index: %d, TREE_MASK: %x\n\n", j, s.getMask(TREE_Mask)[2*j*(s.h/s.d):(2*j+2)*(s.h/s.d)])

		err = tree.SetSkWithMask(common.Flatten(sks))
		if err != nil {
			panic(err)
		}
		// 添加到签名中
		// σw
		signature = append(signature, sign...)
		// authentication path
		auth := tree.AuthenticationPath(0, int(common.Cut(index, s.h, tmp, s.h/s.d)))

		// 有关鉴权路径
		//fmt.Printf("1. index: %d, pk: %x, auth: %x\n\n", j, hash.Sha256(sk), auth)
		signature = append(signature, common.Flatten(auth)...)

		pkH, _ = tree.GetPk()
		//fmt.Printf("1. pkH: %x\n", pkH)
		//if j == s.d-1 {
		//	fmt.Printf("2. root d-1: %x\n", pkH)
		//}

		//start := 1<<(s.h/s.d) - 1
		//pkH_ := merkle.ComputeRootWithMask(pkW, start+int(common.Cut(index, s.h, tmp, s.h/s.d)), auth, hash.Sha256, s.getMask(TREE_Mask)[2*j*(s.h/s.d):(2*j+2)*(s.h/s.d)])
		//
		////fmt.Printf("1. index: %d, pkH: %x\n", j, pkH)
		//fmt.Println(common.Equal(pkH_, pkH))
	}

	return signature
}

func (s *Sphincs) Verify(message []byte, pk []byte, signature []byte) bool {
	// i 的大小
	iSize := uint64(8)
	// R1 的大小
	r1Size := s.n / 8
	x := uint64(calc(int(s.k), int(s.tau)))
	// horst 签名大小
	horstSize := (s.k + (s.tau-x)*s.k + 1<<x) * s.n / 8
	// wots+ 签名大小
	wotsSize := s.l * s.n / 8
	// 鉴权路径大小
	authSize := (s.h / s.d) * s.n / 8
	//println(iSize, r1Size, x, horstSize, wotsSize, authSize)

	// 选择 horst 密钥的索引值
	index := binary.BigEndian.Uint64(signature[:iSize])
	//println(index)

	// 掩码
	//mask := pk[s.n/8:]

	// 1. 对于任意长度的消息，计算 randomized message digest

	// 随机摘要值
	d := hash.HashMessage(signature[iSize:iSize+r1Size], message)
	//fmt.Printf("d: %x\n", d)

	horstMask := pk[s.n/8 : s.n/8+s.tau*2*s.n/8]

	//fmt.Printf("pk: %x\n mask: %x\n", pk, common.Flatten(s.getMask(HORST_Mask)))
	//fmt.Println("----", common.Equal(common.Flatten(s.getMask(HORST_Mask)), mask))

	h, err := newHorst(int(s.tau), int(s.k), int(s.n), horstMask)

	if err != nil {
		panic(err)
	}
	// 首先校验 HORST 签名
	pkH, flag := h.verify(d, signature[iSize+r1Size:iSize+r1Size+horstSize])

	//fmt.Printf("pkH: \n%x\n", pkH)

	if !flag {
		return false
	}

	wotsMask := pk[s.n/8 : s.n/8+(1<<s.w-1)*s.n/8]
	wots, err := newWOTSPlus(int(s.w), int(s.n), wotsMask)
	// 目前来说上面的对上了
	// 接下来需要对 WOTS+ 进行校验了

	// (σW,0, Auth_{A_0}, ..., σ_{W,d-1}, Auth_{A_{d-1})
	sigmaAndAuth := signature[iSize+r1Size+horstSize:]
	partSize := wotsSize + authSize
	lTreeMask := pk[s.n/8 : (s.n/8 + s.ltree*s.n/8)]
	// s.ltree : s.ltree+2*s.h
	treeMask := pk[s.n/8+s.ltree*s.n/8 : s.n/8+(2*s.h+s.ltree)*s.n/8]

	start := 1<<(s.h/s.d) - 1
	// pkH 用来计算 wots 的公钥
	for i := uint64(0); i < s.d; i++ {
		tmp := (s.d - 1 - i) * s.h / s.d

		part := sigmaAndAuth[i*partSize : (i+1)*partSize]

		// pkH 被签名，返回值为公钥
		wotsPk := wots.verify(pkH, part[:wotsSize])
		//fmt.Printf("2. wots pk, index: %d, key: %x\n", i, wotsPk)
		// L-Tree 根节点
		pkW := merkle.LTreeWithMask(wotsPk, int(s.n), hash.F, lTreeMask)
		// 大 Node 的根节点
		//fmt.Printf("2. wots 公钥的L-Tree根节点, index: %d, key: %x\n", i, pkW)

		// 计算出大 Node 的根节点
		j := int(common.Cut(index, s.h, tmp, s.h/s.d))

		mask := common.Ravel(treeMask[2*i*(s.h/s.d)*s.n/8:(2*i+2)*(s.h/s.d)*s.n/8], int(s.n/8))
		// 大 Node 的根节点
		pkH = merkle.ComputeRootWithMask(pkW, start+j, common.Ravel(part[wotsSize:], int(s.n/8)), hash.Sha256, mask)

		// 这个已经 ok 了，可以对应上去
		//fmt.Printf("2. index: %d, pkH: %x\n", i, pkH)
		//fmt.Printf("2.index: %d, key: %x\n auth: %x\n\n", i, pkW, common.Ravel(part[wotsSize:], int(s.n/8)))

		//fmt.Printf("index: %d, TREE_MASK: %x\n\n", i, s.getMask(TREE_Mask)[2*i*(s.h/s.d):(2*i+2)*(s.h/s.d)])
	}

	pk_ := pk[:s.n/8]
	//fmt.Printf("pkH: %x\n", pkH)
	//fmt.Printf("pk: %x\n", pk_)
	return common.Equal(pkH, pk_)
}

// 注意了，这里我们要求 address 的 bit 长度必须是 8 的倍数
// 否则不好计算哈
// bit length of address = ceil(log(d+1)) + (d-1)(h/d) + h/d = ceil(log(d+1)) + h
// SPHINCS-256 中，我们有 length = ceil(log( 12 + 1 )) + 60 = 64 bits
// layer 为 key pair 所在的层数，根节点为 0
// index 为 所在节点在层数中的索引值
// idx 为密钥对的索引
// TODO 实现，下面的实现方式并不是论文中提到的
//  因为位数如果不确定的话，不太好处理，针对 256 我们可以单独处理
func (s *Sphincs) address(layer, index, keyIdx uint64) []byte {
	// length := uint64(math.Ceil(math.Log2(float64(s.d+1)))) + s.h
	// if length%8 != 0 {
	// 	panic("address 的 bit 长度应该是 8 的倍数")
	// }
	res := make([]byte, 8)
	binary.BigEndian.PutUint64(res, layer^index^keyIdx)
	return res
}

// 掩码的个数
func (s *Sphincs) calculateP() {
	num1 := 1<<s.w - 1

	l1 := int(s.n / s.w)

	l2_ := l2(l1, int(s.w))
	ltree := uint64(math.Ceil(math.Log2(float64(l1 + l2_))))
	num2 := 2 * (s.h + ltree)

	num3 := 2 * s.tau

	max := uint64(num1)
	if num2 > max {
		max = num2
	}
	if num3 > max {
		max = num3
	}
	s.p = max
	s.ltree = ltree * 2
	s.l = uint64(l1 + l2_)

	// 初始化掩码
	s.mask = make([][]byte, max)
}

// 获取对应的掩码
type maskType int

const (
	WOTS_Mask  maskType = 1
	HORST_Mask maskType = 2
	LTREE_Mask maskType = 3
	TREE_Mask  maskType = 4
)

func (s *Sphincs) getMask(typ maskType) [][]byte {
	mask := s.mask
	switch typ {
	case WOTS_Mask:
		return mask[:(1<<s.w - 1)]
	case HORST_Mask:
		return mask[:2*s.tau]
	case LTREE_Mask:
		return mask[:s.ltree]
	case TREE_Mask:
		return mask[s.ltree : s.ltree+2*s.h]
	default:
		panic("没有该掩码类型")
	}
}
