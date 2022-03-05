package rand

import (
	"hash/fnv"
	"io"
	"math/rand"
)

// Rander 为随机数生成器接口
// 可以注意的是：一般很多随机数生成器的种子都是 64 bits 的整数型
// 不过在 SPHINCS 中，我们要使用 n bits 的随机数种子，得自己设置
// 故在这里设置该接口，编写代码的时候可以使用接口调用，不必在乎其中实现
type Rander interface {
	// Seed 设置随机数种子
	Seed([]byte)
	io.Reader
}

// Rand 实现 Rander 接口
// 意在提供一个简单的随机数生成器，只作为演示使用
type Rand struct {
	*rand.Rand
}

func (r *Rand) Read(p []byte) (n int, err error) {
	return r.Rand.Read(p)
}

func (r *Rand) Seed(p []byte) {
	h := fnv.New64()
	h.Write(p)
	source := rand.NewSource(int64(h.Sum64()))
	r.Rand = rand.New(source)
}

func New(seed []byte) Rander {
	r := &Rand{}
	r.Seed(seed)
	return r
}
