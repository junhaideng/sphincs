package merkle

import (
	"github.com/junhaideng/sphincs/hash"
)

type Option interface {
	apply(t *Tree)
}

type function func(t *Tree)

func (f function) apply(t *Tree) {
	f(t)
}

func WithN(n int) Option {
	return function(func(t *Tree) {
		t.n = n
		if n == 256 {
			t.hash = hash.Sha256
			return
		}
		if n == 512 {
			t.hash = hash.Sha512
			return
		}
		panic("n should be 256 or 512")
	})
}

func WithHash(hash hash.Hash) Option {
	return function(func(t *Tree) {
		t.hash = hash
	})
}
