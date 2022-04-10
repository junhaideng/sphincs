package api

import (
	"errors"
	"fmt"
	"github.com/junhaideng/sphincs/hash"
	"github.com/junhaideng/sphincs/signature"
	"time"
)

func GenSignature(algorithm string, message []byte) (*SignatureResponse, error) {
	var s signature.Signature
	var err error
	// 这里使用的参数都是 SPHINCS-256 中对应的
	switch SignatureAlgorithm(algorithm) {
	case HORS:
		s, err = signature.NewHorsSignature(16, 32)
	case HORST:
		s, err = signature.NewHorstSignature(16, 32, genRandBytes(32), genRandBytes(32*2*16))
		message = hash.Sha512(message) // horst 的输入直接为 512 bits，和 sphincs 中的对齐，需要自己先 hash 一波
	case LAMPORT:
		s, err = signature.NewLamportSignature(256)
	case SPHINCS:
		s, err = signature.NewSphincs(256, 512, 60, 12, 4, 16, 32, genRandBytes(32))
	case WOTS:
		s, err = signature.NewWinternitzSignature(4, 256)
	case WOTSPLUS:
		s, err = signature.NewWOTSPlusSignature(4, 256, genRandBytes(32), genRandBytes(32*15))
	default:
		return nil, errors.New("不支持该算法")
	}
	if err != nil {
		return nil, err
	}

	start := time.Now()
	sk, pk := s.GenerateKey()
	middle := time.Now()
	sigma := s.Sign(message, sk)
	end := time.Now()
	flag := s.Verify(message, pk, sigma)
	last := time.Now()
	fmt.Printf("algorithm: %s, flag: %t\n", algorithm, flag)
	return &SignatureResponse{
		SK:    toHex(sk),
		PK:    toHex(pk),
		Sigma: toHex(sigma),
		Cost: &Cost{
			Gen:    middle.Sub(start).String(),
			Sign:   end.Sub(middle).String(),
			Verify: last.Sub(end).String(),
		},
	}, nil
}
