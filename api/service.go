package api

import (
	"errors"
	"fmt"
	"github.com/junhaideng/sphincs/signature"
	"time"
)

func GenSignature(algorithm string, message string) (*SignatureResponse, error) {
	var s signature.Signature
	var err error
	switch SignatureAlgorithm(algorithm) {
	case HORS:
		s, err = signature.NewHorsSignature(16, 32)
	case HORST:
		s, err = signature.NewHorstSignature(16, 32, genRandBytes(32), genRandBytes(32*2*16))
	case LAMPORT:
		s, err = signature.NewLamportSignature(256)
	case SPHINCS:
		s, err = signature.NewSphincs(256, 512, 60, 12, 4, 16, 32, genRandBytes(32))
	case WOTS:
		s, err = signature.NewWinternitzSignature(4, 256)
	case WOTSPLUS:
		s, err = signature.NewWOTSPlusSignature(4, 256, genRandBytes(32), genRandBytes(32))
	default:
		return nil, errors.New("不支持该算法")
	}
	if err != nil {
		return nil, err
	}

	start := time.Now()
	sk, pk := s.GenerateKey()
	middle := time.Now()
	sigma := s.Sign([]byte(message), sk)
	end := time.Now()
	flag := s.Verify([]byte(message), pk, sigma)
	fmt.Printf("algorithm: %s, flag: %t\n", algorithm, flag)
	last := time.Now()
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
