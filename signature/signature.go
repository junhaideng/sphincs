package signature

import "github.com/junhaideng/sphincs/common"

type Size = common.Size

const Size512 = common.Size512
const Size256 = common.Size256
const BitSize = common.BitSize

type Signature interface {
	// GenerateKey generates secret key and public key
	GenerateKey() (sk []byte, pk []byte)
	// Sign computes signature of message using secret key
	Sign(message []byte, sk []byte) []byte
	// Verify check if the signature is valid
	Verify(message []byte, pk []byte, signature []byte) bool
}
