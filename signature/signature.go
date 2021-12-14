package signature

type Signature interface {
	// GenerateKey generates secret key and public key
	GenerateKey() (sk []byte, pk []byte)
	//Sign computes signature of message using secret key
	Sign(message []byte, sk []byte) []byte
	// Verify check if the signature is valid
	Verify(message []byte, pk []byte, signature []byte) bool
}
