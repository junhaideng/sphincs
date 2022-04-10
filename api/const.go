package api

type SignatureAlgorithm string

const (
	HORS     = "hors"
	HORST    = "horst"
	LAMPORT  = "lamport"
	SPHINCS  = "sphincs"
	WOTS     = "wots"
	WOTSPLUS = "wots+"
)
