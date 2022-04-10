package api

import (
	"encoding/hex"
	"math/rand"
	"time"
)

type Cost struct {
	Gen    string `json:"gen"`
	Sign   string `json:"sign"`
	Verify string `json:"verify"`
}

type SignatureResponse struct {
	SK    string `json:"sk"`
	PK    string `json:"pk"`
	Sigma string `json:"sigma"`
	Cost  *Cost  `json:"cost"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func genRandBytes(n int) []byte {
	res := make([]byte, n)
	for i := 0; i < len(res); i++ {
		res[i] = byte(rand.Intn(128))
	}
	return res
}

func toHex(data []byte) string {
	return hex.EncodeToString(data)
}
