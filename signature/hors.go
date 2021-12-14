package signature

type Hors struct {
	n Size
}

func (h *Hors) GenerateKey() (sk []byte, pk []byte) {
	n := int(h.n)
	sk = make([]byte, n)

	//TODO implement me
	panic("implement me")
}

func (h *Hors) Sign(message []byte, sk []byte) []byte {
	//TODO implement me
	panic("implement me")
}

func (h *Hors) Verify(message []byte, pk []byte, signature []byte) bool {
	//TODO implement me
	panic("implement me")
}

//
//// private key：一系列的索引， 整数
//// public key: hash private key
//
//import (
//	"bytes"
//	"crypto/sha256"
//	"fmt"
//	"math/rand"
//	"strconv"
//	"time"
//)
//
//var n = 256
//
//func hash(b []byte) []byte {
//	h := sha256.New()
//	return h.Sum(b)
//}
//
//func toBytes(num int) []byte {
//	return []byte(fmt.Sprintf("%d", num))
//}
//
//func toInt(b []byte) int {
//	i, err := strconv.Atoi(string(b))
//	if err != nil {
//		fmt.Println("err: ", err)
//		return 0
//	}
//	return i
//}
//
//func GenPrivateKey() []int {
//	private := make([]int, n)
//	for i := 0; i < n; i++ {
//		private[i] = rand.Intn(n)
//	}
//	return private
//}
//
//// 通过对 private key 进行 hash 得到
//func GetPublicKey(private []int) [][]byte {
//	public := make([][]byte, n)
//	for i := 0; i < n; i++ {
//		public[i] = hash(toBytes(private[i]))
//	}
//	return public
//}
//
//func Sign(message []byte, public [][]byte) []byte {
//	m := hash(message)
//	signature := &bytes.Buffer{}
//	// TODO: adjust len(m) , len(m) 一直为 32 (sha256)
//	for i := 0; i < len(m); i++ {
//		signature.Write(public[m[i]])
//	}
//	return signature.Bytes()
//}
//
//func Verify(message, sign []byte, public [][]byte) bool {
//	m := hash(message)
//	signature := &bytes.Buffer{}
//	for i := 0; i < len(m); i++ {
//		signature.Write(public[m[i]])
//	}
//	bytes := signature.Bytes()
//	if len(bytes) != len(sign) {
//		return false
//	}
//	for i := 0; i < signature.Len(); i++ {
//		if bytes[i] != sign[i] {
//			return false
//		}
//	}
//	return true
//}
//
//func init() {
//	rand.Seed(time.Now().UnixNano())
//}
//
//func main() {
//	private := GenPrivateKey()
//	public := GetPublicKey(private)
//	// fmt.Println(public)
//
//	message := []byte("hello")
//
//	sign := Sign(message, public)
//	fmt.Printf("%x\n", sign)
//	fmt.Println(Verify(message, sign, public))
//}
