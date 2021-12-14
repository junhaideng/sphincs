package signature

import (
	"fmt"
	"math"
	"testing"
)

func ceil(n, w int) int {
	return int(math.Ceil(float64(n / w)))
}

// sphincs
func t2(t1, w int) int {
	up := math.Log2(float64(t1 * (1<<w - 1)))
	return int(math.Floor(up/float64(w))) + 1
}

// pdf
func t2_(t1, w int) int {
	up := math.Floor(math.Log2(float64(t1))) + 1 + float64(w)
	return int(math.Ceil(up / float64(w)))
}

func TestMath(t *testing.T) {
	n, w := 256, 4
	t1 := ceil(n, w)
	fmt.Println(t2(t1, w), t2_(t1, w), t1)
}
