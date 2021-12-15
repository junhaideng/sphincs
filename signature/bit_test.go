package signature

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetBit(t *testing.T) {
	assert := assert.New(t)
	var b byte = 'a' // 0110_0001
	res := []int{0, 1, 1, 0, 0, 0, 0, 1}
	for i, r := range res {
		bit := getBit(b, i)
		assert.Equal(r, bit, "should be equal, index: %d", i)
	}
}

func TestBitCount(t *testing.T) {
	assert := assert.New(t)
	var b uint64 = 'a' // 0110_0001
	assert.Equal(bitCount(b), 7)
}
