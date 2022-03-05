package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetBit(t *testing.T) {
	assert := assert.New(t)
	var b byte = 'a' // 0110_0001
	res := []int{0, 1, 1, 0, 0, 0, 0, 1}
	for i, r := range res {
		bit := GetBit(b, i)
		assert.Equal(r, bit, "should be Equal, index: %d", i)
	}
}

func TestBitCount(t *testing.T) {
	assert := assert.New(t)
	var b uint64 = 'a' // 0110_0001
	assert.Equal(BitCount(b), 7)
}

func TestToInt(t *testing.T) {
	assert := assert.New(t)
	bytes := [][]byte{
		{0x1},
		{0x1, 0x2},
		{0x1, 0x2, 0x3, 0x4},
		{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
	}
	res := []uint64{1, 258, 16909060, 72623859790382856}
	for i := 0; i < len(bytes); i++ {
		assert.Equal(res[i], ToInt(bytes[i]))
	}
}

func TestNearestPowerOf2(t *testing.T) {
	assert := assert.New(t)
	assert.Equal(16, NearestPowerOf2(10))
	assert.Equal(16, NearestPowerOf2(11))
	assert.Equal(16, NearestPowerOf2(12))
	assert.Equal(1, NearestPowerOf2(1))
	assert.Equal(2, NearestPowerOf2(2))
	assert.Equal(4, NearestPowerOf2(4))
	assert.Equal(8, NearestPowerOf2(5))
}
