package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

	assert.Equal(BitCount(7), 3)
	assert.Equal(BitCount(8), 4)
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
	value, power := NearestPowerOf2(10)
	assert.Equal(16, value)
	assert.Equal(4, power)

	value, power = NearestPowerOf2(11)
	assert.Equal(16, value)
	assert.Equal(4, power)

	value, power = NearestPowerOf2(12)
	assert.Equal(16, value)
	assert.Equal(4, power)

	value, power = NearestPowerOf2(1)
	assert.Equal(1, value)
	assert.Equal(0, power)

	value, power = NearestPowerOf2(2)
	assert.Equal(2, value)
	assert.Equal(1, power)

	value, power = NearestPowerOf2(4)
	assert.Equal(4, value)
	assert.Equal(2, power)

	value, power = NearestPowerOf2(5)
	assert.Equal(8, value)
	assert.Equal(3, power)

}

func TestChop(t *testing.T) {
	rand := make([]byte, 32)
	for i := 0; i < len(rand); i++ {
		rand[i] = 0
	}
	rand[7] = 7 // 0000_0111
	h := uint64(60)
	r, _ := Chop(rand, h)
	assert.Equal(t, uint64(0), r)

	rand[7] = 32 // 0010_0000
	r, _ = Chop(rand, h)
	assert.Equal(t, uint64(2), r)

	h = uint64(64)
	r, _ = Chop(rand, h)
	assert.Equal(t, uint64(32), r)
}

func TestCut(t *testing.T) {
	var i uint64 = 0x00ff000000000000 // 后面连续 12 个 0
	assert.Equal(t, uint64(255), Cut(i, 64, 8, 8))
	assert.Equal(t, uint64(15), Cut(i, 64, 12, 4))

	var j uint64 = 0x00000000000000ff // 14 个 0
	assert.Equal(t, uint64(0), Cut(j, 64, 8, 8))
}
