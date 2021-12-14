package signature

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEqual(t *testing.T) {
	assert := assert.New(t)
	a := []byte("hello")
	b := []byte("hello1")
	c := []byte("hello")
	assert.True(equal(a, c))
	assert.False(equal(a, b))
	assert.False(equal(nil, a))
	assert.True(equal(nil, nil))
}
