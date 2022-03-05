package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEqual(t *testing.T) {
	assert := assert.New(t)
	a := []byte("hello")
	b := []byte("hello1")
	c := []byte("hello")
	assert.True(Equal(a, c))
	assert.False(Equal(a, b))
	assert.False(Equal(nil, a))
	assert.True(Equal(nil, nil))
}
