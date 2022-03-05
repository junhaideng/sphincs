package signature

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_calc(t *testing.T) {
	assert := assert.New(t)

	// for SPHINCS-256
	assert.Equal(6, calc(32, 16))
}
