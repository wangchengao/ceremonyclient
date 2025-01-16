package token_test

import (
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
)

func TestRebuildPeerSeniority(t *testing.T) {
	m, err := token.RebuildPeerSeniority(0)
	assert.NoError(t, err)
	peerId := "QmcKQjpQmLpbDsiif2MuakhHFyxWvqYauPsJDaXnLav7PJ"
	b, _ := poseidon.HashBytes([]byte(peerId))
	a := m[string(b.FillBytes(make([]byte, 32)))]
	assert.Equal(t, a, 0)
}
