package tries_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestSerializers(t *testing.T) {
	tree := &tries.RollingFrecencyCritbitTrie{}
	for i := 0; i < 100; i++ {
		seed := make([]byte, 57)
		rand.Read(seed)

		priv := ed448.NewKeyFromSeed(seed)
		pubkey := (priv.Public()).(ed448.PublicKey)
		addr, err := poseidon.HashBytes(pubkey)
		assert.NoError(t, err)

		v := uint64(i)
		a := addr.Bytes()
		b := make([]byte, 32)
		copy(b[32-len(a):], addr.Bytes())

		tree.Add(b, v)
	}

	newTree := &tries.RollingFrecencyCritbitTrie{}
	buf, err := tree.Serialize()
	assert.NoError(t, err)
	err = newTree.Deserialize(buf)
	assert.NoError(t, err)
}

func TestCritbitReinit(t *testing.T) {
	tree := &tries.RollingFrecencyCritbitTrie{}
	set := [][]byte{}
	for i := 0; i < 1024; i++ {
		seed := make([]byte, 32)
		rand.Read(seed)
		set = append(set, seed)
		tree.Add(seed, 14)
		assert.True(t, tree.Contains(seed))
		tree.Remove(seed)
		assert.False(t, tree.Contains(seed))
	}
	for i := 0; i < 1024; i++ {
		tree.Add(set[i], 14)
	}
	near := tree.FindNearestAndApproximateNeighbors(make([]byte, 32))
	assert.Equal(t, 1024, len(near))
	for i := 0; i < 1024; i++ {
		tree.Remove(set[i])
		assert.False(t, tree.Contains(set[i]))
		near = tree.FindNearestAndApproximateNeighbors(make([]byte, 32))
		assert.Equal(t, 1024-i-1, len(near))
	}
	near = tree.FindNearestAndApproximateNeighbors(make([]byte, 32))
	assert.Equal(t, 0, len(near))
}
