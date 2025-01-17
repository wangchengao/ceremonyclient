package token_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestProcessJoinsAndLeaves(t *testing.T) {
	set := [][]byte{}
	for i := 0; i < 6000; i++ {
		b := make([]byte, 9999)
		rand.Read(b)
		set = append(set, b)
	}

	joins := []token.PeerSeniorityItem{}
	seniority := &token.PeerSeniority{}
	for i, s := range set {
		joins = append(joins, token.NewPeerSeniorityItem(uint64(i), string(s)))
		(*seniority)[string(s)] = token.NewPeerSeniorityItem(uint64(i), string(s))
	}
	tr := []*tries.RollingFrecencyCritbitTrie{
		&tries.RollingFrecencyCritbitTrie{},
		&tries.RollingFrecencyCritbitTrie{},
	}
	app := &application.TokenApplication{
		Tries: tr,
	}
	token.ProcessJoinsAndLeaves(joins, []token.PeerSeniorityItem{}, app, seniority, &protobufs.ClockFrame{FrameNumber: 9999})

	assert.Equal(t, len(app.Tries), 4)
	assert.Equal(t, len(app.Tries[1].FindNearestAndApproximateNeighbors(make([]byte, 32))), 2048)
	assert.Equal(t, len(app.Tries[2].FindNearestAndApproximateNeighbors(make([]byte, 32))), 2048)
	assert.Equal(t, len(app.Tries[3].FindNearestAndApproximateNeighbors(make([]byte, 32))), 1904)

	leaves := []token.PeerSeniorityItem{}
	// Seniority works from highest to lowest, so we should have one removal in the bottom most, three in the middle, and one in the highest
	leaves = append(leaves, joins[30])
	leaves = append(leaves, joins[1907])
	leaves = append(leaves, joins[1955])
	leaves = append(leaves, joins[2047])
	leaves = append(leaves, joins[4095])
	token.ProcessJoinsAndLeaves([]token.PeerSeniorityItem{}, leaves, app, seniority, &protobufs.ClockFrame{FrameNumber: 10000})

	assert.Equal(t, len(app.Tries), 4)
	assert.Equal(t, len(app.Tries[1].FindNearestAndApproximateNeighbors(make([]byte, 32))), 2048)
	assert.Equal(t, len(app.Tries[2].FindNearestAndApproximateNeighbors(make([]byte, 32))), 2048)
	assert.Equal(t, len(app.Tries[3].FindNearestAndApproximateNeighbors(make([]byte, 32))), 1899)
}
