package internal

import (
	"math/rand"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
)

// PeerAddrInfosToPeerIDSlice converts a slice of peer.AddrInfo to a slice of peer.ID.
func PeerAddrInfosToPeerIDSlice(p []peer.AddrInfo) []peer.ID {
	ids := make([]peer.ID, len(p))
	for i, pi := range p {
		ids[i] = pi.ID
	}
	return ids
}

// PeerAddrInfosToPeerIDMap converts a slice of peer.AddrInfo to a map of peer.ID.
func PeerAddrInfosToPeerIDMap(p []peer.AddrInfo) map[peer.ID]struct{} {
	m := make(map[peer.ID]struct{}, len(p))
	for _, pi := range p {
		m[pi.ID] = struct{}{}
	}
	return m
}

// IDServiceFromHost returns the identify.IDService from a host.Host.
func IDServiceFromHost(h host.Host) identify.IDService {
	return h.(interface{ IDService() identify.IDService }).IDService()
}

// Permuted returns a permuted copy of a slice.
func Permuted[T any](slice []T) []T {
	permuted := make([]T, len(slice))
	for i := range rand.Perm(len(slice)) {
		permuted[i] = slice[i]
	}
	return permuted
}
