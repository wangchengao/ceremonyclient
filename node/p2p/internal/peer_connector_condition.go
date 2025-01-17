package internal

import (
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerConnectorCondition is a condition that determines whether a peer connector should connect.
type PeerConnectorCondition interface {
	// Should returns true if the peer connector should connect.
	Should() bool
}

type notEnoughPeersCondition struct {
	host     host.Host
	minPeers int
	peers    map[peer.ID]struct{}
}

// Should implements PeerConnectorCondition.
func (c *notEnoughPeersCondition) Should() bool {
	count := 0
	for _, p := range c.host.Network().Peers() {
		if _, ok := c.peers[p]; ok {
			count++
		}
	}
	return count < c.minPeers
}

// NewNotEnoughPeersCondition creates a new not enough peers condition.
func NewNotEnoughPeersCondition(host host.Host, minPeers int, peers map[peer.ID]struct{}) PeerConnectorCondition {
	return &notEnoughPeersCondition{
		host:     host,
		minPeers: minPeers,
		peers:    peers,
	}
}
