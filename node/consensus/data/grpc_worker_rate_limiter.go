package data

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RateLimiter struct {
	mu         sync.RWMutex
	clients    map[peer.ID]time.Time
	maxTokens  int
	windowSize time.Duration
}

type bucket struct {
	tokens   int
	lastSeen time.Time
}

func NewRateLimiter(
	maxTokens int,
	windowSize time.Duration,
) *RateLimiter {
	return &RateLimiter{
		clients:    make(map[peer.ID]time.Time),
		maxTokens:  maxTokens,
		windowSize: windowSize,
	}
}

func (rl *RateLimiter) Allow(peerId peer.ID) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	windowStart := now.Add(-rl.windowSize)

	for peerId, time := range rl.clients {
		if time.Before(windowStart) {
			delete(rl.clients, peerId)
		}
	}

	if _, exists := rl.clients[peerId]; !exists {
		if len(rl.clients) >= rl.maxTokens {
			return status.Errorf(codes.ResourceExhausted,
				"maximum number of unique callers (%d) reached", rl.maxTokens)
		}
	}

	rl.clients[peerId] = now

	return nil
}
