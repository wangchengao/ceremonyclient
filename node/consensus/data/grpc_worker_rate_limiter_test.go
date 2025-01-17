package data_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data"
)

func TestRateLimiter(t *testing.T) {
	limiter := data.NewRateLimiter(5, 10*time.Second)

	for i := 0; i < 7; i++ {
		_, priv, _ := ed448.GenerateKey(rand.Reader)
		privKey, err := crypto.UnmarshalEd448PrivateKey(priv)
		if err != nil {
			t.FailNow()
		}

		pub := privKey.GetPublic()

		peer, _ := peer.IDFromPublicKey(pub)
		err = limiter.Allow(peer)
		if i < 5 {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
		}

		time.Sleep(time.Second)
	}

}
