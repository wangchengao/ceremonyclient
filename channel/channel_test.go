package channel_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/channel"
	generated "source.quilibrium.com/quilibrium/monorepo/channel/generated/channel"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

type peer struct {
	privKey         *curves.ScalarEd448
	pubKey          *curves.PointEd448
	pubKeyB64       string
	identityKey     *curves.ScalarEd448
	identityPubKey  *curves.PointEd448
	signedPreKey    *curves.ScalarEd448
	signedPrePubKey *curves.PointEd448
}

func generatePeer() *peer {
	privKey := &curves.ScalarEd448{}
	privKey = privKey.Random(rand.Reader).(*curves.ScalarEd448)
	identityKey := &curves.ScalarEd448{}
	identityKey = identityKey.Random(rand.Reader).(*curves.ScalarEd448)
	signedPreKey := &curves.ScalarEd448{}
	signedPreKey = signedPreKey.Random(rand.Reader).(*curves.ScalarEd448)

	pubkey := privKey.Point().Generator().Mul(privKey).(*curves.PointEd448)
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubkey.ToAffineCompressed())
	return &peer{
		privKey:         privKey,
		pubKey:          pubkey,
		pubKeyB64:       pubKeyB64,
		identityKey:     identityKey,
		identityPubKey:  identityKey.Point().Generator().Mul(identityKey).(*curves.PointEd448),
		signedPreKey:    signedPreKey,
		signedPrePubKey: signedPreKey.Point().Generator().Mul(signedPreKey).(*curves.PointEd448),
	}
}

func remapOutputs(maps map[string]map[string]string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for k := range maps {
		out[k] = map[string]string{}
	}

	for k := range maps {
		for ik, iv := range maps[k] {
			out[ik][k] = iv
		}
	}

	return out
}

func TestChannel(t *testing.T) {
	peers := []*peer{}
	for i := 0; i < 4; i++ {
		peers = append(peers, generatePeer())
	}

	sort.Slice(peers, func(i, j int) bool {
		return bytes.Compare(peers[i].pubKey.ToAffineCompressed(), peers[j].pubKey.ToAffineCompressed()) <= 0
	})

	trs := map[string]*generated.TripleRatchetStateAndMetadata{}

	peerids := [][]byte{}
	outs := map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		outs[peers[i].pubKeyB64] = make(map[string]string)
		peerids = append(peerids,
			append(
				append(
					append([]byte{}, peers[i].pubKey.ToAffineCompressed()...),
					peers[i].identityPubKey.ToAffineCompressed()...,
				),
				peers[i].signedPrePubKey.ToAffineCompressed()...,
			),
		)
	}

	for i := 0; i < 4; i++ {
		otherPeerIds := [][]byte{}
		for j := 0; j < 4; j++ {
			if i != j {
				otherPeerIds = append(otherPeerIds, peerids[j])
			}
		}

		tr := channel.NewTripleRatchet(
			otherPeerIds,
			peers[i].privKey.Bytes(),
			peers[i].identityKey.Bytes(),
			peers[i].signedPreKey.Bytes(),
			2,
			true,
		)
		trs[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = trs[peers[i].pubKeyB64].Metadata
	}

	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 1
	next := map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound1(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k, _ := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 2
	next = map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound2(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 3
	next = map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound3(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	// round 4
	next = map[string]*generated.TripleRatchetStateAndMetadata{}
	outs = map[string]map[string]string{}
	for i := 0; i < 4; i++ {
		tr := channel.TripleRatchetInitRound4(
			*trs[peers[i].pubKeyB64],
		)
		next[peers[i].pubKeyB64] = &tr
		outs[peers[i].pubKeyB64] = next[peers[i].pubKeyB64].Metadata
	}

	trs = next
	outs = remapOutputs(outs)

	for k := range trs {
		for ik := range trs[k].Metadata {
			delete(trs[k].Metadata, ik)
		}

		for ik, iv := range outs[k] {
			trs[k].Metadata[ik] = iv
		}
	}

	for i := 0; i < 4; i++ {
		send := channel.TripleRatchetEncrypt(
			generated.TripleRatchetStateAndMessage{
				RatchetState: trs[peers[i].pubKeyB64].RatchetState,
				Message:      []byte(fmt.Sprintf("hi-%d", i)),
			},
		)
		trs[peers[i].pubKeyB64].RatchetState = send.RatchetState
		for j := 0; j < 4; j++ {
			if i != j {
				msg := channel.TripleRatchetDecrypt(
					generated.TripleRatchetStateAndEnvelope{
						RatchetState: trs[peers[j].pubKeyB64].RatchetState,
						Envelope:     send.Envelope,
					},
				)
				trs[peers[j].pubKeyB64].RatchetState = msg.RatchetState
				if !bytes.Equal(msg.Message, []byte(fmt.Sprintf("hi-%d", i))) {
					assert.FailNow(t, "mismatch messages")
				}
			}
		}
	}
}
