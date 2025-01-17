package application_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/txaty/go-merkletree"
	"go.uber.org/zap"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type prover struct {
	privKey crypto.PrivKey
	pubKey  ed448.PublicKey
	peerId  []byte
	address []byte
}

func (p *prover) Sign(msg []byte) []byte {
	sig, _ := p.privKey.Sign(msg)
	return sig
}

func generateProver() *prover {
	pubKey, privKey, _ := ed448.GenerateKey(rand.Reader)
	privateKey, _ := crypto.UnmarshalEd448PrivateKey(privKey)
	publicKey := privateKey.GetPublic()
	peerId, _ := peer.IDFromPublicKey(publicKey)

	addrBI, _ := poseidon.HashBytes([]byte(peerId))
	return &prover{
		privKey: privateKey,
		pubKey:  pubKey,
		peerId:  []byte(peerId),
		address: addrBI.FillBytes(make([]byte, 32)),
	}
}

func (p *prover) generateJoin(frameNumber uint64) *protobufs.TokenRequest {
	payload := []byte("join")
	payload = binary.BigEndian.AppendUint64(payload, 0)
	payload = append(payload, bytes.Repeat([]byte{0xff}, 32)...)
	sig := p.Sign(payload)
	join := &protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Join{
			Join: &protobufs.AnnounceProverJoin{
				Filter:      bytes.Repeat([]byte{0xff}, 32),
				FrameNumber: 0,
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					Signature: sig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: p.pubKey,
					},
				},
			},
		},
	}

	return join
}

func (p *prover) generateTransfer(coin []byte) *protobufs.TokenRequest {
	payload := []byte("transfer")
	payload = append(payload, coin...)
	payload = append(payload, bytes.Repeat([]byte{0xff}, 32)...)
	sig := p.Sign(payload)
	join := &protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Transfer{
			Transfer: &protobufs.TransferCoinRequest{
				ToAccount: &protobufs.AccountRef{
					Account: &protobufs.AccountRef_ImplicitAccount{
						ImplicitAccount: &protobufs.ImplicitAccount{
							Address: bytes.Repeat([]byte{0xff}, 32),
						},
					},
				},
				OfCoin: &protobufs.CoinRef{
					Address: coin,
				},
				Signature: &protobufs.Ed448Signature{
					Signature: sig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: p.pubKey,
					},
				},
			},
		},
	}

	return join
}

func (p *prover) generateSplit(addr []byte) *protobufs.TokenRequest {
	payload := []byte("split")
	payload = append(payload, addr...)
	bi1, _ := new(big.Int).SetString("2048000000000", 10)
	bi2, _ := new(big.Int).SetString("2048000000000", 10)
	payload = append(payload, bi1.FillBytes(make([]byte, 32))...)
	payload = append(payload, bi2.FillBytes(make([]byte, 32))...)

	sig := p.Sign(payload)
	join := &protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Split{
			Split: &protobufs.SplitCoinRequest{
				Amounts: [][]byte{
					bi1.FillBytes(make([]byte, 32)),
					bi2.FillBytes(make([]byte, 32)),
				},
				OfCoin: &protobufs.CoinRef{
					Address: addr,
				},
				Signature: &protobufs.Ed448Signature{
					Signature: sig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: p.pubKey,
					},
				},
			},
		},
	}

	return join
}

func (p *prover) generateMerge(coins [][]byte) *protobufs.TokenRequest {
	payload := []byte("merge")
	payload = append(payload, coins[0]...)
	payload = append(payload, coins[1]...)

	sig := p.Sign(payload)
	join := &protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Merge{
			Merge: &protobufs.MergeCoinRequest{
				Coins: []*protobufs.CoinRef{
					&protobufs.CoinRef{
						Address: coins[0],
					},
					&protobufs.CoinRef{
						Address: coins[1],
					},
				},
				Signature: &protobufs.Ed448Signature{
					Signature: sig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: p.pubKey,
					},
				},
			},
		},
	}

	return join
}

func (p *prover) generateProof(
	frame *protobufs.ClockFrame,
	wprover *qcrypto.WesolowskiFrameProver,
	proofTree *merkletree.MerkleTree,
	breakWesoProof bool,
	breakTreeProof bool,
	treeRecovery bool,
) (*merkletree.MerkleTree, [][]byte, *protobufs.TokenRequest) {
	challenge := []byte{}
	challenge = append(challenge, []byte(p.peerId)...)
	challenge = binary.BigEndian.AppendUint64(
		challenge,
		frame.FrameNumber,
	)
	outs := []merkletree.DataBlock{}
	target := 8
	if treeRecovery {
		target = 4
	}
	for i := 0; i < target; i++ {
		individualChallenge := append([]byte{}, challenge...)
		individualChallenge = binary.BigEndian.AppendUint32(
			individualChallenge,
			uint32(i),
		)
		individualChallenge = append(individualChallenge, frame.Output...)
		if proofTree != nil {
			individualChallenge = append(individualChallenge, proofTree.Root...)
		}
		out, _ := wprover.CalculateChallengeProof(individualChallenge, 10000)
		if breakWesoProof {
			out[0] ^= 0xff
		}

		outs = append(outs, tries.NewProofLeaf(out))
	}

	proofTree, output, _ := tries.PackOutputIntoMultiPayloadAndProof(
		outs,
		len(outs),
		frame,
		proofTree,
	)

	mint := &protobufs.MintCoinRequest{
		Proofs: output,
	}
	if breakTreeProof {
		output[len(output)-1][0] ^= 0xff
	}
	mint.SignED448([]byte(p.pubKey), p.privKey.Sign)

	return proofTree, [][]byte{}, &protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Mint{
			Mint: mint,
		},
	}
}

func TestHandleProverJoin(t *testing.T) {
	log, _ := zap.NewDevelopment()
	bpub, bprivKey, _ := ed448.GenerateKey(rand.Reader)
	wprover := qcrypto.NewWesolowskiFrameProver(log)
	app := &application.TokenApplication{
		Beacon:     bpub,
		CoinStore:  store.NewPebbleCoinStore(store.NewInMemKVDB(), log),
		ClockStore: store.NewPebbleClockStore(store.NewInMemKVDB(), log),
		Logger:     log,
		Difficulty: 200000,
		Tries: []*tries.RollingFrecencyCritbitTrie{
			&tries.RollingFrecencyCritbitTrie{},
		},
		FrameProver: wprover,
	}

	baddr, _ := poseidon.HashBytes(bpub)

	app.Tries[0].Add(baddr.FillBytes(make([]byte, 32)), 0)

	gen, _, err := wprover.CreateDataGenesisFrame(
		p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
		make([]byte, 516),
		10000,
		&qcrypto.InclusionAggregateProof{},
		[][]byte{bpub},
	)
	selbi, _ := gen.GetSelector()
	txn, _ := app.ClockStore.NewTransaction(false)
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), gen, txn)
	app.ClockStore.CommitDataClockFrame(gen.Filter, 0, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	application.PROOF_FRAME_CUTOFF = 0
	application.PROOF_FRAME_RING_RESET = 0
	application.PROOF_FRAME_RING_RESET_2 = 0
	application.PROOF_FRAME_COMBINE_CUTOFF = 0
	txn.Commit()
	provers := []*prover{}
	for i := 0; i < 1; i++ {
		provers = append(provers, generateProver())
	}

	joins := []*protobufs.TokenRequest{}
	for i := 0; i < 1; i++ {
		joins = append(joins, provers[i].generateJoin(1))
	}
	app, success, fail, err := app.ApplyTransitions(
		1,
		&protobufs.TokenRequests{
			Requests: joins,
		},
		false,
	)
	assert.NoError(t, err)

	assert.Len(t, success.Requests, 1)
	assert.Len(t, fail.Requests, 0)
	app.Tries = append(app.Tries, &tries.RollingFrecencyCritbitTrie{})
	for _, p := range provers {
		app.Tries[1].Add(p.address, 0)
	}
	txn, _ = app.ClockStore.NewTransaction(false)
	frame1, _ := wprover.ProveDataClockFrame(gen, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame1.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame1, txn)
	app.ClockStore.CommitDataClockFrame(frame1.Filter, 1, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()
	join := &protobufs.AnnounceProverJoin{
		Filter:      bytes.Repeat([]byte{0xff}, 32),
		FrameNumber: 0,
	}
	assert.NoError(t, join.SignED448(provers[0].pubKey, provers[0].privKey.Sign))
	assert.NoError(t, join.Validate())
	_, success, fail, err = app.ApplyTransitions(
		2,
		&protobufs.TokenRequests{
			Requests: []*protobufs.TokenRequest{
				joins[0],
			},
		},
		false,
	)
	// assert.Error(t, err)
	txn, _ = app.ClockStore.NewTransaction(false)
	frame2, _ := wprover.ProveDataClockFrame(frame1, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame2.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame2, txn)
	app.ClockStore.CommitDataClockFrame(frame2.Filter, 2, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	proofTrees := []*merkletree.MerkleTree{}
	reqs := []*protobufs.TokenRequest{}
	for _, prover := range provers {
		proofTree, _, req := prover.generateProof(frame2, wprover, nil, false, false, false)
		proofTrees = append(proofTrees, proofTree)
		reqs = append(reqs, req)
	}
	app, success, _, err = app.ApplyTransitions(3, &protobufs.TokenRequests{
		Requests: reqs,
	}, false)
	assert.NoError(t, err)
	assert.Len(t, success.Requests, 1)
	assert.Len(t, app.TokenOutputs.Outputs, 1)
	txn, _ = app.CoinStore.NewTransaction(false)
	for i, o := range app.TokenOutputs.Outputs {
		switch e := o.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			a, err := token.GetAddressOfCoin(e.Coin, 1, uint64(i))
			assert.NoError(t, err)
			err = app.CoinStore.PutCoin(txn, 1, a, e.Coin)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedCoin:
			c, err := app.CoinStore.GetCoinByAddress(nil, e.DeletedCoin.Address)
			assert.NoError(t, err)
			err = app.CoinStore.DeleteCoin(txn, e.DeletedCoin.Address, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Proof:
			a, err := token.GetAddressOfPreCoinProof(e.Proof)
			fmt.Printf("add addr %x\n", a)
			assert.NoError(t, err)
			err = app.CoinStore.PutPreCoinProof(txn, 1, a, e.Proof)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedProof:
			a, err := token.GetAddressOfPreCoinProof(e.DeletedProof)
			fmt.Printf("del addr %x\n", a)
			assert.NoError(t, err)
			c, err := app.CoinStore.GetPreCoinProofByAddress(a)
			assert.NoError(t, err)
			err = app.CoinStore.DeletePreCoinProof(txn, a, c)
			assert.NoError(t, err)
		}
	}
	err = txn.Commit()
	assert.NoError(t, err)
	txn, _ = app.ClockStore.NewTransaction(false)
	frame3, _ := wprover.ProveDataClockFrame(frame2, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame3.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame3, txn)
	app.ClockStore.CommitDataClockFrame(frame3.Filter, 3, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	for i, prover := range provers {
		proofTree, _, req := prover.generateProof(frame3, wprover, proofTrees[i], false, false, true)
		proofTrees[i] = proofTree
		reqs[i] = req
	}

	app, success, _, err = app.ApplyTransitions(4, &protobufs.TokenRequests{
		Requests: reqs,
	}, false)
	txn, _ = app.CoinStore.NewTransaction(false)
	coins := [][]byte{}
	// gotPenalty := false
	for i, o := range app.TokenOutputs.Outputs {
		switch e := o.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			a, err := token.GetAddressOfCoin(e.Coin, 4, uint64(i))
			assert.NoError(t, err)
			err = app.CoinStore.PutCoin(txn, 4, a, e.Coin)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedCoin:
			c, err := app.CoinStore.GetCoinByAddress(txn, e.DeletedCoin.Address)
			assert.NoError(t, err)
			err = app.CoinStore.DeleteCoin(txn, e.DeletedCoin.Address, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Proof:
			a, err := token.GetAddressOfPreCoinProof(e.Proof)
			fmt.Printf("add addr %x\n", a)
			assert.NoError(t, err)
			err = app.CoinStore.PutPreCoinProof(txn, 4, a, e.Proof)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedProof:
			a, err := token.GetAddressOfPreCoinProof(e.DeletedProof)
			fmt.Printf("del addr %x\n", a)
			assert.NoError(t, err)
			c, err := app.CoinStore.GetPreCoinProofByAddress(a)
			assert.NoError(t, err)
			err = app.CoinStore.DeletePreCoinProof(txn, a, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Penalty:
			// gotPenalty = true
		}
	}
	err = txn.Commit()
	assert.NoError(t, err)
	assert.Len(t, success.Requests, 1)
	assert.Len(t, app.TokenOutputs.Outputs, 2)

	txn, _ = app.ClockStore.NewTransaction(false)
	frame4, _ := wprover.ProveDataClockFrame(frame3, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame4.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame4, txn)
	app.ClockStore.CommitDataClockFrame(frame4.Filter, 4, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	for i, prover := range provers {
		proofTree, _, req := prover.generateProof(frame4, wprover, proofTrees[i], false, false, true)
		proofTrees[i] = proofTree
		reqs[i] = req
	}

	app, success, _, err = app.ApplyTransitions(5, &protobufs.TokenRequests{
		Requests: reqs,
	}, false)
	txn, _ = app.CoinStore.NewTransaction(false)
	// gotPenalty := false
	for i, o := range app.TokenOutputs.Outputs {
		switch e := o.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			a, err := token.GetAddressOfCoin(e.Coin, 5, uint64(i))
			assert.NoError(t, err)
			err = app.CoinStore.PutCoin(txn, 5, a, e.Coin)
			assert.NoError(t, err)
			coins = append(coins, a)
		case *protobufs.TokenOutput_DeletedCoin:
			c, err := app.CoinStore.GetCoinByAddress(txn, e.DeletedCoin.Address)
			assert.NoError(t, err)
			err = app.CoinStore.DeleteCoin(txn, e.DeletedCoin.Address, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Proof:
			a, err := token.GetAddressOfPreCoinProof(e.Proof)
			fmt.Printf("add addr %x\n", a)
			assert.NoError(t, err)
			err = app.CoinStore.PutPreCoinProof(txn, 5, a, e.Proof)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedProof:
			a, err := token.GetAddressOfPreCoinProof(e.DeletedProof)
			fmt.Printf("del addr %x\n", a)
			assert.NoError(t, err)
			c, err := app.CoinStore.GetPreCoinProofByAddress(a)
			assert.NoError(t, err)
			err = app.CoinStore.DeletePreCoinProof(txn, a, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Penalty:
			// gotPenalty = true
		}
	}
	err = txn.Commit()
	assert.NoError(t, err)
	assert.Len(t, success.Requests, 1)
	assert.Len(t, app.TokenOutputs.Outputs, 3)

	txn, _ = app.ClockStore.NewTransaction(false)
	frame5, _ := wprover.ProveDataClockFrame(frame4, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame5.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame5, txn)
	app.ClockStore.CommitDataClockFrame(frame5.Filter, 5, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	reqs = make([]*protobufs.TokenRequest, 1)
	for i, prover := range provers {
		req := prover.generateSplit(coins[i])
		reqs[i] = req
	}

	app, success, _, err = app.ApplyTransitions(6, &protobufs.TokenRequests{
		Requests: reqs,
	}, false)
	assert.NoError(t, err)
	txn, _ = app.CoinStore.NewTransaction(false)
	coins = [][]byte{}
	for i, o := range app.TokenOutputs.Outputs {
		switch e := o.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			a, err := token.GetAddressOfCoin(e.Coin, 5, uint64(i))
			assert.NoError(t, err)
			err = app.CoinStore.PutCoin(txn, 5, a, e.Coin)
			assert.NoError(t, err)
			coins = append(coins, a)
		case *protobufs.TokenOutput_DeletedCoin:
			c, err := app.CoinStore.GetCoinByAddress(txn, e.DeletedCoin.Address)
			assert.NoError(t, err)
			err = app.CoinStore.DeleteCoin(txn, e.DeletedCoin.Address, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Proof:
			a, err := token.GetAddressOfPreCoinProof(e.Proof)
			assert.NoError(t, err)
			err = app.CoinStore.PutPreCoinProof(txn, 1, a, e.Proof)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedProof:
			a, err := token.GetAddressOfPreCoinProof(e.DeletedProof)
			assert.NoError(t, err)
			c, err := app.CoinStore.GetPreCoinProofByAddress(a)
			assert.NoError(t, err)
			err = app.CoinStore.DeletePreCoinProof(txn, a, c)
			assert.NoError(t, err)
		}
	}
	err = txn.Commit()
	assert.NoError(t, err)
	assert.Len(t, success.Requests, 1)
	assert.Len(t, app.TokenOutputs.Outputs, 3)
	txn, _ = app.ClockStore.NewTransaction(false)
	frame6, _ := wprover.ProveDataClockFrame(frame5, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame6.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame6, txn)
	app.ClockStore.CommitDataClockFrame(frame6.Filter, 6, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	// for i, prover := range provers {
	// 	req := prover.generateMerge(coins[i*2 : i*2+2])
	// 	reqs[i] = req
	// }
	// n = time.Now()
	// app, success, _, err = app.ApplyTransitions(6, &protobufs.TokenRequests{
	// 	Requests: reqs,
	// }, false)
	// txn, _ = app.CoinStore.NewTransaction(false)
	// coins = [][]byte{}
	// for i, o := range app.TokenOutputs.Outputs {
	// 	switch e := o.Output.(type) {
	// 	case *protobufs.TokenOutput_Coin:
	// 		a, err := token.GetAddressOfCoin(e.Coin, 6, uint64(i))
	// 		assert.NoError(t, err)
	// 		err = app.CoinStore.PutCoin(txn, 1, a, e.Coin)
	// 		assert.NoError(t, err)
	// 		coins = append(coins, a)
	// 	case *protobufs.TokenOutput_DeletedCoin:
	// 		c, err := app.CoinStore.GetCoinByAddress(txn, e.DeletedCoin.Address)
	// 		assert.NoError(t, err)
	// 		err = app.CoinStore.DeleteCoin(txn, e.DeletedCoin.Address, c)
	// 		assert.NoError(t, err)
	// 	case *protobufs.TokenOutput_Proof:
	// 		a, err := token.GetAddressOfPreCoinProof(e.Proof)
	// 		assert.NoError(t, err)
	// 		err = app.CoinStore.PutPreCoinProof(txn, 1, a, e.Proof)
	// 		assert.NoError(t, err)
	// 	case *protobufs.TokenOutput_DeletedProof:
	// 		a, err := token.GetAddressOfPreCoinProof(e.DeletedProof)
	// 		assert.NoError(t, err)
	// 		c, err := app.CoinStore.GetPreCoinProofByAddress(a)
	// 		assert.NoError(t, err)
	// 		err = app.CoinStore.DeletePreCoinProof(txn, a, c)
	// 		assert.NoError(t, err)
	// 	}
	// }
	// err = txn.Commit()
	// assert.NoError(t, err)
	// assert.Len(t, success.Requests, 10)
	// assert.Len(t, app.TokenOutputs.Outputs, 30)
}
