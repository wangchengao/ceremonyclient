package token

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	gotime "time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	qruntime "source.quilibrium.com/quilibrium/monorepo/node/internal/runtime"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type PeerSeniorityItem struct {
	seniority uint64
	addr      string
}

func NewPeerSeniorityItem(seniority uint64, addr string) PeerSeniorityItem {
	return PeerSeniorityItem{
		seniority: seniority,
		addr:      addr,
	}
}

func (p PeerSeniorityItem) GetSeniority() uint64 {
	return p.seniority
}

func (p PeerSeniorityItem) GetAddr() string {
	return p.addr
}

type PeerSeniority map[string]PeerSeniorityItem

func NewFromMap(m map[string]uint64) *PeerSeniority {
	s := &PeerSeniority{}
	for k, v := range m {
		(*s)[k] = PeerSeniorityItem{
			seniority: v,
			addr:      k,
		}
	}
	return s
}

func ToSerializedMap(m *PeerSeniority) map[string]uint64 {
	s := map[string]uint64{}
	for k, v := range *m {
		s[k] = v.seniority
	}
	return s
}

func (p PeerSeniorityItem) Priority() uint64 {
	return p.seniority
}

type TokenExecutionEngine struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	wg                    sync.WaitGroup
	logger                *zap.Logger
	clock                 *data.DataClockConsensusEngine
	clockStore            store.ClockStore
	coinStore             store.CoinStore
	keyStore              store.KeyStore
	keyManager            keys.KeyManager
	engineConfig          *config.EngineConfig
	pubSub                p2p.PubSub
	peerIdHash            []byte
	provingKey            crypto.Signer
	proverPublicKey       []byte
	provingKeyAddress     []byte
	inclusionProver       qcrypto.InclusionProver
	participantMx         sync.Mutex
	peerChannels          map[string]*p2p.PublicP2PChannel
	activeClockFrame      *protobufs.ClockFrame
	alreadyPublishedShare bool
	intrinsicFilter       []byte
	frameProver           qcrypto.FrameProver
	peerSeniority         *PeerSeniority
}

func NewTokenExecutionEngine(
	logger *zap.Logger,
	cfg *config.Config,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	clockStore store.ClockStore,
	dataProofStore store.DataProofStore,
	coinStore store.CoinStore,
	masterTimeReel *time.MasterTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	keyStore store.KeyStore,
	report *protobufs.SelfTestReport,
) *TokenExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	seed, err := hex.DecodeString(cfg.Engine.GenesisSeed)
	if err != nil {
		panic(err)
	}

	intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

	_, _, err = clockStore.GetDataClockFrame(intrinsicFilter, 0, false)
	var origin []byte
	var inclusionProof *qcrypto.InclusionAggregateProof
	var proverKeys [][]byte
	var peerSeniority map[string]uint64

	if err != nil && errors.Is(err, store.ErrNotFound) {
		origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
			logger,
			cfg.Engine,
			nil,
			inclusionProver,
			clockStore,
			coinStore,
			uint(cfg.P2P.Network),
		)
		if err := coinStore.SetMigrationVersion(
			config.GetGenesis().GenesisSeedHex,
		); err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	} else {
		err := coinStore.Migrate(
			intrinsicFilter,
			config.GetGenesis().GenesisSeedHex,
		)
		if err != nil {
			panic(err)
		}
		_, err = clockStore.GetEarliestDataClockFrame(intrinsicFilter)
		if err != nil && errors.Is(err, store.ErrNotFound) {
			origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
				logger,
				cfg.Engine,
				nil,
				inclusionProver,
				clockStore,
				coinStore,
				uint(cfg.P2P.Network),
			)
		}
	}

	if len(peerSeniority) == 0 {
		peerSeniority, err = clockStore.GetPeerSeniorityMap(intrinsicFilter)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			panic(err)
		}

		if len(peerSeniority) == 0 {
			peerSeniority, err = RebuildPeerSeniority(uint(cfg.P2P.Network))
			if err != nil {
				panic(err)
			}

			txn, err := clockStore.NewTransaction(false)
			if err != nil {
				panic(err)
			}

			err = clockStore.PutPeerSeniorityMap(txn, intrinsicFilter, peerSeniority)
			if err != nil {
				txn.Abort()
				panic(err)
			}

			if err = txn.Commit(); err != nil {
				txn.Abort()
				panic(err)
			}
		}
	} else {
		LoadAggregatedSeniorityMap(uint(cfg.P2P.Network))
	}

	ctx, cancel := context.WithCancel(context.Background())
	e := &TokenExecutionEngine{
		ctx:                   ctx,
		cancel:                cancel,
		logger:                logger,
		engineConfig:          cfg.Engine,
		keyManager:            keyManager,
		clockStore:            clockStore,
		coinStore:             coinStore,
		keyStore:              keyStore,
		pubSub:                pubSub,
		inclusionProver:       inclusionProver,
		frameProver:           frameProver,
		participantMx:         sync.Mutex{},
		peerChannels:          map[string]*p2p.PublicP2PChannel{},
		alreadyPublishedShare: false,
		intrinsicFilter:       intrinsicFilter,
		peerSeniority:         NewFromMap(peerSeniority),
	}

	alwaysSend := false
	if bytes.Equal(config.GetGenesis().Beacon, pubSub.GetPublicKey()) {
		alwaysSend = true
	}

	restore := func() []*tries.RollingFrecencyCritbitTrie {
		frame, _, err := clockStore.GetLatestDataClockFrame(intrinsicFilter)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			panic(err)
		}

		tries := []*tries.RollingFrecencyCritbitTrie{
			&tries.RollingFrecencyCritbitTrie{},
		}
		proverKeys = [][]byte{config.GetGenesis().Beacon}
		for _, key := range proverKeys {
			addr, _ := poseidon.HashBytes(key)
			tries[0].Add(addr.FillBytes(make([]byte, 32)), 0)
			if err = clockStore.SetProverTriesForFrame(frame, tries); err != nil {
				panic(err)
			}
		}
		peerSeniority, err = RebuildPeerSeniority(uint(cfg.P2P.Network))
		if err != nil {
			panic(err)
		}

		txn, err := clockStore.NewTransaction(false)
		if err != nil {
			panic(err)
		}

		err = clockStore.PutPeerSeniorityMap(txn, intrinsicFilter, peerSeniority)
		if err != nil {
			txn.Abort()
			panic(err)
		}

		if err = txn.Commit(); err != nil {
			txn.Abort()
			panic(err)
		}

		return tries
	}

	dataTimeReel := time.NewDataTimeReel(
		intrinsicFilter,
		logger,
		clockStore,
		cfg.Engine,
		frameProver,
		func(
			txn store.Transaction,
			frame *protobufs.ClockFrame,
			triesAtFrame []*tries.RollingFrecencyCritbitTrie,
		) (
			[]*tries.RollingFrecencyCritbitTrie,
			error,
		) {
			if e.engineConfig.FullProver {
				if err := e.VerifyExecution(frame, triesAtFrame); err != nil {
					return nil, err
				}
			}
			var tries []*tries.RollingFrecencyCritbitTrie
			if tries, err = e.ProcessFrame(txn, frame, triesAtFrame); err != nil {
				return nil, err
			}

			return tries, nil
		},
		origin,
		inclusionProof,
		proverKeys,
		alwaysSend,
		restore,
	)

	e.clock = data.NewDataClockConsensusEngine(
		cfg,
		logger,
		keyManager,
		clockStore,
		coinStore,
		dataProofStore,
		keyStore,
		pubSub,
		frameProver,
		inclusionProver,
		masterTimeReel,
		dataTimeReel,
		peerInfoManager,
		report,
		intrinsicFilter,
		seed,
	)

	peerId := e.pubSub.GetPeerID()
	addr, err := poseidon.HashBytes(peerId)
	if err != nil {
		panic(err)
	}

	addrBytes := addr.FillBytes(make([]byte, 32))
	e.peerIdHash = addrBytes
	provingKey, _, publicKeyBytes, provingKeyAddress := e.clock.GetProvingKey(
		cfg.Engine,
	)
	e.provingKey = provingKey
	e.proverPublicKey = publicKeyBytes
	e.provingKeyAddress = provingKeyAddress

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		f, tries, err := e.clockStore.GetLatestDataClockFrame(e.intrinsicFilter)
		if err != nil {
			return
		}

		shouldResume := false
		for _, trie := range tries[1:] {
			altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
			if err != nil {
				break
			}

			if trie.Contains(altAddr.FillBytes(make([]byte, 32))) {
				shouldResume = true
				break
			}
		}

		if shouldResume {
			resume := &protobufs.AnnounceProverResume{
				Filter:      e.intrinsicFilter,
				FrameNumber: f.FrameNumber,
			}
			if err := resume.SignED448(e.pubSub.GetPublicKey(), e.pubSub.SignMessage); err != nil {
				panic(err)
			}
			if err := resume.Validate(); err != nil {
				panic(err)
			}

			// need to wait for peering
		waitPeers:
			for {
				select {
				case <-e.ctx.Done():
					return
				case <-gotime.After(30 * gotime.Second):
					peerMap := e.pubSub.GetBitmaskPeers()
					if peers, ok := peerMap[string(
						append([]byte{0x00}, e.intrinsicFilter...),
					)]; ok {
						if len(peers) >= 3 {
							break waitPeers
						}
					}
				}
			}
			if err := e.publishMessage(
				append([]byte{0x00}, e.intrinsicFilter...),
				resume.TokenRequest(),
			); err != nil {
				e.logger.Warn("error while publishing resume message", zap.Error(err))
			}
		}
	}()

	return e
}

var _ execution.ExecutionEngine = (*TokenExecutionEngine)(nil)

// GetName implements ExecutionEngine
func (*TokenExecutionEngine) GetName() string {
	return "Token"
}

// GetSupportedApplications implements ExecutionEngine
func (
	*TokenExecutionEngine,
) GetSupportedApplications() []*protobufs.Application {
	return []*protobufs.Application{
		{
			Address:          application.TOKEN_ADDRESS,
			ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		},
	}
}

// Start implements ExecutionEngine
func (e *TokenExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	go func() {
		err := <-e.clock.Start()
		if err != nil {
			panic(err)
		}

		err = <-e.clock.RegisterExecutor(e, 0)
		if err != nil {
			panic(err)
		}

		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (e *TokenExecutionEngine) Stop(force bool) <-chan error {
	e.cancel()
	e.wg.Wait()

	errChan := make(chan error)

	go func() {
		errChan <- <-e.clock.Stop(force)
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *TokenExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	if bytes.Equal(address, e.GetSupportedApplications()[0].Address) {
		a := &anypb.Any{}
		if err := proto.Unmarshal(message.Payload, a); err != nil {
			return nil, errors.Wrap(err, "process message")
		}

		e.logger.Debug(
			"processing execution message",
			zap.String("type", a.TypeUrl),
		)

		switch a.TypeUrl {
		case protobufs.TokenRequestType:
			if e.clock.FrameProverTriesContains(e.provingKeyAddress) {
				payload, err := proto.Marshal(a)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				h, err := poseidon.HashBytes(payload)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				msg := &protobufs.Message{
					Hash:    h.Bytes(),
					Address: application.TOKEN_ADDRESS,
					Payload: payload,
				}
				return []*protobufs.Message{
					msg,
				}, nil
			}
		}
	}

	return nil, nil
}

func (e *TokenExecutionEngine) ProcessFrame(
	txn store.Transaction,
	frame *protobufs.ClockFrame,
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
) ([]*tries.RollingFrecencyCritbitTrie, error) {
	f, err := e.coinStore.GetLatestFrameProcessed()
	if err != nil || f == frame.FrameNumber {
		return nil, errors.Wrap(err, "process frame")
	}

	e.activeClockFrame = frame
	e.logger.Info(
		"evaluating next frame",
		zap.Uint64(
			"frame_number",
			frame.FrameNumber,
		),
		zap.Duration("frame_age", frametime.Since(frame)),
	)
	app, err := application.MaterializeApplicationFromFrame(
		e.provingKey,
		frame,
		triesAtFrame,
		e.coinStore,
		e.clockStore,
		e.pubSub,
		e.logger,
		e.frameProver,
	)
	if err != nil {
		e.logger.Error(
			"error while materializing application from frame",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "process frame")
	}

	e.logger.Debug(
		"app outputs",
		zap.Int("outputs", len(app.TokenOutputs.Outputs)),
	)

	proverTrieJoinRequests := [][]byte{}
	proverTrieLeaveRequests := [][]byte{}
	mapSnapshot := ToSerializedMap(e.peerSeniority)
	activeMap := NewFromMap(mapSnapshot)

	outputAddresses := make([][]byte, len(app.TokenOutputs.Outputs))
	outputAddressErrors := make([]error, len(app.TokenOutputs.Outputs))
	wg := sync.WaitGroup{}
	throttle := make(chan struct{}, qruntime.WorkerCount(0, false))
	for i, output := range app.TokenOutputs.Outputs {
		throttle <- struct{}{}
		wg.Add(1)
		go func(i int, output *protobufs.TokenOutput) {
			defer func() { <-throttle }()
			defer wg.Done()
			switch o := output.Output.(type) {
			case *protobufs.TokenOutput_Coin:
				outputAddresses[i], outputAddressErrors[i] = GetAddressOfCoin(o.Coin, frame.FrameNumber, uint64(i))
			case *protobufs.TokenOutput_Proof:
				outputAddresses[i], outputAddressErrors[i] = GetAddressOfPreCoinProof(o.Proof)
			case *protobufs.TokenOutput_DeletedProof:
				outputAddresses[i], outputAddressErrors[i] = GetAddressOfPreCoinProof(o.DeletedProof)
			}
		}(i, output)
	}
	wg.Wait()

	for i, output := range app.TokenOutputs.Outputs {
		switch o := output.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			address, err := outputAddresses[i], outputAddressErrors[i]
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutCoin(
				txn,
				frame.FrameNumber,
				address,
				o.Coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_DeletedCoin:
			coin, err := e.coinStore.GetCoinByAddress(nil, o.DeletedCoin.Address)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeleteCoin(
				txn,
				o.DeletedCoin.Address,
				coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Proof:
			address, err := outputAddresses[i], outputAddressErrors[i]
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutPreCoinProof(
				txn,
				frame.FrameNumber,
				address,
				o.Proof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			if len(o.Proof.Amount) == 32 &&
				!bytes.Equal(o.Proof.Amount, make([]byte, 32)) &&
				o.Proof.Commitment != nil {
				addr := string(o.Proof.Owner.GetImplicitAccount().Address)
				for _, t := range app.Tries {
					if t.Contains([]byte(addr)) {
						t.Add([]byte(addr), frame.FrameNumber)
						break
					}
				}
				if _, ok := (*activeMap)[addr]; !ok {
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: 10,
						addr:      addr,
					}
				} else {
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: (*activeMap)[addr].seniority + 10,
						addr:      addr,
					}
				}
			}
		case *protobufs.TokenOutput_DeletedProof:
			address, err := outputAddresses[i], outputAddressErrors[i]
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeletePreCoinProof(
				txn,
				address,
				o.DeletedProof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Announce:
			peerIds := []string{}
			for _, sig := range o.Announce.PublicKeySignaturesEd448 {
				peerId, err := e.getPeerIdFromSignature(sig)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				peerIds = append(peerIds, peerId.String())
			}

			logger := e.logger.Debug
			if peerIds[0] == peer.ID(e.pubSub.GetPeerID()).String() {
				logger = e.logger.Info
			}
			mergeable := true
			for i, peerId := range peerIds {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[i],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				sen, ok := (*activeMap)[string(addr)]
				if !ok {
					logger(
						"peer announced with no seniority",
						zap.String("peer_id", peerId),
					)
					continue
				}

				peer := new(big.Int).SetUint64(sen.seniority)
				if peer.Cmp(GetAggregatedSeniority([]string{peerId})) != 0 {
					logger(
						"peer announced but has already been announced",
						zap.String("peer_id", peerId),
						zap.Uint64("seniority", sen.seniority),
					)
					mergeable = false
					break
				}
			}

			if mergeable {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				additional := uint64(0)
				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				aggregated := GetAggregatedSeniority(peerIds).Uint64()
				logger("peer has merge, aggregated seniority", zap.Uint64("seniority", aggregated))

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
						logger("1.4.19-21 seniority", zap.Uint64("seniority", additional))
					}
				}

				total := aggregated + additional

				logger("combined aggregate and 1.4.19-21 seniority", zap.Uint64("seniority", total))

				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: aggregated + additional,
					addr:      string(addr),
				}

				for _, sig := range o.Announce.PublicKeySignaturesEd448[1:] {
					addr, err := e.getAddressFromSignature(
						sig,
					)
					if err != nil {
						txn.Abort()
						return nil, errors.Wrap(err, "process frame")
					}

					(*activeMap)[string(addr)] = PeerSeniorityItem{
						seniority: 0,
						addr:      string(addr),
					}
				}
			} else {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				sen, ok := (*activeMap)[string(addr)]
				if !ok {
					logger(
						"peer announced with no seniority",
						zap.String("peer_id", peerIds[0]),
					)
					continue
				}

				peer := new(big.Int).SetUint64(sen.seniority)
				if peer.Cmp(GetAggregatedSeniority([]string{peerIds[0]})) != 0 {
					logger(
						"peer announced but has already been announced",
						zap.String("peer_id", peerIds[0]),
						zap.Uint64("seniority", sen.seniority),
					)
					continue
				}

				additional := uint64(0)
				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				aggregated := GetAggregatedSeniority(peerIds).Uint64()
				logger("peer does not have merge, pre-1.4.19 seniority", zap.Uint64("seniority", aggregated))

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
						logger("1.4.19-21 seniority", zap.Uint64("seniority", additional))
					}
				}
				total := GetAggregatedSeniority([]string{peerIds[0]}).Uint64() + additional
				logger("combined aggregate and 1.4.19-21 seniority", zap.Uint64("seniority", total))
				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: total,
					addr:      string(addr),
				}
			}
		case *protobufs.TokenOutput_Join:
			addr, err := e.getAddressFromSignature(o.Join.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}

			if _, ok := (*activeMap)[string(addr)]; !ok {
				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: 20,
					addr:      string(addr),
				}
			} else {
				(*activeMap)[string(addr)] = PeerSeniorityItem{
					seniority: (*activeMap)[string(addr)].seniority + 20,
					addr:      string(addr),
				}
			}
			proverTrieJoinRequests = append(proverTrieJoinRequests, addr)
		case *protobufs.TokenOutput_Leave:
			addr, err := e.getAddressFromSignature(o.Leave.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			proverTrieLeaveRequests = append(proverTrieLeaveRequests, addr)
		case *protobufs.TokenOutput_Pause:
			_, err := e.getAddressFromSignature(o.Pause.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Resume:
			_, err := e.getAddressFromSignature(o.Resume.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Penalty:
			addr := string(o.Penalty.Account.GetImplicitAccount().Address)
			if _, ok := (*activeMap)[addr]; !ok {
				(*activeMap)[addr] = PeerSeniorityItem{
					seniority: 0,
					addr:      addr,
				}
				proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
			} else {
				if (*activeMap)[addr].seniority > o.Penalty.Quantity {
					for _, t := range app.Tries {
						if t.Contains([]byte(addr)) {
							v := t.Get([]byte(addr))
							latest := v.LatestFrame
							if frame.FrameNumber-latest > 100 {
								proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
							}
							break
						}
					}
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: (*activeMap)[addr].seniority - o.Penalty.Quantity,
						addr:      addr,
					}
				} else {
					(*activeMap)[addr] = PeerSeniorityItem{
						seniority: 0,
						addr:      addr,
					}
					proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
				}
			}
		}
	}

	joinAddrs := tries.NewMinHeap[PeerSeniorityItem]()
	leaveAddrs := tries.NewMinHeap[PeerSeniorityItem]()
	for _, addr := range proverTrieJoinRequests {
		if _, ok := (*activeMap)[string(addr)]; !ok {
			joinAddrs.Push(PeerSeniorityItem{
				addr:      string(addr),
				seniority: 0,
			})
		} else {
			joinAddrs.Push((*activeMap)[string(addr)])
		}
	}
	for _, addr := range proverTrieLeaveRequests {
		if _, ok := (*activeMap)[string(addr)]; !ok {
			leaveAddrs.Push(PeerSeniorityItem{
				addr:      string(addr),
				seniority: 0,
			})
		} else {
			leaveAddrs.Push((*activeMap)[string(addr)])
		}
	}

	joinReqs := make([]PeerSeniorityItem, len(joinAddrs.All()))
	copy(joinReqs, joinAddrs.All())
	slices.Reverse(joinReqs)
	leaveReqs := make([]PeerSeniorityItem, len(leaveAddrs.All()))
	copy(leaveReqs, leaveAddrs.All())
	slices.Reverse(leaveReqs)

	ProcessJoinsAndLeaves(joinReqs, leaveReqs, app, e.peerSeniority, frame)

	if frame.FrameNumber == application.PROOF_FRAME_SENIORITY_REPAIR {
		e.performSeniorityMapRepair(activeMap, frame)
	}

	err = e.clockStore.PutPeerSeniorityMap(
		txn,
		e.intrinsicFilter,
		ToSerializedMap(activeMap),
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	err = e.coinStore.SetLatestFrameProcessed(txn, frame.FrameNumber)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	e.peerSeniority = activeMap

	if frame.FrameNumber == application.PROOF_FRAME_RING_RESET ||
		frame.FrameNumber == application.PROOF_FRAME_RING_RESET_2 {
		e.logger.Info("performing ring reset")
		seniorityMap, err := RebuildPeerSeniority(e.pubSub.GetNetwork())
		if err != nil {
			return nil, errors.Wrap(err, "process frame")
		}
		e.peerSeniority = NewFromMap(seniorityMap)

		app.Tries = []*tries.RollingFrecencyCritbitTrie{
			app.Tries[0],
		}

		err = e.clockStore.PutPeerSeniorityMap(
			txn,
			e.intrinsicFilter,
			ToSerializedMap(e.peerSeniority),
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "process frame")
		}
	}

	return app.Tries, nil
}

func (e *TokenExecutionEngine) performSeniorityMapRepair(
	activeMap *PeerSeniority,
	frame *protobufs.ClockFrame,
) {
	if e.pubSub.GetNetwork() != 0 {
		return
	}

	e.logger.Info(
		"repairing seniority map from historic data, this may take a while",
	)

	RebuildPeerSeniority(0)
	for f := uint64(application.PROOF_FRAME_RING_RESET_2); f < frame.FrameNumber; f++ {
		frame, _, err := e.clockStore.GetDataClockFrame(e.intrinsicFilter, f, false)
		if err != nil {
			break
		}

		reqs, _, _ := application.GetOutputsFromClockFrame(frame)

		for _, req := range reqs.Requests {
			switch t := req.Request.(type) {
			case *protobufs.TokenRequest_Join:
				if t.Join.Announce != nil && len(
					t.Join.Announce.PublicKeySignaturesEd448,
				) > 0 {
					addr, err := e.getAddressFromSignature(
						t.Join.Announce.PublicKeySignaturesEd448[0],
					)
					if err != nil {
						continue
					}

					peerId, err := e.getPeerIdFromSignature(
						t.Join.Announce.PublicKeySignaturesEd448[0],
					)
					if err != nil {
						continue
					}

					additional := uint64(0)

					_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
					for _, pr := range prfs {
						if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
							// approximate average per interval:
							add := new(big.Int).SetBytes(pr.Amount)
							add.Quo(add, big.NewInt(58800000))
							if add.Cmp(big.NewInt(4000000)) > 0 {
								add = big.NewInt(4000000)
							}
							additional = add.Uint64()
						}
					}

					if err != nil && !errors.Is(err, store.ErrNotFound) {
						continue
					}
					peerIds := []string{peerId.String()}
					if len(t.Join.Announce.PublicKeySignaturesEd448) > 1 {
						for _, announce := range t.Join.Announce.PublicKeySignaturesEd448[1:] {
							peerId, err := e.getPeerIdFromSignature(
								announce,
							)
							if err != nil {
								continue
							}

							peerIds = append(peerIds, peerId.String())
						}
					}

					aggregated := GetAggregatedSeniority(peerIds).Uint64()
					total := aggregated + additional
					sen, ok := (*activeMap)[string(addr)]

					if !ok || sen.seniority < total {
						(*activeMap)[string(addr)] = PeerSeniorityItem{
							seniority: total,
							addr:      string(addr),
						}
					}
				}
			}
		}
	}
}

func ProcessJoinsAndLeaves(
	joinReqs []PeerSeniorityItem,
	leaveReqs []PeerSeniorityItem,
	app *application.TokenApplication,
	seniority *PeerSeniority,
	frame *protobufs.ClockFrame,
) {
	for _, addr := range joinReqs {
		rings := len(app.Tries)
		last := app.Tries[rings-1]
		set := last.FindNearestAndApproximateNeighbors(make([]byte, 32))
		if len(set) == 2048 || rings == 1 {
			app.Tries = append(
				app.Tries,
				&tries.RollingFrecencyCritbitTrie{},
			)
			last = app.Tries[rings]
		}
		if !last.Contains([]byte(addr.addr)) {
			last.Add([]byte(addr.addr), frame.FrameNumber)
		}
	}
	for _, addr := range leaveReqs {
		for _, t := range app.Tries[1:] {
			if t.Contains([]byte(addr.addr)) {
				t.Remove([]byte(addr.addr))
				break
			}
		}
	}

	if frame.FrameNumber > application.PROOF_FRAME_RING_RESET {
		if len(app.Tries) >= 2 {
			for _, t := range app.Tries[1:] {
				nodes := t.FindNearestAndApproximateNeighbors(make([]byte, 32))
				for _, n := range nodes {
					if frame.FrameNumber >= application.PROOF_FRAME_COMBINE_CUTOFF {
						if n.LatestFrame < frame.FrameNumber-100 {
							t.Remove(n.Key)
						}
					} else {
						if n.LatestFrame < frame.FrameNumber-1000 {
							t.Remove(n.Key)
						}
					}
				}
			}
		}
	}

	if len(app.Tries) > 2 {
		for i, t := range app.Tries[2:] {
			setSize := len(app.Tries[1+i].FindNearestAndApproximateNeighbors(make([]byte, 32)))
			if setSize < 2048 {
				nextSet := t.FindNearestAndApproximateNeighbors(make([]byte, 32))
				eligibilityOrder := tries.NewMinHeap[PeerSeniorityItem]()
				for _, n := range nextSet {
					eligibilityOrder.Push((*seniority)[string(n.Key)])
				}
				process := eligibilityOrder.All()
				slices.Reverse(process)
				for s := 0; s < len(process) && s+setSize < 2048; s++ {
					app.Tries[1+i].Add([]byte(process[s].addr), frame.FrameNumber)
					app.Tries[2+i].Remove([]byte(process[s].addr))
				}
			}
		}
	}
}

func (e *TokenExecutionEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	a := &anypb.Any{}
	if err := a.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	a.TypeUrl = strings.Replace(
		a.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: application.TOKEN_ADDRESS,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *TokenExecutionEngine) VerifyExecution(
	frame *protobufs.ClockFrame,
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
) error {
	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					transition, _, err := application.GetOutputsFromClockFrame(frame)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					parent, tries, err := e.clockStore.GetDataClockFrame(
						p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
						frame.FrameNumber-1,
						false,
					)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return errors.Wrap(err, "verify execution")
					}

					if parent == nil && frame.FrameNumber != 0 {
						return errors.Wrap(
							errors.New("missing parent frame"),
							"verify execution",
						)
					}

					a, err := application.MaterializeApplicationFromFrame(
						e.provingKey,
						parent,
						tries,
						e.coinStore,
						e.clockStore,
						e.pubSub,
						e.logger,
						e.frameProver,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a, _, _, err = a.ApplyTransitions(
						frame.FrameNumber,
						transition,
						false,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a2, err := application.MaterializeApplicationFromFrame(
						e.provingKey,
						frame,
						triesAtFrame,
						e.coinStore,
						e.clockStore,
						e.pubSub,
						e.logger,
						e.frameProver,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					if len(a.TokenOutputs.Outputs) != len(a2.TokenOutputs.Outputs) {
						return errors.Wrap(
							errors.New("mismatched outputs"),
							"verify execution",
						)
					}

					for i := range a.TokenOutputs.Outputs {
						o1 := a.TokenOutputs.Outputs[i]
						o2 := a2.TokenOutputs.Outputs[i]
						if !proto.Equal(o1, o2) {
							return errors.Wrap(
								errors.New("mismatched messages"),
								"verify execution",
							)
						}
					}

					return nil
				}
			}
		}
	}

	return nil
}

func (e *TokenExecutionEngine) GetPeerInfo() *protobufs.PeerInfoResponse {
	return e.clock.GetPeerInfo()
}

func (e *TokenExecutionEngine) GetFrame() *protobufs.ClockFrame {
	return e.clock.GetFrame()
}

func (e *TokenExecutionEngine) GetSeniority() *big.Int {
	altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		return nil
	}

	sen, ok := (*e.peerSeniority)[string(
		altAddr.FillBytes(make([]byte, 32)),
	)]

	if !ok {
		return big.NewInt(0)
	}

	return new(big.Int).SetUint64(sen.Priority())
}

func GetAggregatedSeniority(peerIds []string) *big.Int {
	highestFirst := uint64(0)
	highestSecond := uint64(0)
	highestThird := uint64(0)
	highestFourth := uint64(0)

	for _, f := range firstRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}
		// these don't have decimals so we can shortcut
		max := 157208
		actual, err := strconv.Atoi(f.Reward)
		if err != nil {
			panic(err)
		}

		s := uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
		if s > uint64(highestFirst) {
			highestFirst = s
		}
	}

	for _, f := range secondRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		amt := uint64(0)
		if f.JanPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.FebPresence {
			amt += (10 * 6 * 60 * 24 * 29)
		}

		if f.MarPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.AprPresence {
			amt += (10 * 6 * 60 * 24 * 30)
		}

		if f.MayPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if amt > uint64(highestSecond) {
			highestSecond = amt
		}
	}

	for _, f := range thirdRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 30)
		if s > uint64(highestThird) {
			highestThird = s
		}
	}

	for _, f := range fourthRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 31)
		if s > uint64(highestFourth) {
			highestFourth = s
		}
	}
	return new(big.Int).SetUint64(
		highestFirst + highestSecond + highestThird + highestFourth,
	)
}

func (e *TokenExecutionEngine) AnnounceProverMerge() *protobufs.AnnounceProverRequest {
	currentHead := e.GetFrame()
	if currentHead == nil ||
		currentHead.FrameNumber < application.PROOF_FRAME_CUTOFF {
		return nil
	}

	var helpers []protobufs.ED448SignHelper = []protobufs.ED448SignHelper{
		{
			PublicKey: e.pubSub.GetPublicKey(),
			Sign:      e.pubSub.SignMessage,
		},
	}

	if len(e.engineConfig.MultisigProverEnrollmentPaths) != 0 &&
		e.GetSeniority().Cmp(GetAggregatedSeniority(
			[]string{peer.ID(e.pubSub.GetPeerID()).String()},
		)) == 0 {
		for _, conf := range e.engineConfig.MultisigProverEnrollmentPaths {
			extraConf, err := config.LoadConfig(conf, "", false)
			if err != nil {
				panic(err)
			}

			peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
			if err != nil {
				panic(errors.Wrap(err, "error unmarshaling peerkey"))
			}

			privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
			if err != nil {
				panic(errors.Wrap(err, "error unmarshaling peerkey"))
			}

			pub := privKey.GetPublic()
			pubBytes, err := pub.Raw()
			if err != nil {
				panic(errors.Wrap(err, "error unmarshaling peerkey"))
			}

			helpers = append(helpers, protobufs.ED448SignHelper{
				PublicKey: pubBytes,
				Sign:      privKey.Sign,
			})
		}
	}

	announce := &protobufs.AnnounceProverRequest{}
	if err := announce.SignED448(helpers); err != nil {
		panic(err)
	}
	if err := announce.Validate(); err != nil {
		panic(err)
	}

	return announce
}

func (e *TokenExecutionEngine) AnnounceProverJoin() {
	head := e.GetFrame()
	if head == nil ||
		head.FrameNumber < application.PROOF_FRAME_CUTOFF {
		return
	}

	join := &protobufs.AnnounceProverJoin{
		Filter:      bytes.Repeat([]byte{0xff}, 32),
		FrameNumber: head.FrameNumber,
		Announce:    e.AnnounceProverMerge(),
	}
	if err := join.SignED448(e.pubSub.GetPublicKey(), e.pubSub.SignMessage); err != nil {
		panic(err)
	}
	if err := join.Validate(); err != nil {
		panic(err)
	}

	if err := e.publishMessage(
		append([]byte{0x00}, e.intrinsicFilter...),
		join.TokenRequest(),
	); err != nil {
		e.logger.Warn("error publishing join message", zap.Error(err))
	}
}

func (e *TokenExecutionEngine) GetRingPosition() int {
	altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		return -1
	}

	tries := e.clock.GetFrameProverTries()
	if len(tries) <= 1 {
		return -1
	}

	for i, trie := range tries[1:] {
		if trie.Contains(altAddr.FillBytes(make([]byte, 32))) {
			return i
		}
	}

	return -1
}

func (e *TokenExecutionEngine) getPeerIdFromSignature(
	sig *protobufs.Ed448Signature,
) (peer.ID, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return "", errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return "", errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return "", errors.Wrap(err, "get address from signature")
	}

	return peerId, nil
}

func (e *TokenExecutionEngine) getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	return altAddr.FillBytes(make([]byte, 32)), nil
}

func (e *TokenExecutionEngine) GetWorkerCount() uint32 {
	return e.clock.GetWorkerCount()
}
