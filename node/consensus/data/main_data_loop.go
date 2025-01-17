package data

import (
	"bytes"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	mt "github.com/txaty/go-merkletree"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/cas"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (
	e *DataClockConsensusEngine,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	frameProverTries := make(
		[]*tries.RollingFrecencyCritbitTrie,
		len(e.frameProverTries),
	)

	for i, trie := range e.frameProverTries {
		newTrie := &tries.RollingFrecencyCritbitTrie{}
		b, err := trie.Serialize()
		if err != nil {
			panic(err)
		}

		err = newTrie.Deserialize(b)
		if err != nil {
			panic(err)
		}
		frameProverTries[i] = newTrie
	}

	e.frameProverTriesMx.RUnlock()
	return frameProverTries
}

func (e *DataClockConsensusEngine) GetFrameProverTrie(i int) *tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	defer e.frameProverTriesMx.RUnlock()
	newTrie := &tries.RollingFrecencyCritbitTrie{}
	if i < 0 || i >= len(e.frameProverTries) {
		return newTrie
	}
	b, err := e.frameProverTries[i].Serialize()
	if err != nil {
		panic(err)
	}
	if err := newTrie.Deserialize(b); err != nil {
		panic(err)
	}
	return newTrie
}

func (e *DataClockConsensusEngine) FrameProverTriesContains(
	key []byte,
) bool {
	e.frameProverTriesMx.RLock()
	defer e.frameProverTriesMx.RUnlock()
	for _, trie := range e.frameProverTries {
		if trie.Contains(key) {
			return true
		}
	}
	return false
}

func (e *DataClockConsensusEngine) FrameProverTrieContains(
	i int,
	key []byte,
) bool {
	e.frameProverTriesMx.RLock()
	defer e.frameProverTriesMx.RUnlock()
	if i < 0 || i >= len(e.frameProverTries) {
		return false
	}
	return e.frameProverTries[i].Contains(key)
}

func (e *DataClockConsensusEngine) runFramePruning() {
	defer e.wg.Done()
	// A full prover should _never_ do this
	if e.FrameProverTrieContains(0, e.provingKeyAddress) ||
		e.config.Engine.MaxFrames == -1 || e.config.Engine.FullProver {
		e.logger.Info("frame pruning not enabled")
		return
	}

	if e.config.Engine.MaxFrames < 1000 {
		e.logger.Warn(
			"max frames for pruning too low, pruning disabled",
			zap.Int64("max_frames", e.config.Engine.MaxFrames),
		)
		return
	}

	e.logger.Info("frame pruning enabled, waiting for delay timeout expiry")

	from := uint64(1)
	maxFrames := uint64(e.config.Engine.MaxFrames)
	batchSize := uint64(1000)
outer:
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-time.After(1 * time.Minute):
			head, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			if head.FrameNumber <= maxFrames ||
				head.FrameNumber <= application.PROOF_FRAME_SENIORITY_REPAIR+1 {
				continue
			}

			to := head.FrameNumber - maxFrames
			for i := from; i < to; i += batchSize {
				start, stop := i, min(i+batchSize, to)
				if err := e.clockStore.DeleteDataClockFrameRange(e.filter, start, stop); err != nil {
					e.logger.Error(
						"failed to prune frames",
						zap.Error(err),
						zap.Uint64("from", start),
						zap.Uint64("to", stop),
					)
					continue outer
				}
				e.logger.Info(
					"pruned frames",
					zap.Uint64("from", start),
					zap.Uint64("to", stop),
				)
				select {
				case <-e.ctx.Done():
					return
				default:
				}
				from = stop
			}
		}
	}
}

func (e *DataClockConsensusEngine) runSync() {
	defer e.wg.Done()
	// small optimization, beacon should never collect for now:
	if e.FrameProverTrieContains(0, e.provingKeyAddress) {
		return
	}

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.requestSyncCh:
			if err := e.pubSub.Bootstrap(e.ctx); err != nil {
				e.logger.Error("could not bootstrap", zap.Error(err))
			}
			if err := e.syncWithMesh(); err != nil {
				e.logger.Error("could not sync", zap.Error(err))
			}
		}
	}
}

func (e *DataClockConsensusEngine) runLoop() {
	defer e.wg.Done()
	dataFrameCh := e.dataTimeReel.NewFrameCh()
	runOnce := true
	for {
		peerCount := e.pubSub.GetNetworkPeersCount()
		if peerCount < e.minimumPeersRequired {
			e.logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		} else {
			latestFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			if runOnce {
				if e.FrameProverTrieContains(0, e.provingKeyAddress) {
					dataFrame, err := e.dataTimeReel.Head()
					if err != nil {
						panic(err)
					}

					latestFrame = e.processFrame(latestFrame, dataFrame)
				}
				runOnce = false
			}

			select {
			case <-e.ctx.Done():
				return
			case dataFrame := <-dataFrameCh:
				e.validationFilterMx.Lock()
				e.validationFilter = make(map[string]struct{}, len(e.validationFilter))
				e.validationFilterMx.Unlock()
				if e.FrameProverTrieContains(0, e.provingKeyAddress) {
					if err := e.publishProof(dataFrame); err != nil {
						e.logger.Error("could not publish proof", zap.Error(err))
						e.stateMx.Lock()
						if e.state < consensus.EngineStateStopping {
							e.state = consensus.EngineStateCollecting
						}
						e.stateMx.Unlock()
					}
				}
				latestFrame = e.processFrame(latestFrame, dataFrame)
			}
		}
	}
}

func (e *DataClockConsensusEngine) processFrame(
	latestFrame *protobufs.ClockFrame,
	dataFrame *protobufs.ClockFrame,
) *protobufs.ClockFrame {

	e.logger.Info(
		"current frame head",
		zap.Uint64("frame_number", dataFrame.FrameNumber),
		zap.Duration("frame_age", frametime.Since(dataFrame)),
	)
	var err error
	if !e.FrameProverTrieContains(0, e.provingKeyAddress) {
		select {
		case e.requestSyncCh <- struct{}{}:
		default:
		}
	}

	if latestFrame != nil && dataFrame.FrameNumber > latestFrame.FrameNumber {
		latestFrame = dataFrame
	}

	cas.IfLessThanUint64(&e.latestFrameReceived, latestFrame.FrameNumber)
	e.frameProverTriesMx.Lock()
	e.frameProverTries = e.dataTimeReel.GetFrameProverTries()
	e.frameProverTriesMx.Unlock()

	trie := e.GetFrameProverTrie(0)
	selBI, _ := dataFrame.GetSelector()
	sel := make([]byte, 32)
	sel = selBI.FillBytes(sel)

	if bytes.Equal(
		trie.FindNearest(sel).Key,
		e.provingKeyAddress,
	) {
		var nextFrame *protobufs.ClockFrame
		if nextFrame, err = e.prove(dataFrame); err != nil {
			e.logger.Error("could not prove", zap.Error(err))
			e.stateMx.Lock()
			if e.state < consensus.EngineStateStopping {
				e.state = consensus.EngineStateCollecting
			}
			e.stateMx.Unlock()
			return dataFrame
		}

		if _, err := e.dataTimeReel.Insert(e.ctx, nextFrame); err != nil {
			e.logger.Debug("could not insert frame", zap.Error(err))
		}

		return nextFrame
	} else {
		if latestFrame.Timestamp > time.Now().UnixMilli()-120000 {
			if !e.IsInProverTrie(e.pubSub.GetPeerID()) {
				e.logger.Info("announcing prover join")
				for _, eng := range e.executionEngines {
					eng.AnnounceProverJoin()
					break
				}
			} else {
				if e.previousFrameProven != nil &&
					e.previousFrameProven.FrameNumber == latestFrame.FrameNumber {
					return latestFrame
				}

				h, err := poseidon.HashBytes(e.pubSub.GetPeerID())
				if err != nil {
					panic(err)
				}
				peerProvingKeyAddress := h.FillBytes(make([]byte, 32))

				ring := -1
				if tries := e.GetFrameProverTries(); len(tries) > 1 {
					for i, tries := range tries[1:] {
						i := i
						if tries.Contains(peerProvingKeyAddress) {
							ring = i
						}
					}
				}

				//e.clientReconnectTest++
				//if e.clientReconnectTest >= 10 {
				//	e.tryReconnectDataWorkerClients()
				//	e.clientReconnectTest = 0
				//}

				previousTreeRoot := []byte{}
				if e.previousTree != nil {
					previousTreeRoot = e.previousTree.Root
				}
				outputs := e.PerformTimeProof(latestFrame, previousTreeRoot, latestFrame.Difficulty, ring)
				if outputs == nil || len(outputs) < 3 {
					e.logger.Info("workers not yet available for proving")
					return latestFrame
				}
				modulo := len(outputs)
				var proofTree *mt.MerkleTree
				var output [][]byte
				if latestFrame.FrameNumber >= application.PROOF_FRAME_COMBINE_CUTOFF {
					proofTree, output, err = tries.PackOutputIntoMultiPayloadAndProof(
						outputs,
						modulo,
						latestFrame,
						e.previousTree,
					)
				} else {
					proofTree, output, err = tries.PackOutputIntoPayloadAndProof(
						e.logger,
						outputs,
						modulo,
						latestFrame,
						e.previousTree,
					)
				}
				if err != nil {
					e.logger.Error(
						"could not successfully pack proof, reattempting",
						zap.Error(err),
					)
					return latestFrame
				}

				e.logger.Info(
					"PackOutputIntoPayloadAndProof data proof",
					zap.Int("ring", ring),
					zap.Int("active_workers", len(outputs)),
					zap.Uint64("frame_number", latestFrame.FrameNumber),
					zap.Duration("frame_age", frametime.Since(latestFrame)),
				)

				e.previousFrameProven = latestFrame
				e.previousTree = proofTree

				mint := &protobufs.MintCoinRequest{
					Proofs: output,
				}
				if err := mint.SignED448(e.pubSub.GetPublicKey(), e.pubSub.SignMessage); err != nil {
					e.logger.Error("could not sign mint", zap.Error(err))
					return latestFrame
				}
				if err := mint.Validate(); err != nil {
					e.logger.Error("mint validation failed", zap.Error(err))
					return latestFrame
				}

				e.logger.Info(
					"submitting data proof",
					zap.Int("ring", ring),
					zap.Int("active_workers", len(outputs)),
					zap.Uint64("frame_number", latestFrame.FrameNumber),
					zap.Duration("frame_age", frametime.Since(latestFrame)),
				)

				if err := e.publishMessage(e.txFilter, mint.TokenRequest()); err != nil {
					e.logger.Error("could not publish mint", zap.Error(err))
				}

				if e.config.Engine.AutoMergeCoins {
					_, addrs, _, err := e.coinStore.GetCoinsForOwner(
						peerProvingKeyAddress,
					)
					if err != nil {
						e.logger.Error(
							"received error while iterating coins",
							zap.Error(err),
						)
						return latestFrame
					}

					if len(addrs) > 25 {
						refs := []*protobufs.CoinRef{}
						for _, addr := range addrs {
							refs = append(refs, &protobufs.CoinRef{
								Address: addr,
							})
						}

						merge := &protobufs.MergeCoinRequest{
							Coins: refs,
						}
						if err := merge.SignED448(
							e.pubSub.GetPublicKey(),
							e.pubSub.SignMessage,
						); err != nil {
							e.logger.Error("could not sign merge", zap.Error(err))
							return latestFrame
						}
						if err := merge.Validate(); err != nil {
							e.logger.Error("merge validation failed", zap.Error(err))
							return latestFrame
						}

						if err := e.publishMessage(e.txFilter, merge.TokenRequest()); err != nil {
							e.logger.Warn("could not publish merge", zap.Error(err))
						}
					}
				}
			}
		}
		return latestFrame
	}
}
