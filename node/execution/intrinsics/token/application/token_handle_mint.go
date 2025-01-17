package application

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"math/bits"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

// for tests, these need to be var
var PROOF_FRAME_CUTOFF = uint64(46500)
var PROOF_FRAME_RING_RESET = uint64(52000)
var PROOF_FRAME_RING_RESET_2 = uint64(53028)
var PROOF_FRAME_COMBINE_CUTOFF = uint64(99900)

const PROOF_FRAME_SENIORITY_REPAIR = 59029

type processedMint struct {
	isPre2          bool
	penalty         bool
	deletedProof    *protobufs.TokenOutput_DeletedProof
	parallelism     uint32
	priorCommitment []byte
	newCommitment   []byte
	newFrameNumber  uint64
	implicitAddr    []byte
	validForReward  bool
	treeVerified    bool
	wesoVerified    bool
}

func (a *TokenApplication) preProcessMint(
	currentFrameNumber uint64,
	t *protobufs.MintCoinRequest,
	frame *protobufs.ClockFrame,
) (
	out *processedMint,
	err error,
) {
	if err := t.Validate(); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
	}

	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
	}

	addr, err := poseidon.HashBytes(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
	}
	addrBytes := addr.FillBytes(make([]byte, 32))

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
	}
	altAddrBytes := altAddr.FillBytes(make([]byte, 32))

	// todo: set termination frame for this:
	if len(t.Proofs) == 1 && a.Tries[0].Contains(addrBytes) &&
		bytes.Equal(t.Signature.PublicKey.KeyValue, a.Beacon) {
		return &processedMint{
			isPre2:  true,
			penalty: false,
		}, nil
	} else if len(t.Proofs) > 0 && currentFrameNumber > PROOF_FRAME_CUTOFF &&
		currentFrameNumber < PROOF_FRAME_COMBINE_CUTOFF {
		a.Logger.Debug(
			"got mint from peer",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
		)
		_, prfs, err := a.CoinStore.GetPreCoinProofsForOwner(altAddrBytes)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
		}

		var delete *protobufs.PreCoinProof
		var commitment []byte
		var previousFrame *protobufs.ClockFrame
		var previousParallelism uint32
		for _, pr := range prfs {
			if len(pr.Proof) >= 3 && (len(pr.Commitment) == 40 || len(pr.Commitment) == 72) {
				delete = pr
				commitment = pr.Commitment[:32]
				previousFrameNumber := binary.BigEndian.Uint64(pr.Commitment[32:])
				previousParallelism = binary.BigEndian.Uint32(pr.Proof[36:40])
				previousFrame, _, err = a.ClockStore.GetDataClockFrame(
					frame.Filter,
					previousFrameNumber,
					true,
				)

				if err != nil {
					a.Logger.Debug(
						"invalid frame",
						zap.Error(err),
						zap.String("peer_id", base58.Encode([]byte(peerId))),
						zap.Uint64("frame_number", currentFrameNumber),
					)
					return &processedMint{
						isPre2:  false,
						penalty: true,
					}, nil
				}
			}
		}

		newCommitment, parallelism, newFrameNumber, verified, err :=
			tries.UnpackAndVerifyOutput(commitment, t.Proofs)
		if err != nil {
			a.Logger.Debug(
				"mint error",
				zap.Error(err),
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return &processedMint{
				isPre2:  false,
				penalty: true,
			}, nil
		}

		if previousParallelism != 0 && previousParallelism != parallelism {
			verified = false
		}

		if !verified {
			a.Logger.Debug(
				"tree verification failed",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
		}

		// Current frame - 2 is because the current frame is the newly created frame,
		// and the provers are submitting proofs on the frame preceding the one they
		// last saw. This enforces liveness and creates a punishment for being
		// late.
		if (previousFrame != nil && newFrameNumber <= previousFrame.FrameNumber) ||
			newFrameNumber < currentFrameNumber-2 {
			previousFrameNumber := uint64(0)
			if previousFrame != nil {
				previousFrameNumber = previousFrame.FrameNumber
			}

			a.Logger.Debug(
				"received out of order proofs, ignoring",
				zap.Error(err),
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("previous_frame", previousFrameNumber),
				zap.Uint64("new_frame", newFrameNumber),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		wesoVerified := true
		if verified && delete != nil && len(t.Proofs) > 3 {
			newFrame, _, err := a.ClockStore.GetDataClockFrame(
				frame.Filter,
				newFrameNumber,
				true,
			)
			if err != nil {
				a.Logger.Debug(
					"invalid frame",
					zap.Error(err),
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
				)
				return &processedMint{
					isPre2:  false,
					penalty: true,
				}, nil
			}
			hash := sha3.Sum256(newFrame.Output)
			pick := tries.BytesToUnbiasedMod(hash, uint64(parallelism))
			challenge := []byte{}
			challenge = append(challenge, peerId...)
			challenge = binary.BigEndian.AppendUint64(
				challenge,
				previousFrame.FrameNumber,
			)
			individualChallenge := append([]byte{}, challenge...)
			individualChallenge = binary.BigEndian.AppendUint32(
				individualChallenge,
				uint32(pick),
			)
			leaf := t.Proofs[len(t.Proofs)-1]
			individualChallenge = append(individualChallenge, previousFrame.Output...)
			if len(leaf) != 516 {
				a.Logger.Debug(
					"invalid size",
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
					zap.Int("proof_size", len(leaf)),
				)
				return &processedMint{
					isPre2:  false,
					penalty: true,
				}, nil
			}

			if bytes.Equal(leaf, bytes.Repeat([]byte{0x00}, 516)) ||
				!a.FrameProver.VerifyChallengeProof(
					individualChallenge,
					frame.Difficulty,
					leaf,
				) {
				a.Logger.Debug(
					"invalid proof",
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
				)
				// we want this to still apply the next commit even if this proof failed
				wesoVerified = false
			}
		}

		var deletedProof *protobufs.TokenOutput_DeletedProof
		if delete != nil {
			deletedProof = &protobufs.TokenOutput_DeletedProof{
				DeletedProof: delete,
			}
		}

		validForReward := verified && delete != nil && len(t.Proofs) > 3 && wesoVerified
		return &processedMint{
			isPre2:         false,
			penalty:        false,
			deletedProof:   deletedProof,
			parallelism:    parallelism,
			newCommitment:  newCommitment,
			newFrameNumber: newFrameNumber,
			implicitAddr:   altAddrBytes,
			validForReward: validForReward,
			treeVerified:   verified,
			wesoVerified:   wesoVerified,
		}, nil
	} else if len(t.Proofs) > 0 && currentFrameNumber >= PROOF_FRAME_COMBINE_CUTOFF {
		a.Logger.Debug(
			"got mint from peer",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
		)
		_, prfs, err := a.CoinStore.GetPreCoinProofsForOwner(altAddrBytes)
		if err != nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
		}

		var delete *protobufs.PreCoinProof
		var commitment []byte
		var previousFrame *protobufs.ClockFrame
		var previousParallelism uint32
		var priorCommitment []byte
		for _, pr := range prfs {
			if len(pr.Proof) >= 3 && (len(pr.Commitment) == 40 || len(pr.Commitment) == 72) {
				delete = pr
				commitment = pr.Commitment[:32]
				previousFrameNumber := binary.BigEndian.Uint64(pr.Commitment[32:40])
				previousParallelism = binary.BigEndian.Uint32(pr.Proof[36:40])
				previousFrame, _, err = a.ClockStore.GetDataClockFrame(
					frame.Filter,
					previousFrameNumber,
					true,
				)
				if len(pr.Commitment) > 40 {
					priorCommitment = pr.Commitment[40:]
				}

				if err != nil {
					a.Logger.Debug(
						"invalid frame",
						zap.Error(err),
						zap.String("peer_id", base58.Encode([]byte(peerId))),
						zap.Uint64("frame_number", currentFrameNumber),
					)
					return &processedMint{
						isPre2:  false,
						penalty: true,
					}, nil
				}
			}
		}

		newCommitment, parallelism, newFrameNumber, verified, err :=
			tries.UnpackAndVerifyMultiOutput(commitment, t.Proofs)
		if err != nil {
			a.Logger.Debug(
				"mint error",
				zap.Error(err),
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return &processedMint{
				isPre2:  false,
				penalty: true,
			}, nil
		}

		if previousParallelism != 0 && previousParallelism != parallelism {
			verified = false
		}

		if !verified {
			a.Logger.Debug(
				"tree verification failed",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
			)
		}

		// Current frame - 2 is because the current frame is the newly created frame,
		// and the provers are submitting proofs on the frame preceding the one they
		// last saw. This enforces liveness and creates a punishment for being
		// late.
		if (previousFrame != nil && newFrameNumber <= previousFrame.FrameNumber) ||
			newFrameNumber < currentFrameNumber-2 {
			previousFrameNumber := uint64(0)
			if previousFrame != nil {
				previousFrameNumber = previousFrame.FrameNumber
			}

			a.Logger.Debug(
				"received out of order proofs, ignoring",
				zap.Error(err),
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("previous_frame", previousFrameNumber),
				zap.Uint64("new_frame", newFrameNumber),
				zap.Uint64("frame_number", currentFrameNumber),
			)
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		wesoVerified := true
		if verified && delete != nil && len(t.Proofs) > 3 {
			newFrame, _, err := a.ClockStore.GetDataClockFrame(
				frame.Filter,
				newFrameNumber,
				true,
			)
			if err != nil {
				a.Logger.Debug(
					"invalid frame",
					zap.Error(err),
					zap.String("peer_id", base58.Encode([]byte(peerId))),
					zap.Uint64("frame_number", currentFrameNumber),
				)
				return &processedMint{
					isPre2:  false,
					penalty: true,
				}, nil
			}
			hash := sha3.Sum256(append(append([]byte{}, newFrame.Output...), commitment...))
			pick := tries.BytesToUnbiasedMod(hash, uint64(parallelism))
			challenge := []byte{}
			challenge = append(challenge, peerId...)
			challenge = binary.BigEndian.AppendUint64(
				challenge,
				previousFrame.FrameNumber,
			)
			additional := bits.Len64(uint64(parallelism)-1) - 1
			picks := []int{int(pick)}
			outputs := [][]byte{t.Proofs[len(t.Proofs)-(additional+1)]}
			for additional > 0 {
				hash = sha3.Sum256(hash[:])
				pick := tries.BytesToUnbiasedMod(hash, uint64(parallelism))
				found := false
				for _, p := range picks {
					if p == int(pick) {
						found = true
						break
					}
				}

				if !found {
					picks = append(picks, int(pick))
					outputs = append(outputs, t.Proofs[len(t.Proofs)-additional])
					additional--
				}
			}
			for i, pick := range picks {
				individualChallenge := append([]byte{}, challenge...)
				individualChallenge = binary.BigEndian.AppendUint32(
					individualChallenge,
					uint32(pick),
				)

				individualChallenge = append(individualChallenge, previousFrame.Output...)
				individualChallenge = append(individualChallenge, priorCommitment...)
				leaf := outputs[i]

				if len(leaf) != 516 {
					a.Logger.Debug(
						"invalid size",
						zap.String("peer_id", base58.Encode([]byte(peerId))),
						zap.Uint64("frame_number", currentFrameNumber),
						zap.Int("proof_size", len(leaf)),
					)
					return &processedMint{
						isPre2:  false,
						penalty: true,
					}, nil
				}

				if bytes.Equal(leaf, bytes.Repeat([]byte{0x00}, 516)) ||
					!a.FrameProver.VerifyChallengeProof(
						individualChallenge,
						frame.Difficulty,
						leaf,
					) {
					a.Logger.Debug(
						"invalid proof",
						zap.String("peer_id", base58.Encode([]byte(peerId))),
						zap.Uint64("frame_number", currentFrameNumber),
					)
					// we want this to still apply the next commit even if this proof failed
					wesoVerified = wesoVerified && false
				}
			}
		}

		var deletedProof *protobufs.TokenOutput_DeletedProof
		if delete != nil {
			deletedProof = &protobufs.TokenOutput_DeletedProof{
				DeletedProof: delete,
			}
		}

		validForReward := verified && delete != nil && len(t.Proofs) > 3 && wesoVerified
		return &processedMint{
			isPre2:          false,
			penalty:         false,
			deletedProof:    deletedProof,
			parallelism:     parallelism,
			priorCommitment: commitment,
			newCommitment:   newCommitment,
			newFrameNumber:  newFrameNumber,
			implicitAddr:    altAddrBytes,
			validForReward:  validForReward,
			treeVerified:    verified,
			wesoVerified:    wesoVerified,
		}, nil
	}

	a.Logger.Debug(
		"could not find case for proof",
		zap.String("peer_id", base58.Encode([]byte(peerId))),
		zap.Uint64("frame_number", currentFrameNumber),
	)
	return nil, errors.Wrap(ErrInvalidStateTransition, "pre process mint")
}

func (a *TokenApplication) handleMint(
	currentFrameNumber uint64,
	t *protobufs.MintCoinRequest,
	frame *protobufs.ClockFrame,
	processed *processedMint,
	parallelismMap map[int]uint64,
) ([]*protobufs.TokenOutput, error) {
	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
	}
	altAddrBytes := altAddr.FillBytes(make([]byte, 32))

	// todo: set termination frame for this:
	if processed.isPre2 {
		if len(t.Proofs[0]) != 64 {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		_, pr, err := a.CoinStore.GetPreCoinProofsForOwner(t.Proofs[0][32:])
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
		}

		for _, p := range pr {
			if p.IndexProof == nil && bytes.Equal(p.Amount, t.Proofs[0][:32]) {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
			}
		}

		outputs := []*protobufs.TokenOutput{
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Proof{
					Proof: &protobufs.PreCoinProof{
						Amount: t.Proofs[0][:32],
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      t.Proofs[0][32:],
								},
							},
						},
						Proof: t.Signature.Signature,
					},
				},
			},
			&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount:       t.Proofs[0][:32],
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      t.Proofs[0][32:],
								},
							},
						},
					},
				},
			},
		}
		return outputs, nil
	} else if len(t.Proofs) > 0 && currentFrameNumber > PROOF_FRAME_CUTOFF {
		a.Logger.Debug(
			"got mint from peer",
			zap.String("peer_id", base58.Encode([]byte(peerId))),
			zap.Uint64("frame_number", currentFrameNumber),
		)
		ring := -1
		for i, t := range a.Tries[1:] {
			if t.Contains(altAddrBytes) {
				ring = i
			}
		}

		if processed.penalty {
			return []*protobufs.TokenOutput{&protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Penalty{
					Penalty: &protobufs.ProverPenalty{
						Quantity: 10,
						Account: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									ImplicitType: 0,
									Address:      altAddrBytes,
								},
							},
						},
					},
				},
			}}, nil
		}

		outputs := []*protobufs.TokenOutput{}

		if processed.deletedProof != nil {
			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: processed.deletedProof,
				},
			)
		}
		if processed.validForReward {
			storage := PomwBasis(1, ring, currentFrameNumber)
			m := parallelismMap[ring]
			if m == 0 {
				m = 1
			}
			storage.Quo(storage, big.NewInt(int64(m)))
			storage.Mul(storage, big.NewInt(int64(processed.parallelism)))
			storageBytes := storage.FillBytes(make([]byte, 32))

			a.Logger.Debug(
				"issued reward",
				zap.String("peer_id", base58.Encode([]byte(peerId))),
				zap.Uint64("frame_number", currentFrameNumber),
				zap.String("reward", storage.String()),
			)

			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Proof{
						Proof: &protobufs.PreCoinProof{
							Commitment: append(
								binary.BigEndian.AppendUint64(
									append([]byte{}, processed.newCommitment...),
									processed.newFrameNumber,
								),
								processed.priorCommitment...,
							),
							Amount:     storageBytes,
							Proof:      payload,
							Difficulty: a.Difficulty,
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddrBytes,
									},
								},
							},
						},
					},
				},
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Coin{
						Coin: &protobufs.Coin{
							Amount:       storageBytes,
							Intersection: make([]byte, 1024),
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddrBytes,
									},
								},
							},
						},
					},
				},
			)
		} else {
			outputs = append(
				outputs,
				&protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Proof{
						Proof: &protobufs.PreCoinProof{
							Commitment: append(
								binary.BigEndian.AppendUint64(
									append([]byte{}, processed.newCommitment...),
									processed.newFrameNumber,
								),
								processed.priorCommitment...,
							),
							Proof:      payload,
							Difficulty: a.Difficulty,
							Owner: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddrBytes,
									},
								},
							},
						},
					},
				},
			)
			if !processed.wesoVerified ||
				(currentFrameNumber < PROOF_FRAME_RING_RESET && !processed.treeVerified) {
				outputs = append(outputs, &protobufs.TokenOutput{
					Output: &protobufs.TokenOutput_Penalty{
						Penalty: &protobufs.ProverPenalty{
							Quantity: 10,
							Account: &protobufs.AccountRef{
								Account: &protobufs.AccountRef_ImplicitAccount{
									ImplicitAccount: &protobufs.ImplicitAccount{
										ImplicitType: 0,
										Address:      altAddrBytes,
									},
								},
							},
						},
					},
				})
			}
		}
		return outputs, nil
	}
	a.Logger.Debug(
		"could not find case for proof",
		zap.String("peer_id", base58.Encode([]byte(peerId))),
		zap.Uint64("frame_number", currentFrameNumber),
	)
	return nil, errors.Wrap(ErrInvalidStateTransition, "handle mint")
}

func PomwBasis(generation uint64, ring int, currentFrameNumber uint64) *big.Int {
	prec := uint(53)

	one := new(big.Float).SetPrec(prec).SetInt64(1)
	divisor := new(big.Float).SetPrec(prec).SetInt64(1048576)

	normalized := new(big.Float).SetPrec(prec)
	// A simple hack for estimating state growth in terms of frames, based on
	// linear relationship of state growth:
	normalized.SetInt64(int64((737280 + currentFrameNumber) / 184320))
	normalized.Quo(normalized, divisor)

	// 1/2^n
	exp := new(big.Float).SetPrec(prec).SetInt64(1)
	if generation > 0 {
		powerOfTwo := new(big.Float).SetPrec(prec).SetInt64(2)
		powerOfTwo.SetInt64(1)
		for i := uint64(0); i < generation; i++ {
			powerOfTwo.Mul(powerOfTwo, big.NewFloat(2))
		}
		exp.Quo(one, powerOfTwo)
	}

	// (d/1048576)^(1/2^n)
	result := new(big.Float).Copy(normalized)
	if generation > 0 {
		for i := uint64(0); i < generation; i++ {
			result.Sqrt(result)
		}
	}

	// Calculate 1/result
	result.Quo(one, result)

	// Divide by 2^s
	if ring > 0 {
		divisor := new(big.Float).SetPrec(prec).SetInt64(1)
		for i := 0; i < ring; i++ {
			divisor.Mul(divisor, big.NewFloat(2))
		}
		result.Quo(result, divisor)
	}

	result.Mul(result, new(big.Float).SetPrec(prec).SetInt64(8000000000))

	out, _ := result.Int(new(big.Int))
	return out
}
