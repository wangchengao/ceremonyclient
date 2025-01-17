package tries

import (
	"encoding/binary"
	"fmt"
	"go.uber.org/zap"
	"math"
	"math/bits"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"

	"github.com/pkg/errors"
	mt "github.com/txaty/go-merkletree"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type ProofLeaf struct {
	output []byte
}

var _ mt.DataBlock = (*ProofLeaf)(nil)

func NewProofLeaf(output []byte) *ProofLeaf {
	return &ProofLeaf{output}
}

func (p *ProofLeaf) Serialize() ([]byte, error) {
	return p.output, nil
}

func PackOutputIntoPayloadAndProof(
	logger *zap.Logger,
	outputs []mt.DataBlock,
	modulo int,
	frame *protobufs.ClockFrame,
	previousTree *mt.MerkleTree,
) (*mt.MerkleTree, [][]byte, error) {
	if modulo != len(outputs) {
		return nil, nil, errors.Wrap(
			errors.New("mismatch of outputs and prover size"),
			"pack output into payload and proof",
		)
	}
	tree, err := mt.New(
		&mt.Config{
			HashFunc: func(data []byte) ([]byte, error) {
				hash := sha3.Sum256(data)
				return hash[:], nil
			},
			Mode:               mt.ModeProofGen,
			DisableLeafHashing: true,
			RunInParallel:      true,
		},
		outputs,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "pack output into payload and proof")
	}

	logger.Info(
		"mt.New data proof",
		zap.Int("active_workers", len(outputs)),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Duration("frame_age", frametime.Since(frame)),
	)

	output := [][]byte{
		tree.Root,
		binary.BigEndian.AppendUint32([]byte{}, uint32(modulo)),
		binary.BigEndian.AppendUint64([]byte{}, frame.FrameNumber),
	}

	if previousTree != nil && len(previousTree.Proofs) == modulo {
		hash := sha3.Sum256(frame.Output)
		pick := BytesToUnbiasedMod(hash, uint64(modulo))
		if uint64(modulo) < pick || int(pick) >= len(previousTree.Proofs) {
			return nil, nil, errors.Wrap(
				errors.New("proof size mismatch"),
				"pack output into payload and proof",
			)
		}
		output = append(output, previousTree.Proofs[int(pick)].Siblings...)
		output = append(
			output,
			binary.BigEndian.AppendUint32(
				[]byte{},
				previousTree.Proofs[int(pick)].Path,
			),
		)
		output = append(output, previousTree.Leaves[int(pick)])
	}
	return tree, output, nil
}

func PackOutputIntoMultiPayloadAndProof(
	outputs []mt.DataBlock,
	modulo int,
	frame *protobufs.ClockFrame,
	previousTree *mt.MerkleTree,
) (*mt.MerkleTree, [][]byte, error) {
	if modulo != len(outputs) {
		return nil, nil, errors.Wrap(
			errors.New("mismatch of outputs and prover size"),
			"pack output into payload and proof",
		)
	}
	tree, err := mt.New(
		&mt.Config{
			HashFunc: func(data []byte) ([]byte, error) {
				hash := sha3.Sum256(data)
				return hash[:], nil
			},
			Mode:               mt.ModeProofGen,
			DisableLeafHashing: true,
		},
		outputs,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "pack output into payload and proof")
	}

	output := [][]byte{
		tree.Root,
		binary.BigEndian.AppendUint32([]byte{}, uint32(modulo)),
		binary.BigEndian.AppendUint64([]byte{}, frame.FrameNumber),
	}

	if previousTree != nil && len(previousTree.Proofs) == modulo {
		hash := sha3.Sum256(append(append([]byte{}, frame.Output...), previousTree.Root...))
		pick := BytesToUnbiasedMod(hash, uint64(modulo))
		if uint64(modulo) < pick {
			return nil, nil, errors.Wrap(
				errors.New("proof size mismatch"),
				"pack output into payload and proof",
			)
		}
		output = append(output, previousTree.Proofs[int(pick)].Siblings...)
		output = append(
			output,
			binary.BigEndian.AppendUint32(
				[]byte{},
				previousTree.Proofs[int(pick)].Path,
			),
		)
		output = append(output, previousTree.Leaves[int(pick)])
		additional := bits.Len64(uint64(modulo)-1) - 1
		picks := []int{int(pick)}
		for additional > 0 {
			hash = sha3.Sum256(hash[:])
			pick := BytesToUnbiasedMod(hash, uint64(modulo))
			found := false
			for _, p := range picks {
				if p == int(pick) {
					found = true
					break
				}
			}

			if !found {
				picks = append(picks, int(pick))
				output = append(output, previousTree.Leaves[int(pick)])
				additional--
			}
		}
	}
	return tree, output, nil
}

func UnpackAndVerifyOutput(
	previousRoot []byte,
	output [][]byte,
) (treeRoot []byte, modulo uint32, frameNumber uint64, verified bool, err error) {
	if len(output) < 3 {
		return nil, 0, 0, false, errors.Wrap(
			fmt.Errorf("output too short, expected at least 3 elements"),
			"unpack and verify output",
		)
	}

	treeRoot = output[0]
	modulo = binary.BigEndian.Uint32(output[1])
	frameNumber = binary.BigEndian.Uint64(output[2])

	if len(output) > 3 {
		numSiblings := bits.Len64(uint64(modulo) - 1)
		if len(output) != 5+numSiblings {
			return nil, 0, 0, false, errors.Wrap(
				fmt.Errorf("invalid number of proof elements"),
				"unpack and verify output",
			)
		}

		siblings := output[3 : 3+numSiblings]
		path := binary.BigEndian.Uint32(output[3+numSiblings])
		leaf := output[len(output)-1]

		verified, err = mt.Verify(
			NewProofLeaf(leaf),
			&mt.Proof{
				Siblings: siblings,
				Path:     path,
			},
			previousRoot,
			&mt.Config{
				HashFunc: func(data []byte) ([]byte, error) {
					hash := sha3.Sum256(data)
					return hash[:], nil
				},
				Mode:               mt.ModeProofGen,
				DisableLeafHashing: true,
			},
		)
		if err != nil {
			return nil, 0, 0, false, errors.Wrap(err, "unpack and verify output")
		}
	} else {
		verified = true
	}

	return treeRoot, modulo, frameNumber, verified, nil
}

func UnpackAndVerifyMultiOutput(
	previousRoot []byte,
	output [][]byte,
) (treeRoot []byte, modulo uint32, frameNumber uint64, verified bool, err error) {
	if len(output) < 3 {
		return nil, 0, 0, false, errors.Wrap(
			fmt.Errorf("output too short, expected at least 3 elements"),
			"unpack and verify output",
		)
	}

	treeRoot = output[0]
	modulo = binary.BigEndian.Uint32(output[1])
	frameNumber = binary.BigEndian.Uint64(output[2])

	if len(output) > 3 {
		numSiblings := bits.Len64(uint64(modulo) - 1)
		additional := bits.Len64(uint64(modulo)-1) - 1
		total := numSiblings
		if additional > 0 {
			total = numSiblings + additional
		}
		if len(output) != 5+total {
			return nil, 0, 0, false, errors.Wrap(
				fmt.Errorf("invalid number of proof elements"),
				"unpack and verify output",
			)
		}

		siblings := output[3 : 3+numSiblings]
		path := binary.BigEndian.Uint32(output[3+numSiblings])
		leaf := output[4+numSiblings]
		verified, err = mt.Verify(
			NewProofLeaf(leaf),
			&mt.Proof{
				Siblings: siblings,
				Path:     path,
			},
			previousRoot,
			&mt.Config{
				HashFunc: func(data []byte) ([]byte, error) {
					hash := sha3.Sum256(data)
					return hash[:], nil
				},
				Mode:               mt.ModeProofGen,
				DisableLeafHashing: true,
			},
		)
		if err != nil {
			return nil, 0, 0, false, errors.Wrap(err, "unpack and verify output")
		}
	} else {
		verified = true
	}

	return treeRoot, modulo, frameNumber, verified, nil
}

func BytesToUnbiasedMod(input [32]byte, modulus uint64) uint64 {
	if modulus <= 1 {
		return 0
	}

	hashValue := binary.BigEndian.Uint64(input[:8])

	maxValid := math.MaxUint64 - (math.MaxUint64 % modulus)

	result := hashValue
	for result > maxValid {
		offset := uint64(8)
		for result > maxValid && offset <= 24 {
			nextBytes := binary.BigEndian.Uint64(input[offset : offset+8])
			result = (result * 31) ^ nextBytes
			offset += 8
		}

		if result > maxValid {
			result = (result * 31) ^ (result >> 32)
		}
	}

	return result % modulus
}
