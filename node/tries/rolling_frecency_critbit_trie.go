package tries

import (
	"bytes"
	"encoding/gob"
	"sort"
	"sync"

	"github.com/pkg/errors"
)

type RollingFrecencyCritbitTrie struct {
	Trie *Tree
	mu   sync.RWMutex
}

func (t *RollingFrecencyCritbitTrie) Serialize() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(t.Trie); err != nil {
		return nil, errors.Wrap(err, "serialize")
	}

	return b.Bytes(), nil
}

func (t *RollingFrecencyCritbitTrie) Deserialize(buf []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(buf) == 0 {
		return nil
	}

	var b bytes.Buffer
	b.Write(buf)
	dec := gob.NewDecoder(&b)

	if err := dec.Decode(&t.Trie); err != nil {
		if t.Trie == nil {
			t.Trie = New()
		}
	}

	return nil
}

func (t *RollingFrecencyCritbitTrie) Contains(address []byte) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	_, ok := t.Trie.Get(address)
	return ok
}

func (t *RollingFrecencyCritbitTrie) Get(
	address []byte,
) Value {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	p, ok := t.Trie.Get(address)
	if !ok {
		return Value{
			EarliestFrame: 0,
			LatestFrame:   0,
			Count:         0,
		}
	}

	return p.(Value)
}

func (t *RollingFrecencyCritbitTrie) FindNearest(
	address []byte,
) Value {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	return t.FindNearestAndApproximateNeighbors(address)[0]
}

func (t *RollingFrecencyCritbitTrie) FindNearestAndApproximateNeighbors(
	address []byte,
) []Value {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ret := []Value{}
	if t.Trie == nil {
		t.Trie = New()
	}

	t.Trie.Walk(func(k []byte, v interface{}) bool {
		ret = append(ret, v.(Value))
		return false
	})

	sort.Slice(ret, func(i, j int) bool {
		targetLen := len(address)
		a := ret[i].Key
		b := ret[j].Key
		aLen := len(a)
		bLen := len(b)

		maxLen := targetLen
		if aLen > maxLen {
			maxLen = aLen
		}
		if bLen > maxLen {
			maxLen = bLen
		}

		var aDiff, bDiff byte
		for i := 0; i < maxLen; i++ {
			var targetByte, aByte, bByte byte

			if i < targetLen {
				targetByte = address[i]
			}
			if i < aLen {
				aByte = a[i]
			}
			if i < bLen {
				bByte = b[i]
			}

			if targetByte >= aByte {
				aDiff = targetByte - aByte
			} else {
				aDiff = aByte - targetByte
			}

			if targetByte >= bByte {
				bDiff = targetByte - bByte
			} else {
				bDiff = bByte - targetByte
			}

			if aDiff != bDiff {
				return aDiff < bDiff
			}
		}

		return true
	})

	return ret
}

func (t *RollingFrecencyCritbitTrie) Add(
	address []byte,
	latestFrame uint64,
) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Trie == nil {
		t.Trie = New()
	}

	i, ok := t.Trie.Get(address)
	var v Value
	if !ok {
		v = Value{
			Key:           address,
			EarliestFrame: latestFrame,
			LatestFrame:   latestFrame,
			Count:         0,
		}
	} else {
		v = i.(Value)
	}
	v.LatestFrame = latestFrame
	t.Trie.Insert(address, v)
}

func (t *RollingFrecencyCritbitTrie) Remove(address []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Trie == nil {
		t.Trie = New()
	}
	t.Trie.Delete(address)
}
