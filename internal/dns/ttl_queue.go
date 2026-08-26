package dns

import (
	"container/heap"
	"time"
)

// TTLEntry tracks when a single hostname next needs re-resolution.
type TTLEntry struct {
	Hostname    string
	NextRefresh time.Time
	index       int // maintained by heap.Interface
}

// TTLQueue is a min-heap of TTLEntry ordered by NextRefresh.
// It lets the controller schedule re-resolution at the exact moment
// DNS TTLs expire rather than polling on a fixed timer.
type TTLQueue struct {
	items []*TTLEntry
	byKey map[string]*TTLEntry
}

func NewTTLQueue() *TTLQueue {
	q := &TTLQueue{byKey: make(map[string]*TTLEntry)}
	heap.Init(q)
	return q
}

// Upsert adds or updates the refresh time for hostname.
func (q *TTLQueue) Upsert(hostname string, ttl time.Duration) {
	next := time.Now().Add(ttl)
	if e, ok := q.byKey[hostname]; ok {
		e.NextRefresh = next
		heap.Fix(q, e.index)
		return
	}
	e := &TTLEntry{Hostname: hostname, NextRefresh: next}
	heap.Push(q, e)
	q.byKey[hostname] = e
}

// PeekNext returns the earliest refresh time across all tracked hostnames.
// Returns zero Time if the queue is empty.
func (q *TTLQueue) PeekNext() time.Time {
	if len(q.items) == 0 {
		return time.Time{}
	}
	return q.items[0].NextRefresh
}

// MinDelay returns max(PeekNext - now, floor). Use as RequeueAfter.
func (q *TTLQueue) MinDelay(floor time.Duration) time.Duration {
	next := q.PeekNext()
	if next.IsZero() {
		return floor
	}
	d := time.Until(next)
	if d < floor {
		return floor
	}
	return d
}

// heap.Interface implementation

func (q *TTLQueue) Len() int { return len(q.items) }

func (q *TTLQueue) Less(i, j int) bool {
	return q.items[i].NextRefresh.Before(q.items[j].NextRefresh)
}

func (q *TTLQueue) Swap(i, j int) {
	q.items[i], q.items[j] = q.items[j], q.items[i]
	q.items[i].index = i
	q.items[j].index = j
}

func (q *TTLQueue) Push(x any) {
	e := x.(*TTLEntry)
	e.index = len(q.items)
	q.items = append(q.items, e)
}

func (q *TTLQueue) Pop() any {
	n := len(q.items)
	e := q.items[n-1]
	q.items[n-1] = nil
	q.items = q.items[:n-1]
	delete(q.byKey, e.Hostname)
	return e
}
