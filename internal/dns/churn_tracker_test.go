package dns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChurnTracker_SingleCycle(t *testing.T) {
	ct := NewChurnTracker()
	n := ct.Record("api.example.com", []string{"1.2.3.4", "1.2.3.5"})
	assert.Equal(t, 2, n)
}

func TestChurnTracker_StableIPs(t *testing.T) {
	ct := NewChurnTracker()
	for i := 0; i < 5; i++ {
		n := ct.Record("api.example.com", []string{"1.2.3.4"})
		assert.Equal(t, 1, n, "stable single IP should always report churn=1")
	}
}

func TestChurnTracker_GrowingChurn(t *testing.T) {
	ct := NewChurnTracker()
	for i := 0; i < 5; i++ {
		n := ct.Record("cdn.example.com", []string{fmt.Sprintf("10.0.0.%d", i)})
		assert.Equal(t, i+1, n)
	}
}

func TestChurnTracker_RingOverwrite(t *testing.T) {
	ct := NewChurnTracker()
	// Fill the ring with distinct IPs.
	for i := 0; i < churnRingSize; i++ {
		ct.Record("cdn.example.com", []string{fmt.Sprintf("10.0.0.%d", i)})
	}
	// One more cycle: the oldest slot is overwritten.
	// Churn should still be churnRingSize (the new IP replaces slot 0's old IP).
	n := ct.Record("cdn.example.com", []string{fmt.Sprintf("10.0.0.%d", churnRingSize)})
	assert.Equal(t, churnRingSize, n, "ring should not exceed churnRingSize distinct IPs")
}

func TestChurnTracker_MultipleHostnames(t *testing.T) {
	ct := NewChurnTracker()
	ct.Record("a.example.com", []string{"1.1.1.1"})
	ct.Record("b.example.com", []string{"2.2.2.2", "3.3.3.3"})
	assert.Equal(t, 1, ct.Record("a.example.com", []string{"1.1.1.1"}))
	assert.Equal(t, 2, ct.Record("b.example.com", []string{"2.2.2.2", "3.3.3.3"}))
}

func TestChurnTracker_ConcurrentSafe(t *testing.T) {
	ct := NewChurnTracker()
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(i int) {
			ct.Record("concurrent.example.com", []string{fmt.Sprintf("10.0.0.%d", i)})
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}
