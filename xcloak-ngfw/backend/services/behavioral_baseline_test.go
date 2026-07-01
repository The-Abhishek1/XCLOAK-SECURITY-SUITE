package services

import (
	"math"
	"testing"
	"time"

	"xcloak-ngfw/models"
)

// fixedTime returns a time.Time at the given hour on an arbitrary Monday.
func fixedTime(hour int) time.Time {
	return time.Date(2024, 1, 1, hour, 0, 0, 0, time.UTC)
}

// ── ewmaUpdate ────────────────────────────────────────────────────────────────

func TestEwmaUpdate_FirstObservation(t *testing.T) {
	newMean, newVar := ewmaUpdate(0, 0, 100)
	wantMean := ewmaAlpha * 100
	if math.Abs(newMean-wantMean) > 1e-9 {
		t.Errorf("mean = %.6f, want %.6f", newMean, wantMean)
	}
	if newVar <= 0 {
		t.Errorf("variance after first non-zero obs should be > 0, got %v", newVar)
	}
}

func TestEwmaUpdate_StableSignal(t *testing.T) {
	// After many identical observations, mean converges to that value and
	// variance converges toward zero.
	mean, variance := 0.0, 0.0
	for i := 0; i < 200; i++ {
		mean, variance = ewmaUpdate(mean, variance, 50)
	}
	if math.Abs(mean-50) > 0.5 {
		t.Errorf("mean should converge to 50, got %.4f", mean)
	}
	if variance > 1.0 {
		t.Errorf("variance for constant signal should be near 0, got %.4f", variance)
	}
}

func TestEwmaUpdate_NoisySignal(t *testing.T) {
	// Alternating 0/100 → mean near 50, non-trivial variance.
	mean, variance := 50.0, 0.0
	for i := 0; i < 200; i++ {
		obs := float64((i % 2) * 100)
		mean, variance = ewmaUpdate(mean, variance, obs)
	}
	if math.Abs(mean-50) > 5 {
		t.Errorf("alternating 0/100 mean should be ~50, got %.4f", mean)
	}
	if variance < 100 {
		t.Errorf("alternating 0/100 variance should be large, got %.4f", variance)
	}
}

// ── metricZScore ──────────────────────────────────────────────────────────────

func TestMetricZScore_Zero(t *testing.T) {
	z := metricZScore(50, 50, 25)
	if math.Abs(z) > 1e-9 {
		t.Errorf("z for obs==mean should be 0, got %v", z)
	}
}

func TestMetricZScore_TwoSigmaAbove(t *testing.T) {
	// σ=5 (var=25), obs = mean+10 → z = 2.
	z := metricZScore(60, 50, 25)
	if math.Abs(z-2.0) > 1e-9 {
		t.Errorf("z should be 2.0, got %v", z)
	}
}

func TestMetricZScore_MinSigmaFloor(t *testing.T) {
	// variance=0 → floor = max(1, mean*0.10).
	// mean=10 → floor=1; obs=20 → z = (20-10)/1 = 10.
	z := metricZScore(20, 10, 0)
	if math.Abs(z-10.0) > 1e-9 {
		t.Errorf("z = %v, want 10.0 (sigma floor applied)", z)
	}
}

func TestMetricZScore_NegativeDeviation(t *testing.T) {
	z := metricZScore(30, 50, 100) // below mean → negative
	if z >= 0 {
		t.Errorf("z for obs < mean should be negative, got %v", z)
	}
}

// ── computeScore ──────────────────────────────────────────────────────────────

func emptyBaseline() *models.AgentBaseline { return &models.AgentBaseline{SampleCount: 0} }

func establishedBaseline() *models.AgentBaseline {
	return &models.AgentBaseline{
		SampleCount:  100,
		AvgLogCount:  100, VarLogCount: 25,
		AvgLoginFail: 0, VarLoginFail: 0,
		AvgConnCount: 0, VarConnCount: 0,
		AvgProcCount: 0, VarProcCount: 0,
		AvgPrivEsc:   0, VarPrivEsc:   0,
	}
}

func TestComputeScore_NoBaseline_LowActivity(t *testing.T) {
	score, _ := computeScore(agentWindowMetrics{LogCount: 3}, emptyBaseline(), fixedTime(10))
	if score != 0 {
		t.Errorf("low activity with no baseline: want 0, got %d", score)
	}
}

func TestComputeScore_NoBaseline_HighActivity(t *testing.T) {
	m := agentWindowMetrics{LogCount: 50, LoginFails: 5}
	score, _ := computeScore(m, emptyBaseline(), fixedTime(10))
	if score == 0 {
		t.Error("high activity with no baseline should score > 0")
	}
}

func TestComputeScore_PrivEscAlwaysScores(t *testing.T) {
	_, c := computeScore(agentWindowMetrics{PrivEsc: 3}, emptyBaseline(), fixedTime(10))
	if c.PrivEscScore == 0 {
		t.Error("privilege escalation events should always contribute to score")
	}
}

func TestComputeScore_SpikeAboveBaseline(t *testing.T) {
	// 100 events in 5 min = 1200/hr against baseline of 100/hr (σ=5) → very high z.
	m := agentWindowMetrics{LogCount: 100}
	score, _ := computeScore(m, establishedBaseline(), fixedTime(10))
	if score < 30 {
		t.Errorf("large log-rate spike should score >= 30, got %d", score)
	}
}

func TestComputeScore_OffHoursBonus(t *testing.T) {
	b := &models.AgentBaseline{SampleCount: 10, AvgLogCount: 1}
	m := agentWindowMetrics{LogCount: 20}

	score3am, c3am := computeScore(m, b, fixedTime(3))
	score10am, _ := computeScore(m, b, fixedTime(10))

	if c3am.OffHoursScore == 0 {
		t.Error("3am off-hours activity should set OffHoursScore > 0")
	}
	if score3am <= score10am {
		t.Errorf("3am score (%d) should exceed 10am score (%d)", score3am, score10am)
	}
}

func TestComputeScore_ClampedTo100(t *testing.T) {
	m := agentWindowMetrics{
		LogCount: 9999, LoginFails: 100,
		ConnCount: 500, ProcCount: 200, PrivEsc: 50,
	}
	score, _ := computeScore(m, establishedBaseline(), fixedTime(3))
	if score > 100 {
		t.Errorf("score must not exceed 100, got %d", score)
	}
	if score < 95 {
		t.Errorf("extreme multi-metric spike should nearly saturate score, got %d", score)
	}
}

func TestComputeScore_NormalActivity_LowScore(t *testing.T) {
	// Activity right at the baseline mean should produce a near-zero score.
	b := &models.AgentBaseline{
		SampleCount:  200,
		AvgLogCount:  120, VarLogCount: 100, // mean=120/hr, σ=10
		AvgLoginFail: 0, VarLoginFail: 0,
		AvgConnCount: 0, VarConnCount: 0,
		AvgProcCount: 0, VarProcCount: 0,
		AvgPrivEsc:   0, VarPrivEsc:   0,
	}
	// 10 events/5-min = 120/hr → exactly at baseline.
	m := agentWindowMetrics{LogCount: 10}
	score, _ := computeScore(m, b, fixedTime(14))
	if score > 5 {
		t.Errorf("activity at baseline mean should score near 0, got %d", score)
	}
}
