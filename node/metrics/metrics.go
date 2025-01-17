package metrics

import (
	"github.com/go-kit/kit/metrics/prometheus"
	stdprome "github.com/prometheus/client_golang/prometheus"
)

const (
	promNamespace = ""
	promSubsystem = ""
)

var (
	NodeMaxFrame = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_max_frame",
		Help:      "Max Frame value",
	}, []string{"node"})

	NodeProverRing = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_prover_ring",
		Help:      "Prover Ring value",
	}, []string{"node"})

	NodeSeniority = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_seniority",
		Help:      "Seniority value",
	}, []string{"node"})

	NodeClusterCoreWorkers = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_cluster_core_workers",
		Help:      "ClusterCore Workers value",
	}, []string{"node"})

	NodeActiveWorkers = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_active_workers",
		Help:      "Active Workers value",
	}, []string{"node"})
	NodeCalculateTime = prometheus.NewHistogramFrom(stdprome.HistogramOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_calculate_time",
		Help:      "Node Calculate Time",
		Buckets: []float64{
			0.1, // 捕获非常快的操作 (<100ms)
			0.5, // 500ms
			1,   // 1s
			2.5, // 2.5s
			5,   // 5s
			10,  // 10s
			20,  // 20s
			30,  // 30s
			45,  // 45s
			60,  // 1min
			90,  // 1.5min
			120, // 2min
			180, // 3min, 用于捕获异常情况
		},
	}, []string{"node"})

	NodeOwnedBalance = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_owned_balance_quil",
		Help:      "Owned balance in QUIL",
	}, []string{"node"})

	NodeMaxFrameIncrease = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_max_frame_increase",
		Help:      "Max Frame increase value, 0 or 1",
	}, []string{"node"})

	NodeBalanceIncrease = prometheus.NewGaugeFrom(stdprome.GaugeOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_balance_increase",
		Help:      "Node Balance Increase, 0 or 1",
	}, []string{"node"})

	NodeRequestCount = prometheus.NewCounterFrom(stdprome.CounterOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_request_count",
		Help:      "Node Request Count",
	}, []string{"node", "source", "method", "url"})
	NodeTaskRequestCount = prometheus.NewCounterFrom(stdprome.CounterOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_task_request_count",
		Help:      "Node Task Request Count",
	}, []string{"node", "source", "method"})
	NodeRequestDuration = prometheus.NewHistogramFrom(stdprome.HistogramOpts{
		Namespace: promNamespace,
		Subsystem: promSubsystem,
		Name:      "node_request_duration",
		Help:      "Node Request Duration",
		Buckets: []float64{
			1,      // 1微秒
			2,      // 2微秒
			5,      // 5微秒
			10,     // 10微秒
			25,     // 25微秒
			50,     // 50微秒
			100,    // 0.1ms
			500,    // 0.5ms
			1000,   // 1ms
			5000,   // 5ms
			10000,  // 10ms
			50000,  // 50ms
			75000,  // 75ms
			100000, // 100ms
			125000, // 125ms
			150000, // 150ms
			175000, // 175ms
			200000, // 200ms
			250000, // 250ms
			300000, // 300ms
			350000, // 350ms
			400000, // 400ms
			450000, // 450ms
			500000, // 500ms
		},
	}, []string{"node", "source", "method", "url"})
)
