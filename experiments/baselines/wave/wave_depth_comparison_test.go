package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/stretchr/testify/require"
)

const waveCommit = "3b90ec17ea9dde89e995a9a46222a93df0f992d4"

type waveDepthResult struct {
	System       string  `json:"system"`
	SourceCommit string  `json:"source_commit"`
	Session      string  `json:"session"`
	Depth        int     `json:"depth"`
	Iterations   int     `json:"iterations"`
	Warmups      int     `json:"warmups"`
	ProofBytes   int     `json:"proof_bytes"`
	MeanMS       float64 `json:"mean_ms"`
	P50MS        float64 `json:"p50_ms"`
	P95MS        float64 `json:"p95_ms"`
	P99MS        float64 `json:"p99_ms"`
	MinMS        float64 `json:"min_ms"`
	MaxMS        float64 `json:"max_ms"`
}

type waveDepthSample struct {
	Session    string
	Depth      int
	Iteration  int
	LatencyNS  int64
	ProofBytes int
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		panic(fmt.Sprintf("%s must be a positive integer", name))
	}
	return value
}

func envString(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func buildLinearWaveProof(t *testing.T, depth int) []byte {
	t.Helper()
	tg := TG()
	source := "ns"
	for hop := 1; hop <= depth; hop++ {
		destination := fmt.Sprintf("depth_%d_hop_%d", depth, hop)
		tg.Edge(t, source, destination, "1", 100)
		source = destination
	}

	perspective := &pb.Perspective{
		EntitySecret: &pb.EntitySecret{DER: tg.secrets[source]},
		Location:     &inmem,
	}

	// Publication to the in-memory storage is asynchronous. This delay is
	// outside the measured verification path.
	time.Sleep(time.Second)
	resync, err := eapi.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: perspective,
	})
	require.NoError(t, err)
	require.Nil(t, resync.Error)
	require.NoError(t, eapi.WaitForSyncCompleteHack(&pb.SyncParams{Perspective: perspective}))

	proof, err := eapi.BuildRTreeProof(context.Background(), &pb.BuildRTreeProofParams{
		Perspective: perspective,
		SubjectHash: tg.pubs[source].Hash,
		Namespace:   tg.pubs["ns"].Hash,
		Statements: []*pb.RTreePolicyStatement{
			{
				PermissionSet: tg.pubs["ns"].Hash,
				Permissions:   []string{"1"},
				Resource:      "common/resource",
			},
		},
	})
	require.NoError(t, err)
	require.Nil(t, proof.Error)
	require.Len(t, proof.Result.Elements, depth)
	return proof.ProofDER
}

func verifyWaveProof(t *testing.T, proof []byte) {
	t.Helper()
	response, err := eapi.VerifyProof(context.Background(), &pb.VerifyProofParams{ProofDER: proof})
	require.NoError(t, err)
	require.Nil(t, response.Error)
}

func percentileNS(sorted []int64, percentile int) int64 {
	index := (percentile*len(sorted) + 99) / 100
	if index < 1 {
		index = 1
	}
	return sorted[index-1]
}

func summarizeWaveDepth(session string, depth, iterations, warmups, proofBytes int, samples []int64) waveDepthResult {
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var total int64
	for _, sample := range sorted {
		total += sample
	}
	toMS := func(ns int64) float64 { return float64(ns) / float64(time.Millisecond) }
	return waveDepthResult{
		System:       "WAVE",
		SourceCommit: waveCommit,
		Session:      session,
		Depth:        depth,
		Iterations:   iterations,
		Warmups:      warmups,
		ProofBytes:   proofBytes,
		MeanMS:       toMS(total) / float64(len(sorted)),
		P50MS:        toMS(percentileNS(sorted, 50)),
		P95MS:        toMS(percentileNS(sorted, 95)),
		P99MS:        toMS(percentileNS(sorted, 99)),
		MinMS:        toMS(sorted[0]),
		MaxMS:        toMS(sorted[len(sorted)-1]),
	}
}

func writeWaveRaw(path string, samples []waveDepthSample) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{
		"session", "system", "source_commit", "depth", "iteration",
		"accepted", "latency_ms", "proof_bytes",
	}); err != nil {
		file.Close()
		return err
	}
	for _, sample := range samples {
		latencyMS := float64(sample.LatencyNS) / float64(time.Millisecond)
		if err := writer.Write([]string{
			sample.Session,
			"WAVE",
			waveCommit,
			strconv.Itoa(sample.Depth),
			strconv.Itoa(sample.Iteration),
			"true",
			strconv.FormatFloat(latencyMS, 'f', 9, 64),
			strconv.Itoa(sample.ProofBytes),
		}); err != nil {
			file.Close()
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func TestWaveDepthComparison(t *testing.T) {
	runtime.GOMAXPROCS(1)
	iterations := envInt("WAVE_ITERATIONS", 100)
	warmups := envInt("WAVE_WARMUPS", 5)
	session := envString("WAVE_SESSION", "01")
	depths := []int{1, 2, 3, 5, 10}
	results := make([]waveDepthResult, 0, len(depths))
	rawSamples := make([]waveDepthSample, 0, len(depths)*iterations)

	for _, depth := range depths {
		proof := buildLinearWaveProof(t, depth)
		for warmup := 0; warmup < warmups; warmup++ {
			verifyWaveProof(t, proof)
		}

		samples := make([]int64, 0, iterations)
		for iteration := 1; iteration <= iterations; iteration++ {
			started := time.Now()
			verifyWaveProof(t, proof)
			latencyNS := time.Since(started).Nanoseconds()
			samples = append(samples, latencyNS)
			rawSamples = append(rawSamples, waveDepthSample{
				Session:    session,
				Depth:      depth,
				Iteration:  iteration,
				LatencyNS:  latencyNS,
				ProofBytes: len(proof),
			})
		}
		result := summarizeWaveDepth(session, depth, iterations, warmups, len(proof), samples)
		results = append(results, result)
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		fmt.Printf("WAVE_DEPTH_RESULT %s\n", encoded)
	}

	if outputPath := os.Getenv("WAVE_RESULTS_PATH"); outputPath != "" {
		encoded, err := json.MarshalIndent(results, "", "  ")
		require.NoError(t, err)
		require.NoError(t, ioutil.WriteFile(outputPath, append(encoded, '\n'), 0644))
	}
	if rawPath := os.Getenv("WAVE_RAW_PATH"); rawPath != "" {
		require.NoError(t, writeWaveRaw(rawPath, rawSamples))
	}
}
