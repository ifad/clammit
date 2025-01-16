package metrics

import (
	"log"
	"sync"
	"time"

	"github.com/DataDog/datadog-go/v5/statsd"
)

type Metrics struct {
	FilesFailedToProcess int `json:"files_failed_to_process"`
	TotalFilesScanned    int `json:"total_files_scanned"`
	TotalVirusesFound    int `json:"total_viruses_found"`
}

var (
	metrics      Metrics
	mu           sync.Mutex
	durations    []time.Duration
	statsdClient *statsd.Client
)

func InitStatsdClient(address, namespace string, tags []string, log *log.Logger) {
	if address == "" {
		log.Println("StatsD address not provided, skipping initialization")
		return
	}
	var err error
	statsdClient, err = statsd.New(address, statsd.WithNamespace(namespace), statsd.WithTags(tags))
	if err != nil {
		log.Println("Failed to initialize StatsD client:", err)
		return
	}
	log.Println("StatsD client initialized successfully with tags:", tags)
}

func CloseStatsdClient(log *log.Logger) {
	if statsdClient != nil {
		statsdClient.Close()
		log.Println("StatsD client closed successfully")
	}
}

func UpdateMetrics(duration time.Duration, failed bool, fileCount int, virusesFound int, log *log.Logger) {
	mu.Lock()
	defer mu.Unlock()

	// Consider the total duration for multipart files as a single entry
	if fileCount > 1 {
		durations = append(durations, duration)
	} else {
		for i := 0; i < fileCount; i++ {
			durations = append(durations, duration/time.Duration(fileCount))
		}
	}
	metrics.TotalFilesScanned += fileCount
	metrics.TotalVirusesFound += virusesFound

	if failed {
		metrics.FilesFailedToProcess++
	}
	sendMetricsToDatadog(duration, fileCount, virusesFound, log)
}

func sendMetricsToDatadog(duration time.Duration, fileCount int, virusesFound int, log *log.Logger) {
	if statsdClient == nil {
		log.Println("StatsD client not initialized, skipping metrics sending")
		return
	}
	statsdClient.Histogram("scan.response_time", float64(duration/time.Millisecond), nil, 1)
	statsdClient.Count("scan.failed", int64(metrics.FilesFailedToProcess), nil, 1)
	statsdClient.Count("scan.processed", int64(fileCount), nil, 1)
	statsdClient.Count("scan.viruses_found", int64(virusesFound), nil, 1)
}
