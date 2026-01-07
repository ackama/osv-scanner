package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"time"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/mcp"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
)

var startTime = time.Now()

func withPrefix(str string) string {
	return fmt.Sprintf("scanner-%s-%s", startTime.Format("20060102-150405"), str)
}

func run() int {
	// make a trace
	f, _ := os.Create(withPrefix("trace.out"))
	trace.Start(f)
	defer trace.Stop()

	f, err := os.Create(withPrefix("cpuprofile.prof"))
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f.Close() // error handling omitted for example
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	// Open CSV file for writing
	f2, err := os.Create(withPrefix("memstats.csv"))
	if err != nil {
		panic(err)
	}
	defer f2.Close()

	writer := csv.NewWriter(f2)
	defer writer.Flush()

	// Write header row
	writer.Write([]string{"time_ms", "alloc_bytes", "total_alloc_bytes", "sys_bytes", "num_gc"})

	// Start background sampler
	start := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond) // sample every 100ms
	defer ticker.Stop()

	done := make(chan struct{})

	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-ticker.C:
				runtime.ReadMemStats(&m)
				elapsed := time.Since(start).Milliseconds()
				record := []string{
					fmt.Sprint(elapsed),
					fmt.Sprint(m.Alloc),      // currently allocated heap
					fmt.Sprint(m.TotalAlloc), // cumulative allocations
					fmt.Sprint(m.Sys),        // memory obtained from system
					fmt.Sprint(m.NumGC),      // number of GCs
				}
				writer.Write(record)
				writer.Flush()
			case <-done:
				return
			}
		}
	}()

	r := cmd.Run(os.Args, os.Stdout, os.Stderr, nil, []cmd.CommandBuilder{
		scan.Command,
		fix.Command,
		update.Command,
		mcp.Command,
	})

	close(done)

	f, err = os.Create(withPrefix(withPrefix("memprofile.prof")))
	if err != nil {
		log.Fatal("could not create memory profile: ", err)
	}
	defer f.Close() // error handling omitted for example
	runtime.GC()    // get up-to-date statistics
	// Lookup("allocs") creates a profile similar to go test -memprofile.
	// Alternatively, use Lookup("heap") for a profile
	// that has inuse_space as the default index.
	if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
		log.Fatal("could not write memory profile: ", err)
	}

	return r
}

func main() {
	os.Exit(run())
}
