package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/fix"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/cmd"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/scan"
	"github.com/google/osv-scanner/v2/cmd/osv-scanner/update"
)

func withPrefix(str string) string {
	prefix := "1"

	return fmt.Sprintf("scanner-%s-%s", prefix, str)
}

func run() int {
	f, err := os.Create(withPrefix("cpuprofile.prof"))
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f.Close() // error handling omitted for example
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	r := cmd.Run(os.Args, os.Stdout, os.Stderr, []cmd.CommandBuilder{
		scan.Command,
		fix.Command,
		update.Command,
	})

	f, err = os.Create(withPrefix("memprofile.prof"))
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
