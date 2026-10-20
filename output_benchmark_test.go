package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
)

type outputCounter struct {
	io.Writer
	writes, bytes int
}

func (w *outputCounter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.writes++
	w.bytes += n
	return n, err
}

// Compare the former synchronized, per-record output path with the bounded
// owner on identical dense results. /dev/null includes a real syscall; discard
// isolates encoding and synchronization. Full engine fixtures verify fields.
func BenchmarkJSONLOutput(b *testing.B) {
	const records = 10000
	result := Result{IP: "192.0.2.1", Target: "192.0.2.0/24", PTR: []string{"host.example.test"}}
	encoded, _ := json.Marshal(result)
	for _, sink := range []string{"discard", "devnull"} {
		for _, mode := range []string{"direct", "buffered"} {
			b.Run(sink+"/"+mode, func(b *testing.B) {
				var writer io.Writer = io.Discard
				if sink == "devnull" {
					file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
					if err != nil {
						b.Fatal(err)
					}
					defer file.Close()
					writer = file
				}
				counter := &outputCounter{Writer: writer}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					ctx, cancel := context.WithCancel(context.Background())
					var lock sync.Mutex
					emit := func(r Result) {
						line, err := json.Marshal(r)
						if err != nil {
							b.Error(err)
							return
						}
						lock.Lock()
						_, err = (checkedWriter{counter}).Write(append(line, '\n'))
						lock.Unlock()
						if err != nil {
							b.Error(err)
						}
					}
					var out *runOutput
					if mode == "buffered" {
						out = newRunOutput(ctx, counter, io.Discard, true, cancel)
						emit = out.emit
					}
					var producers sync.WaitGroup
					for worker := range 32 {
						producers.Go(func() {
							for index := worker; index < records; index += 32 {
								emit(result)
							}
						})
					}
					producers.Wait()
					if out != nil {
						if err := out.finish(); err != nil {
							b.Fatal(err)
						}
					}
					cancel()
				}
				b.StopTimer()
				if want := b.N * records * (len(encoded) + 1); counter.bytes != want {
					b.Fatalf("bytes=%d, want %d", counter.bytes, want)
				}
				b.ReportMetric(float64(records), "records/op")
				b.ReportMetric(float64(counter.writes)/float64(b.N), "writes/op")
				b.ReportMetric(float64(counter.bytes)/float64(b.N), "bytes/op")
				b.ReportMetric(1, "complete")
			})
		}
	}
}
