package scheduler

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"warden/runtimes"
)

// Break caught: the timeout receiver exits before the snapshot is published,
// leaving its late reader and collection goroutine without a cleanup owner.
func TestLateSnapshotPublicationClosesReaderAndCollectorExits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &lateSnapshotReader{closed: make(chan struct{}), reading: make(chan struct{}), readExited: make(chan struct{})}
		release := make(chan struct{})
		handle := lateSnapshotHandle{reader: reader, release: release}
		worker := Scheduler{OperationTimeout: time.Second}
		returned := make(chan struct{})
		go func() {
			logs, err := worker.collect(handle, runtimes.Exit{CgroupEmpty: true})
			if !errors.Is(err, context.DeadlineExceeded) || logs.Status != "lost" {
				t.Errorf("timeout logs=%+v err=%v", logs, err)
			}
			close(returned)
		}()
		// The synctest clock advances only once both the blocked reader publication
		// and collector wait are idle. No sleeps or probabilistic race are involved.
		<-returned
		close(release)
		synctest.Wait()
		select {
		case <-reader.closed:
		default:
			t.Error("late snapshot reader has no cleanup owner")
		}
		select {
		case <-reader.reading:
			select {
			case <-reader.readExited:
			default:
				t.Error("late snapshot read goroutine is still blocked")
			}
		default: // Closing a late snapshot without reading it is also correct.
		}
		// Release a failing pre-fix implementation so RED does not itself leak.
		_ = reader.Close()
		synctest.Wait()
		// synctest.Test cannot finish with an abandoned blocked collection goroutine.
	})
}

type lateSnapshotHandle struct {
	reader  io.ReadCloser
	release <-chan struct{}
}

func (h lateSnapshotHandle) Logs() io.ReadCloser                       { <-h.release; return h.reader }
func (lateSnapshotHandle) Wait(context.Context) (runtimes.Exit, error) { return runtimes.Exit{}, nil }
func (lateSnapshotHandle) Kill() error                                 { return nil }

type lateSnapshotReader struct {
	closed, reading, readExited chan struct{}
	closeOnce                   sync.Once
}

func (r *lateSnapshotReader) Read([]byte) (int, error) {
	close(r.reading)
	<-r.closed
	close(r.readExited)
	return 0, io.ErrClosedPipe
}
func (r *lateSnapshotReader) Close() error { r.closeOnce.Do(func() { close(r.closed) }); return nil }
