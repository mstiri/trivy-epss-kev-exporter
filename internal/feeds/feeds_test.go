package feeds

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubSink struct {
	ok, fail int
	lastFeed string
}

func (s *stubSink) FeedRefreshSucceeded(feed string, _ time.Time) { s.ok++; s.lastFeed = feed }
func (s *stubSink) FeedRefreshFailed(feed string)                 { s.fail++; s.lastFeed = feed }

func TestRefresher_SweepsOnlyOnContentChange(t *testing.T) {
	ctx := context.Background()
	marker := [2]string{"v1", "d1"}
	var loadErr error
	applied, swept := 0, 0

	load := func(context.Context) (Result, error) {
		if loadErr != nil {
			return Result{}, loadErr
		}
		m := marker
		return Result{Marker: m, Apply: func() { applied++ }}, nil
	}
	sink := &stubSink{}
	r := NewRefresher("epss", time.Hour, load, func() { swept++ }, sink)

	// First load: no prior marker ⇒ changed ⇒ sweep.
	if changed, err := r.RefreshOnce(ctx); err != nil || !changed {
		t.Fatalf("first refresh: changed=%v err=%v, want true/nil", changed, err)
	}
	if applied != 1 || swept != 1 || sink.ok != 1 {
		t.Fatalf("after first: applied=%d swept=%d ok=%d, want 1/1/1", applied, swept, sink.ok)
	}

	// Same marker: data unchanged ⇒ snapshot still applied, but NO sweep.
	if changed, _ := r.RefreshOnce(ctx); changed {
		t.Error("unchanged marker should report changed=false")
	}
	if applied != 2 {
		t.Errorf("apply should still run on unchanged refresh: applied=%d, want 2", applied)
	}
	if swept != 1 {
		t.Errorf("unchanged refresh must not sweep: swept=%d, want 1", swept)
	}

	// Marker changes: content changed ⇒ sweep again.
	marker = [2]string{"v2", "d2"}
	if changed, _ := r.RefreshOnce(ctx); !changed {
		t.Error("changed marker should report changed=true")
	}
	if swept != 2 {
		t.Errorf("changed refresh should sweep: swept=%d, want 2", swept)
	}

	// Failure: record failure, keep last snapshot (apply not called), no sweep.
	loadErr = errors.New("boom")
	if changed, err := r.RefreshOnce(ctx); err == nil || changed {
		t.Errorf("failed refresh: changed=%v err=%v, want false/non-nil", changed, err)
	}
	if sink.fail != 1 {
		t.Errorf("failure not recorded: fail=%d, want 1", sink.fail)
	}
	if applied != 3 || swept != 2 {
		t.Errorf("failure must not apply or sweep: applied=%d swept=%d, want 3/2", applied, swept)
	}
}

func TestRefresher_NilOnChangeIsSafe(t *testing.T) {
	load := func(context.Context) (Result, error) {
		return Result{Marker: [2]string{"a", "b"}, Apply: func() {}}, nil
	}
	r := NewRefresher("kev", time.Hour, load, nil, &stubSink{})
	if _, err := r.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("RefreshOnce with nil onChange: %v", err)
	}
}
