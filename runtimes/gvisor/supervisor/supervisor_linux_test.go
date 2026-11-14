package supervisor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"
)

// The payload's exit and the end of its exec status arrive together when
// the payload fails setup or runs only briefly. Whichever await sees first,
// the report must keep the status: a dropped setup error gave exit 126/127
// with no reason, a dropped EOF gave ExecUnixNano 0.
func TestAwaitKeepsTheExecStatusWhenTheExitIsReadyFirst(t *testing.T) {
	const runs = 200
	for i := 0; i < runs; i++ {
		done := make(chan error, 1)
		done <- nil
		var r Report
		if err := await(&r, strings.NewReader("setuid: operation not permitted"), done, nil, nil, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if r.Error != "payload setup: setuid: operation not permitted" {
			t.Fatalf("run %d of %d: setup error lost, report %+v", i+1, runs, r)
		}
	}
	for i := 0; i < runs; i++ {
		done := make(chan error, 1)
		done <- nil
		var r Report
		before := time.Now().UnixNano()
		if err := await(&r, strings.NewReader(""), done, nil, nil, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if r.Error != "" || r.ExecUnixNano < before || r.ExecUnixNano > time.Now().UnixNano() {
			t.Fatalf("run %d of %d: exec time lost, report %+v", i+1, runs, r)
		}
	}
}

// payload drops the bounding set (PR_CAPBSET_DROP) and the capability sets
// (capset), which are per thread, and then calls execve. The Go scheduler
// can move a goroutine to another thread between two calls, so the thread
// has to be locked before the first of them and stay locked, as the
// Firecracker guest's trampoline does (runtimes/firecracker/guest). The
// trampoline needs root, so the test checks the source.
func TestPayloadLocksItsThreadBeforeChangingCredentials(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "supervisor_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "payload" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("no func payload")
	}
	perThread := map[string]bool{"unix.Prctl": true, "unix.Capset": true, "syscall.Setgroups": true, "syscall.Setgid": true,
		"syscall.Setuid": true, "seccomp.Install": true, "unix.Exec": true}
	var lock, first token.Pos
	var firstName string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		name := pkg.Name + "." + sel.Sel.Name
		switch {
		case name == "runtime.LockOSThread" && lock == token.NoPos:
			lock = call.Pos()
		case name == "runtime.UnlockOSThread":
			t.Errorf("payload unlocks its thread")
		case perThread[name] && first == token.NoPos:
			first, firstName = call.Pos(), name
		}
		return true
	})
	if first == token.NoPos {
		t.Fatal("payload changes no credentials: the check is out of date")
	}
	if lock == token.NoPos || lock > first {
		t.Fatalf("payload calls %s before runtime.LockOSThread", firstName)
	}
}
