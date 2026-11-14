package main

// forkHold performs fork and leaves the child blocked in pause entirely in
// assembly: a post-fork Go runtime may create threads and distort the pids test.
func forkHold() (pid int64, errno uintptr)
