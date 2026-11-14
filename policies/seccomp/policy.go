// Package seccomp embeds the reviewed fail-closed syscall allowlist.
package seccomp

import _ "embed"

//go:embed default.json
var Default []byte
