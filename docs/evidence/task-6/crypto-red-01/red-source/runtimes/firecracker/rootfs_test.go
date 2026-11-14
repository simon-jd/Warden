package firecracker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func archive(t *testing.T, headers []*tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, h := range headers {
		if e := w.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			w.Write(bytes.Repeat([]byte{'x'}, int(h.Size)))
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

// Catches caching/extracting bytes other than the exact digest-bound export.
func TestRootFSExportProvenance(t *testing.T) {
	raw := archive(t, []*tar.Header{{Name: "./", Typeflag: tar.TypeDir, Mode: 0755}, {Name: "warden-probe", Typeflag: tar.TypeReg, Mode: 0755, Size: 3}, {Name: "write-probe", Typeflag: tar.TypeReg, Mode: 0666, Size: 1}})
	p := private(t)
	out, e := ExtractRootFS(bytes.NewReader(raw), p)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if out.SHA256 != hex.EncodeToString(sum[:]) || out.Files != 2 || out.Bytes != 4 {
		t.Fatalf("provenance %+v", out)
	}
	b, e := os.ReadFile(filepath.Join(p, "warden-probe"))
	if e != nil || string(b) != "xxx" {
		t.Fatalf("extraction %q %v", b, e)
	}
	st, e := os.Stat(filepath.Join(p, "write-probe"))
	if e != nil || st.Mode().Perm() != 0666 {
		t.Fatalf("probe mode lost: %v %v", st, e)
	}
}

// Catches archive escapes, aliases, devices and privilege bits before any write.
func TestRootFSRejectsUnsafeExportWithoutPartialWrites(t *testing.T) {
	for _, bad := range []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg}, {Name: "/escape", Typeflag: tar.TypeReg},
		{Name: "alias", Typeflag: tar.TypeSymlink, Linkname: "/tmp"}, {Name: "alias", Typeflag: tar.TypeLink, Linkname: "good"},
		{Name: "dev", Typeflag: tar.TypeChar, Devmajor: 10, Devminor: 232}, {Name: "fifo", Typeflag: tar.TypeFifo},
		{Name: "suid", Typeflag: tar.TypeReg, Mode: 04755}, {Name: "good", Typeflag: tar.TypeReg},
		{Name: "a/../escape", Typeflag: tar.TypeReg},
	} {
		t.Run(bad.Name, func(t *testing.T) {
			p := private(t)
			raw := archive(t, []*tar.Header{{Name: "good", Typeflag: tar.TypeReg, Size: 1}, bad})
			if _, e := ExtractRootFS(bytes.NewReader(raw), p); e == nil {
				t.Fatal("unsafe export accepted")
			}
			items, e := os.ReadDir(p)
			if e != nil || len(items) != 0 {
				t.Fatalf("partial extraction %v %v", items, e)
			}
		})
	}
}
func TestRootFSRejectsOversizedStream(t *testing.T) {
	p := private(t)
	raw := archive(t, []*tar.Header{{Name: "probe", Typeflag: tar.TypeReg}})
	if _, e := ExtractRootFS(bytes.NewReader(append(raw, make([]byte, 64*1024*1024)...)), p); e == nil {
		t.Fatal("unbounded tar trailing data accepted")
	}
}

func dockerMtab() *tar.Header {
	return &tar.Header{Name: "etc/mtab", Typeflag: tar.TypeSymlink, Linkname: "/proc/mounts", Mode: 0777}
}
func TestDockerMtabOmittedWithoutCreatingAlias(t *testing.T) {
	raw := archive(t, []*tar.Header{{Name: "warden-probe", Typeflag: tar.TypeReg, Size: 3, Mode: 0555}, dockerMtab()})
	p := private(t)
	out, e := ExtractRootFS(bytes.NewReader(raw), p)
	if e != nil {
		t.Fatal(e)
	}
	if out.Files != 1 || out.Bytes != 3 {
		t.Fatalf("omission counted as payload: %+v", out)
	}
	expected := archive(t, []*tar.Header{{Name: "warden-probe", Typeflag: tar.TypeReg, Size: 3, Mode: 0555, Format: tar.FormatUSTAR}})
	normalized := sha256.Sum256(expected)
	rawHash := sha256.Sum256(raw)
	if out.SHA256 != hex.EncodeToString(rawHash[:]) || out.NormalizedSHA256 != hex.EncodeToString(normalized[:]) || out.NormalizedSHA256 == out.SHA256 || out.NormalizationVersion != NormalizationVersion || out.NormalizationPolicySHA != NormalizationPolicySHA() || out.Omitted == nil || out.Omitted.Name != "etc/mtab" || out.Omitted.UID != 0 || out.Omitted.GID != 0 {
		t.Fatalf("normalization provenance not bound: %+v", out)
	}
	if _, e = os.Lstat(filepath.Join(p, "etc/mtab")); !os.IsNotExist(e) {
		t.Fatalf("alias created: %v", e)
	}
	b, e := os.ReadFile(filepath.Join(p, "warden-probe"))
	if e != nil || string(b) != "xxx" {
		t.Fatalf("payload changed %q %v", b, e)
	}
}
func TestDockerMtabRejectsChangedMetadataAndCollisionsBeforeWrites(t *testing.T) {
	mutations := map[string]func(*tar.Header){
		"target":    func(h *tar.Header) { h.Linkname = "/etc/passwd" },
		"path":      func(h *tar.Header) { h.Name = "other" },
		"dot_alias": func(h *tar.Header) { h.Name = "./etc/mtab" },
		"traversal": func(h *tar.Header) { h.Name = "etc/x/../mtab" },
		"type":      func(h *tar.Header) { h.Typeflag = tar.TypeLink },
		"mode":      func(h *tar.Header) { h.Mode = 0755 },
		"uid":       func(h *tar.Header) { h.Uid = 1 },
		"gid":       func(h *tar.Header) { h.Gid = 1 },
		"pax":       func(h *tar.Header) { h.PAXRecords = map[string]string{"comment": "unexpected"} },
		"xattr":     func(h *tar.Header) { h.Xattrs = map[string]string{"user.test": "unexpected"} },
	}
	cases := map[string][]*tar.Header{}
	for name, mutate := range mutations {
		h := dockerMtab()
		mutate(h)
		cases[name] = []*tar.Header{h}
	}
	cases["duplicate"] = []*tar.Header{dockerMtab(), dockerMtab()}
	cases["regular_after"] = []*tar.Header{dockerMtab(), {Name: "etc/mtab", Typeflag: tar.TypeReg}}
	cases["alias_after"] = []*tar.Header{dockerMtab(), {Name: "./etc/mtab", Typeflag: tar.TypeReg}}
	cases["parent_before"] = []*tar.Header{{Name: "etc", Typeflag: tar.TypeReg}, dockerMtab()}
	cases["parent_after"] = []*tar.Header{dockerMtab(), {Name: "etc", Typeflag: tar.TypeReg}}
	cases["child"] = []*tar.Header{dockerMtab(), {Name: "etc/mtab/child", Typeflag: tar.TypeReg}}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			p := private(t)
			raw := archive(t, append([]*tar.Header{{Name: "good", Typeflag: tar.TypeReg, Size: 1}}, headers...))
			if _, e := ExtractRootFS(bytes.NewReader(raw), p); e == nil {
				t.Fatal("changed metadata accepted")
			}
			items, e := os.ReadDir(p)
			if e != nil || len(items) != 0 {
				t.Fatalf("partial extraction: %v %v", items, e)
			}
		})
	}
}

func TestDockerMtabRejectsNonzeroSizeBeforeWrites(t *testing.T) {
	raw := archive(t, []*tar.Header{dockerMtab()})
	copy(raw[124:136], []byte("00000000001\x00"))
	for i := 148; i < 156; i++ {
		raw[i] = ' '
	}
	sum := 0
	for _, b := range raw[:512] {
		sum += int(b)
	}
	copy(raw[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
	p := private(t)
	if _, e := ExtractRootFS(bytes.NewReader(raw), p); e == nil {
		t.Fatal("nonzero-size omitted entry accepted")
	}
	entries, e := os.ReadDir(p)
	if e != nil || len(entries) != 0 {
		t.Fatalf("partial writes: %v %v", entries, e)
	}
}
func TestDockerMtabParticipatesInHeaderCount(t *testing.T) {
	headers := []*tar.Header{dockerMtab()}
	for i := 0; i < 512; i++ {
		headers = append(headers, &tar.Header{Name: fmt.Sprintf("file%d", i), Typeflag: tar.TypeReg})
	}
	p := private(t)
	if _, e := ExtractRootFS(bytes.NewReader(archive(t, headers)), p); e == nil {
		t.Fatal("omission evaded entry count")
	}
	entries, e := os.ReadDir(p)
	if e != nil || len(entries) != 0 {
		t.Fatalf("partial writes: %v %v", entries, e)
	}
}

func TestOrdinaryMtabFileIsKeptAndNeverOmitted(t *testing.T) {
	raw := archive(t, []*tar.Header{{Name: "etc/mtab", Typeflag: tar.TypeReg, Size: 3, Mode: 0644}})
	p := private(t)
	out, e := ExtractRootFS(bytes.NewReader(raw), p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(p, "etc/mtab"))
	if e != nil || string(b) != "xxx" || out.Files != 1 || out.Bytes != 3 || out.Omitted != nil {
		t.Fatalf("ordinary file lost or mislabeled: %+v %q %v", out, b, e)
	}
}
