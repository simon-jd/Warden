package firecracker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

type Export struct {
	SHA256                                                         string
	NormalizedSHA256, NormalizationVersion, NormalizationPolicySHA string
	Omitted                                                        *OmittedHeader
	Files                                                          int
	Bytes                                                          int64
}

const NormalizationVersion = "warden-fc-docker-export-v1"
const normalizationPolicy = "warden-fc-docker-export-v1;omit-only:rawname=etc/mtab,type=symlink,target=/proc/mounts,size=0,mode=0777,uid=0,gid=0,pax=empty,xattrs=empty;all-entries-preflight-seen-ancestors;reject-other-links-specials;normalized=ordered-ustar-canonical-name-permission-mode-uid0-gid0-zero-time-data"

func NormalizationPolicySHA() string {
	sum := sha256.Sum256([]byte(normalizationPolicy))
	return hex.EncodeToString(sum[:])
}

type OmittedHeader struct {
	Name, Type, Target           string
	Size, Mode                   int64
	UID, GID, PAXRecords, Xattrs int
}

// ExtractRootFS accepts only the bounded owned fixed-probe export. One exact
// Docker-injected metadata link is recorded and omitted, never materialized. All
// headers are validated before writing. Archive uid/gid never become host IDs.
func ExtractRootFS(r io.Reader, destination string) (Export, error) {
	var out Export
	raw, e := io.ReadAll(io.LimitReader(r, 64*1024*1024+1))
	if e != nil {
		return out, e
	}
	if len(raw) > 64*1024*1024 {
		return out, errors.New("export exceeds 64MiB")
	}
	type entry struct {
		name      string
		mode      os.FileMode
		directory bool
		omit      bool
		data      []byte
	}
	var entries []entry
	seen := map[string]bool{}
	reader := tar.NewReader(bytes.NewReader(raw))
	for {
		h, e := reader.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, e
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "" && h.Typeflag == tar.TypeDir {
			name = "."
		}
		if seen[name] || len(seen) >= 512 || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00") || name == ".." || strings.HasPrefix(name, "../") || h.Mode&07000 != 0 || len(h.PAXRecords) > 0 || len(h.Xattrs) > 0 || h.Size < 0 {
			return out, errors.New("unsafe export metadata")
		}
		seen[name] = true
		if name == "etc/mtab" && h.Typeflag == tar.TypeSymlink {
			if h.Name != "etc/mtab" || h.Typeflag != tar.TypeSymlink || h.Linkname != "/proc/mounts" || h.Size != 0 || h.Mode != 0777 || h.Uid != 0 || h.Gid != 0 {
				return out, errors.New("unexpected Docker mtab metadata")
			}
			out.Omitted = &OmittedHeader{Name: h.Name, Type: "symlink", Target: h.Linkname, Size: h.Size, Mode: h.Mode, UID: h.Uid, GID: h.Gid}
			entries = append(entries, entry{name: name, omit: true})
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return out, errors.New("export links/devices/special files forbidden")
		}
		if h.Linkname != "" {
			return out, errors.New("link metadata on ordinary file forbidden")
		}
		if name == "." {
			if h.Typeflag != tar.TypeDir {
				return out, errors.New("invalid archive root")
			}
			continue
		}
		item := entry{name: name, mode: os.FileMode(h.Mode) & 0777, directory: h.Typeflag == tar.TypeDir}
		if !item.directory {
			out.Bytes += h.Size
			out.Files++
			if out.Bytes > 32*1024*1024 {
				return out, errors.New("expanded export exceeds 32MiB")
			}
			item.data, e = io.ReadAll(reader)
			if e != nil {
				return out, e
			}
		}
		entries = append(entries, item)
	}
	// A regular file cannot be another member's parent, regardless of order.
	for _, entry := range entries {
		for parent := path.Dir(entry.name); parent != "."; parent = path.Dir(parent) {
			for _, other := range entries {
				if other.name == parent && !other.directory {
					return out, errors.New("non-directory archive parent")
				}
			}
		}
	}
	// Hash the deterministic, link-free input represented by the fully checked
	// entries. Omitted metadata still participated in all collision checks above.
	var normalized bytes.Buffer
	tw := tar.NewWriter(&normalized)
	for _, item := range entries {
		if item.omit {
			continue
		}
		h := &tar.Header{Name: item.name, Mode: int64(item.mode), Typeflag: tar.TypeReg, Size: int64(len(item.data)), Format: tar.FormatUSTAR}
		if item.directory {
			h.Typeflag = tar.TypeDir
			h.Size = 0
		}
		if e := tw.WriteHeader(h); e != nil {
			return out, e
		}
		if _, e := tw.Write(item.data); e != nil {
			return out, e
		}
	}
	if e := tw.Close(); e != nil {
		return out, e
	}
	normalizedSum := sha256.Sum256(normalized.Bytes())
	out.NormalizedSHA256 = hex.EncodeToString(normalizedSum[:])
	out.NormalizationVersion = NormalizationVersion
	out.NormalizationPolicySHA = NormalizationPolicySHA()
	root, e := privateRoot(destination)
	if e != nil {
		return out, e
	}
	defer root.Close()
	d, e := root.Open(".")
	if e != nil {
		return out, e
	}
	items, e := d.ReadDir(-1)
	d.Close()
	if e != nil || len(items) != 0 {
		return out, errors.New("empty private extraction directory required")
	}
	for _, item := range entries {
		if item.omit {
			continue
		}
		if e = root.MkdirAll(path.Dir(item.name), 0755); e != nil {
			return out, e
		}
		if item.directory {
			if e = root.MkdirAll(item.name, 0755); e != nil {
				return out, e
			}
			continue
		}
		f, e := root.OpenFile(item.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return out, e
		}
		_, e = f.Write(item.data)
		e = errors.Join(e, f.Chmod(item.mode), f.Sync(), f.Close())
		if e != nil {
			return out, e
		}
	}
	// Implicit parent directories must be traversable by the nonroot payload.
	for _, item := range entries {
		if item.omit {
			continue
		}
		for p := path.Dir(item.name); p != "."; p = path.Dir(p) {
			if e = root.Chmod(p, 0755); e != nil {
				return out, e
			}
		}
		if item.directory {
			if e = root.Chmod(item.name, 0755); e != nil {
				return out, e
			}
		}
	}
	if e = syncRoot(root); e != nil {
		return out, e
	}
	sum := sha256.Sum256(raw)
	out.SHA256 = hex.EncodeToString(sum[:])
	return out, nil
}
