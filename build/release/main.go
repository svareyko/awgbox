// Command release builds sing-box for a list of targets and packages the
// results the way upstream's release does: one directory per target with the
// binary and LICENSE, a tar.gz (darwin, linux) or zip (windows) of it, and
// SHA256SUMS files. It uses only the standard library and the go toolchain.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	versionPackage = "github.com/sagernet/sing-box/constant.Version"
	defaultTargets = "darwin/arm64,darwin/amd64,windows/amd64,windows/arm64,linux/amd64"
	// length of "<sha256 hex>  " in a checksum line
	sumNameOffset = 66
)

type target struct {
	goos, goarch string
}

type result struct {
	target   target
	binary   string // path relative to the output directory, forward slashes
	archive  string // file name of the archive
	binSize  int64
	archSize int64
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
}

func run() error {
	version := flag.String("version", "", "version string embedded in the binary (required)")
	out := flag.String("out", "", "output directory (default dist/<version>)")
	targetsFlag := flag.String("targets", defaultTargets, "comma separated list of os/arch")
	goBin := flag.String("go", "go", "path to the go binary")
	flag.Parse()

	if *version == "" {
		return fmt.Errorf("-version is required")
	}
	if *out == "" {
		*out = filepath.Join("dist", *version)
	}
	outDir, err := filepath.Abs(*out)
	if err != nil {
		return err
	}

	var targets []target
	for _, item := range strings.Split(*targetsFlag, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("bad target %q, want os/arch", item)
		}
		targets = append(targets, target{parts[0], parts[1]})
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets")
	}

	tags, err := readTrimmed("release/DEFAULT_BUILD_TAGS_OTHERS")
	if err != nil {
		return err
	}
	extraLdflags, err := readTrimmed("release/LDFLAGS")
	if err != nil {
		return err
	}
	ldflags := fmt.Sprintf("-X '%s=%s' %s -s -w -buildid=", versionPackage, *version, extraLdflags)

	commitTime, err := headCommitTime()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	var results []result
	for _, t := range targets {
		r, err := buildTarget(*goBin, *version, outDir, t, tags, ldflags, commitTime)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", t.goos, t.goarch, err)
		}
		results = append(results, r)
	}

	var archiveSums, binarySums []string
	for _, r := range results {
		sum, err := fileSHA256(filepath.Join(outDir, r.archive))
		if err != nil {
			return err
		}
		archiveSums = append(archiveSums, sum+"  "+r.archive)
		sum, err = fileSHA256(filepath.Join(outDir, filepath.FromSlash(r.binary)))
		if err != nil {
			return err
		}
		binarySums = append(binarySums, sum+"  "+r.binary)
	}
	if err := writeSums(filepath.Join(outDir, "SHA256SUMS"), archiveSums); err != nil {
		return err
	}
	if err := writeSums(filepath.Join(outDir, "SHA256SUMS.binaries"), binarySums); err != nil {
		return err
	}

	fmt.Printf("\n%-16s %-52s %12s %12s\n", "target", "archive", "binary", "archive")
	for _, r := range results {
		fmt.Printf("%-16s %-52s %12d %12d\n", r.target.goos+"/"+r.target.goarch, r.archive, r.binSize, r.archSize)
	}
	fmt.Printf("\noutput: %s\n", outDir)
	return nil
}

func buildTarget(goBin, version, outDir string, t target, tags, ldflags string, commitTime time.Time) (result, error) {
	name := fmt.Sprintf("sing-box-%s-%s-%s", version, t.goos, t.goarch)
	dir := filepath.Join(outDir, name)
	// Start from a clean directory so stale files never end up in the archive.
	if err := os.RemoveAll(dir); err != nil {
		return result{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return result{}, err
	}

	binName := "sing-box"
	if t.goos == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(dir, binName)

	buildTags := tags
	if t.goos == "darwin" {
		// Same as upstream's .github/workflows/build.yml.
		buildTags = strings.ReplaceAll(buildTags, ",with_usbip", "")
	}

	fmt.Printf("== building %s/%s\n", t.goos, t.goarch)
	cmd := exec.Command(goBin, "build", "-v", "-trimpath",
		"-tags", buildTags,
		"-ldflags", ldflags,
		"-o", binPath,
		"./cmd/sing-box")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+t.goos,
		"GOARCH="+t.goarch,
		"GOTOOLCHAIN=local",
		"GOFLAGS=-mod=mod",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return result{}, fmt.Errorf("go build: %w", err)
	}

	licenseData, err := os.ReadFile("LICENSE")
	if err != nil {
		return result{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), licenseData, 0o644); err != nil {
		return result{}, err
	}
	binData, err := os.ReadFile(binPath)
	if err != nil {
		return result{}, err
	}

	files := []archiveFile{
		{name: name + "/" + binName, data: binData, mode: 0o755},
		{name: name + "/LICENSE", data: licenseData, mode: 0o644},
	}
	r := result{
		target:  t,
		binary:  name + "/" + binName,
		binSize: int64(len(binData)),
	}
	if t.goos == "windows" {
		// No wintun.dll goes into the zip: sing-tun embeds wintun 0.14.1 in the binary.
		r.archive = name + ".zip"
		err = writeZip(filepath.Join(outDir, r.archive), name, files, commitTime)
	} else {
		r.archive = name + ".tar.gz"
		err = writeTarGz(filepath.Join(outDir, r.archive), name, files, commitTime)
	}
	if err != nil {
		return result{}, err
	}
	st, err := os.Stat(filepath.Join(outDir, r.archive))
	if err != nil {
		return result{}, err
	}
	r.archSize = st.Size()
	return r, nil
}

type archiveFile struct {
	name string
	data []byte
	mode int64
}

func writeTarGz(path, dirName string, files []archiveFile, mtime time.Time) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	// The gzip header carries no name and a zero mtime, so rebuilds are identical.
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     dirName + "/",
		Mode:     0o755,
		ModTime:  mtime,
		Format:   tar.FormatPAX,
	}); err != nil {
		return err
	}
	for _, file := range files {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     file.name,
			Mode:     file.mode,
			Size:     int64(len(file.data)),
			ModTime:  mtime,
			Format:   tar.FormatPAX,
		}); err != nil {
			return err
		}
		if _, err := tw.Write(file.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func writeZip(path, dirName string, files []archiveFile, mtime time.Time) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	zw := zip.NewWriter(f)
	dirHeader := &zip.FileHeader{Name: dirName + "/", Method: zip.Store, Modified: mtime}
	dirHeader.SetMode(os.ModeDir | 0o755)
	if _, err := zw.CreateHeader(dirHeader); err != nil {
		return err
	}
	for _, file := range files {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate, Modified: mtime}
		header.SetMode(os.FileMode(file.mode))
		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := w.Write(file.data); err != nil {
			return err
		}
	}
	return zw.Close()
}

func readTrimmed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w (run from the repository root)", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func headCommitTime() (time.Time, error) {
	output, err := exec.Command("git", "log", "-1", "--format=%ct").Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("git log: %w", err)
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0).UTC(), nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeSums writes lines sorted by file name (the part after the hash) with LF endings.
func writeSums(path string, lines []string) error {
	sort.Slice(lines, func(i, j int) bool { return lines[i][sumNameOffset:] < lines[j][sumNameOffset:] })
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
