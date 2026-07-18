package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	backupManifestName   = "enshrouded-backup-manifest.json"
	backupManifestSchema = 1
)

type backupManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	CreatedAt     time.Time            `json:"createdAt"`
	GameBuild     string               `json:"gameBuild,omitempty"`
	Files         []backupManifestFile `json:"files"`
}

type backupManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func createSnapshotStage(saveDir string, configFiles map[string]string, gameBuild string, now time.Time) (string, error) {
	parent := filepath.Dir(filepath.Clean(saveDir))
	stageDir, err := os.MkdirTemp(parent, ".enshrouded-backup-stage-")
	if err != nil {
		return "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stageDir)
		}
	}()

	if err := copyTree(saveDir, filepath.Join(stageDir, "savegame")); err != nil {
		return "", fmt.Errorf("snapshot savegame: %w", err)
	}
	for archiveName, sourcePath := range configFiles {
		if strings.TrimSpace(sourcePath) == "" {
			continue
		}
		info, err := os.Stat(sourcePath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("snapshot config %s: %w", archiveName, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("snapshot config %s is not a regular file", archiveName)
		}
		target := filepath.Join(stageDir, "config", filepath.Base(archiveName))
		if err := copyRegularFile(sourcePath, target, info.Mode().Perm()); err != nil {
			return "", fmt.Errorf("snapshot config %s: %w", archiveName, err)
		}
	}

	manifest, err := buildBackupManifest(stageDir, gameBuild, now)
	if err != nil {
		return "", err
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	manifestData = append(manifestData, '\n')
	if err := os.WriteFile(filepath.Join(stageDir, backupManifestName), manifestData, 0o600); err != nil {
		return "", err
	}

	cleanup = false
	return stageDir, nil
}

func buildBackupManifest(root, gameBuild string, now time.Time) (*backupManifest, error) {
	manifest := &backupManifest{
		SchemaVersion: backupManifestSchema,
		CreatedAt:     now.UTC(),
		GameBuild:     strings.TrimSpace(gameBuild),
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root || info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported snapshot entry %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == backupManifestName {
			return nil
		}
		sum, err := sha256File(path)
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, backupManifestFile{Path: rel, Size: info.Size(), SHA256: sum})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	if len(manifest.Files) == 0 {
		return nil, errors.New("snapshot contains no files")
	}
	return manifest, nil
}

func verifyBackupManifest(root string) (*backupManifest, bool, error) {
	manifestPath := filepath.Join(root, backupManifestName)
	raw, err := os.ReadFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	var manifest backupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, true, fmt.Errorf("invalid backup manifest: %w", err)
	}
	if manifest.SchemaVersion != backupManifestSchema {
		return nil, true, fmt.Errorf("unsupported backup manifest schema %d", manifest.SchemaVersion)
	}
	if len(manifest.Files) == 0 {
		return nil, true, errors.New("backup manifest contains no files")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, entry := range manifest.Files {
		name, ok := cleanArchivePath(entry.Path)
		if !ok || filepath.ToSlash(name) != entry.Path {
			return nil, true, fmt.Errorf("invalid manifest path %q", entry.Path)
		}
		if _, exists := seen[entry.Path]; exists {
			return nil, true, fmt.Errorf("duplicate manifest path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		path := filepath.Join(root, filepath.FromSlash(entry.Path))
		if !pathWithinBase(root, path) {
			return nil, true, fmt.Errorf("manifest path escapes backup root: %q", entry.Path)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, true, fmt.Errorf("manifest file %q: %w", entry.Path, err)
		}
		if !info.Mode().IsRegular() || info.Size() != entry.Size {
			return nil, true, fmt.Errorf("manifest size mismatch for %q", entry.Path)
		}
		sum, err := sha256File(path)
		if err != nil {
			return nil, true, err
		}
		if !strings.EqualFold(sum, entry.SHA256) {
			return nil, true, fmt.Errorf("manifest checksum mismatch for %q", entry.Path)
		}
	}
	return &manifest, true, nil
}

func restorePayload(root string) (saveDir string, configDir string, manifest *backupManifest, err error) {
	manifest, hasManifest, err := verifyBackupManifest(root)
	if err != nil {
		return "", "", nil, err
	}
	if hasManifest {
		saveDir = filepath.Join(root, "savegame")
		configDir = filepath.Join(root, "config")
	} else {
		saveDir = root
	}
	if err := validateSaveDirectory(saveDir); err != nil {
		return "", "", nil, err
	}
	return saveDir, configDir, manifest, nil
}

func validateSaveDirectory(saveDir string) error {
	info, err := os.Stat(saveDir)
	if err != nil {
		return fmt.Errorf("save directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("save payload is not a directory")
	}
	regularFiles := 0
	err = filepath.Walk(saveDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.Size() > 0 {
			regularFiles++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if regularFiles == 0 {
		return errors.New("save payload contains no non-empty files")
	}
	for _, pair := range [][2]string{{"3ad85aea", "3ad85aea-index"}, {"characters", "characters-index"}} {
		left := regularFileExists(filepath.Join(saveDir, pair[0]))
		right := regularFileExists(filepath.Join(saveDir, pair[1]))
		if left != right {
			return fmt.Errorf("save payload has incomplete %s pair", pair[0])
		}
	}
	return nil
}

func copyTree(source, target string) error {
	rootInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() {
		return errors.New("source is not a directory")
	}
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		dest := target
		if rel != "." {
			dest = filepath.Join(target, rel)
		}
		switch {
		case info.IsDir():
			return os.MkdirAll(dest, info.Mode().Perm())
		case info.Mode().IsRegular():
			return copyRegularFile(path, dest, info.Mode().Perm())
		default:
			return fmt.Errorf("unsupported file type in save directory: %s", path)
		}
	})
}

func copyRegularFile(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
	if err != nil {
		return err
	}
	copyErr := error(nil)
	if _, err := io.Copy(out, in); err != nil {
		copyErr = err
	}
	if err := out.Sync(); copyErr == nil && err != nil {
		copyErr = err
	}
	if err := out.Close(); copyErr == nil && err != nil {
		copyErr = err
	}
	return copyErr
}

func sha256File(path string) (string, error) {
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

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func pathWithinBase(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

var steamBuildPattern = regexp.MustCompile(`(?m)"buildid"\s+"([^"]+)"`)

func readSteamBuild(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	match := steamBuildPattern.FindSubmatch(raw)
	if len(match) != 2 {
		return ""
	}
	return string(match[1])
}
