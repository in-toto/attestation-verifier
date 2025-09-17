package probes

import (
	"context"
	"os"
	"path/filepath"
)

type Store interface {
	Put(ctx context.Context, key string, value []byte) error
}

type FileStore struct {
	rootDir string
}

func NewFileStore(rootDir string) *FileStore {
	return &FileStore{rootDir: rootDir}
}

func (fs *FileStore) Put(ctx context.Context, filename string, value []byte) error {
	return os.WriteFile(filepath.Join(fs.rootDir, filename), value, 0644)
}
