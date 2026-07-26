package xray

import (
	"encoding/json"
	"os"
	"path/filepath"

	"log"
)

// FileConfigStore is a file-based implementation of ConfigStore.
// It persists inbound and outbound configs as JSON files.
type FileConfigStore struct {
	inboundsPath  string
	outboundsPath string
}

// NewFileConfigStore creates a file-based config store.
// The state is stored in <dir>/inbounds.json and <dir>/outbounds.json.
func NewFileConfigStore(path string) *FileConfigStore {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	// If path is like "state.json", use state-inbounds.json and state-outbounds.json
	// Otherwise, derive from the path
	inboundsPath := filepath.Join(dir, "inbounds.json")
	outboundsPath := filepath.Join(dir, "outbounds.json")
	if base != "" && base != "." {
		// Use the base name to create derived filenames
		ext := filepath.Ext(base)
		name := base[:len(base)-len(ext)]
		if ext == "" {
			name = base
		}
		inboundsPath = filepath.Join(dir, name+"-inbounds.json")
		outboundsPath = filepath.Join(dir, name+"-outbounds.json")
	}
	return &FileConfigStore{
		inboundsPath:  inboundsPath,
		outboundsPath: outboundsPath,
	}
}

// SaveInbounds persists inbound configs to a JSON file.
func (s *FileConfigStore) SaveInbounds(inbounds map[string]*InboundConfig) error {
	return s.saveMap(s.inboundsPath, inbounds)
}

// LoadInbounds loads inbound configs from the JSON file.
// Returns an empty map if the file does not exist.
func (s *FileConfigStore) LoadInbounds() (map[string]*InboundConfig, error) {
	result := make(map[string]*InboundConfig)
	if err := s.loadMap(s.inboundsPath, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SaveOutbounds persists outbound configs to a JSON file.
func (s *FileConfigStore) SaveOutbounds(outbounds map[string]*OutboundConfig) error {
	return s.saveMap(s.outboundsPath, outbounds)
}

// LoadOutbounds loads outbound configs from the JSON file.
func (s *FileConfigStore) LoadOutbounds() (map[string]*OutboundConfig, error) {
	result := make(map[string]*OutboundConfig)
	if err := s.loadMap(s.outboundsPath, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// saveMap writes a map as JSON to the given path.
func (s *FileConfigStore) saveMap(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// loadMap reads JSON from the given path into v.
// Returns nil (and leaves v as-is) if the file does not exist.
func (s *FileConfigStore) loadMap(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		log.Printf("[xray] warning: failed to parse %s: %v", path, err)
		return nil
	}
	return nil
}
