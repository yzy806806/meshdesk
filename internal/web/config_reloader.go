package web

import (
	"sync"

	"github.com/yzy806806/meshdesk/internal/config"
)

// ConfigReloader is implemented by subsystems that support hot-reloading
// of config changes. On reload, each registered reloader is called with
// the new config; it returns the list of field paths it applied, the
// list it rejected (with reason), and any errors.
//
// See CONFIG_API_DESIGN.md §5.1.
type ConfigReloader interface {
	// ReloadConfig applies config changes to this subsystem.
	// cfg is the new config loaded from disk.
	ReloadConfig(cfg *config.Config) (applied []string, rejected []string, errs []error)
}

// ReloaderRegistry manages the set of subsystem reloaders and tracks
// dirty state (fields changed on disk but not yet hot-reloaded).
type ReloaderRegistry struct {
	mu sync.Mutex

	// reloaders is the ordered list of registered subsystem reloaders.
	reloaders []ConfigReloader

	// dirtyHotReload tracks hot-reload fields that have been written to
	// disk but not yet applied via POST /api/config/reload.
	dirtyHotReload map[string]bool

	// dirtyRestart tracks restart-required fields that have been written
	// but not yet applied (pending process restart).
	dirtyRestart map[string]bool

	// lastReloadTime is when the last successful reload ran.
	lastReloadTime int64
}

// NewReloaderRegistry creates a new reloader registry.
func NewReloaderRegistry() *ReloaderRegistry {
	return &ReloaderRegistry{
		dirtyHotReload: make(map[string]bool),
		dirtyRestart:   make(map[string]bool),
	}
}

// Register adds a subsystem reloader to the registry.
func (r *ReloaderRegistry) Register(reloader ConfigReloader) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloaders = append(r.reloaders, reloader)
}

// MarkDirty records that a field has been modified on disk.
// The field's reload classification determines which dirty set it goes into.
func (r *ReloaderRegistry) MarkDirty(fieldPath string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tmpl := fieldPathToTemplate(fieldPath)
	meta, ok := tierMap[tmpl]
	if !ok {
		// Unknown field — treat as hot-reload by default.
		r.dirtyHotReload[fieldPath] = true
		return
	}
	if meta.Reload == ReloadRestart {
		r.dirtyRestart[fieldPath] = true
	} else {
		r.dirtyHotReload[fieldPath] = true
	}
}

// HasPendingRestart returns true if any restart-required field has been
// modified but not yet applied via process restart.
func (r *ReloaderRegistry) HasPendingRestart() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dirtyRestart) > 0
}

// HasPendingReload returns true if any hot-reload field has been modified
// but not yet applied via POST /api/config/reload.
func (r *ReloaderRegistry) HasPendingReload() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.dirtyHotReload) > 0
}

// DirtySinceReload returns the list of field paths modified since the
// last successful reload (both hot-reload and restart-required).
func (r *ReloaderRegistry) DirtySinceReload() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []string
	for f := range r.dirtyHotReload {
		result = append(result, f)
	}
	for f := range r.dirtyRestart {
		result = append(result, f)
	}
	return result
}

// PendingRestartFields returns only the restart-required dirty fields.
func (r *ReloaderRegistry) PendingRestartFields() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []string
	for f := range r.dirtyRestart {
		result = append(result, f)
	}
	return result
}

// Reload triggers all registered reloaders with the given config.
// Returns the applied, rejected, and error lists aggregated across all
// reloaders. After a successful reload, hot-reload dirty entries are cleared.
//
// If no hot-reload fields are dirty, the reload is a no-op and the
// response includes a "no changes pending" indicator.
func (r *ReloaderRegistry) Reload(cfg *config.Config) ReloadResult {
	r.mu.Lock()
	if len(r.dirtyHotReload) == 0 {
		r.mu.Unlock()
		return ReloadResult{
			OK:             true,
			Message:        "No changes pending — config is clean",
			PendingRestart: len(r.dirtyRestart) > 0,
		}
	}
	reloaders := make([]ConfigReloader, len(r.reloaders))
	copy(reloaders, r.reloaders)
	r.mu.Unlock()

	result := ReloadResult{
		OK: true,
	}

	for _, rl := range reloaders {
		applied, rejected, errs := rl.ReloadConfig(cfg)
		result.Applied = append(result.Applied, applied...)
		result.Rejected = append(result.Rejected, rejected...)
		result.Errors = append(result.Errors, errs...)
	}

	// Clear hot-reload dirty entries after successful reload.
	r.mu.Lock()
	r.dirtyHotReload = make(map[string]bool)
	r.mu.Unlock()

	result.PendingRestart = len(r.dirtyRestart) > 0
	if len(result.Errors) > 0 {
		// Don't mark as fully successful if there were errors.
		// But we still return what was applied.
	}

	return result
}

// ClearRestartDirty clears the restart dirty set after a successful restart.
func (r *ReloaderRegistry) ClearRestartDirty() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dirtyRestart = make(map[string]bool)
}

// ReloadResult holds the outcome of a POST /api/config/reload call.
type ReloadResult struct {
	OK              bool     `json:"ok"`
	Applied         []string `json:"applied"`
	RequiresRestart []string `json:"requires_restart"`
	Rejected        []string `json:"rejected_readonly,omitempty"`
	Errors          []error  `json:"-"`
	ErrorMsgs       []string `json:"errors,omitempty"`
	PendingRestart  bool     `json:"pending_restart"`
	Message         string   `json:"message,omitempty"`
}
