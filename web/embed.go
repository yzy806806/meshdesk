// Package webembed provides embedded frontend assets for MeshDesk.
//
// This file lives in the web/ directory at the project root so that go:embed
// patterns can reference the templates/ and static/ subdirectories directly.
// The internal/web package imports these embedded filesystems.
//
// Per ARCHITECTURE.md Decision D: all frontend assets are compiled into the
// binary at build time via go:embed — zero external HTTP requests at runtime.
package webembed

import (
	"embed"
	"io/fs"
)

//go:embed all:templates
var templateFS embed.FS

//go:embed all:static
var staticFS embed.FS

// Templates returns the embedded template filesystem rooted at templates/.
func Templates() (fs.FS, error) {
	return fs.Sub(templateFS, "templates")
}

// Static returns the embedded static asset filesystem rooted at static/.
func Static() (fs.FS, error) {
	return fs.Sub(staticFS, "static")
}
