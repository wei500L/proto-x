package cover

import (
	"errors"
	"net/http"
	"os"
)

// Site serves a configured tree of public files using Go's normal file-server
// behavior. It contains no authentication route, challenge, or proxy metadata.
// Use the same Site as the fallback and as an ordinary-server control.
type Site struct {
	root    *os.Root
	handler http.Handler
}

// NewSite opens a directory root that confines symlink and path resolution on
// the supported Linux/macOS deployments. Put only public regular files and
// directories in this root; it is not a sandbox for hostile local filesystems,
// bind mounts, device nodes, or a directory containing private configuration.
func NewSite(root string) (*Site, error) {
	if root == "" {
		return nil, errors.New("a public static site directory is required")
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	return &Site{root: r, handler: http.FileServerFS(r.FS())}, nil
}

// Close releases the root directory handle. Stop the HTTP server before Close.
func (s *Site) Close() error { return s.root.Close() }

func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	s.handler.ServeHTTP(w, r)
}
