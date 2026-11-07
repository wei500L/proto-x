package cover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testSite(t *testing.T) (*Site, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"index.html":     "<!doctype html><title>Notebook</title><p>Public notes.</p>\n",
		"note.txt":       "0123456789abcdef",
		"sub/index.html": "<!doctype html><title>Archive</title>\n",
	} {
		name = filepath.Join(root, name)
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(name, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	site, err := NewSite(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := site.Close(); err != nil {
			t.Error(err)
		}
	})
	return site, root
}

func siteResponse(handler http.Handler, method, target string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Header = headers.Clone()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestSiteStandardHTTPBehavior(t *testing.T) {
	site, _ := testSite(t)
	cases := []struct {
		name, method, path string
		headers            http.Header
		status             int
		body               string
		checkBody          bool
		responseHeaders    http.Header
	}{
		{"index", "GET", "/", nil, 200, "<!doctype html><title>Notebook</title><p>Public notes.</p>\n", true, nil},
		{"head", "HEAD", "/note.txt", nil, 200, "", true, http.Header{"Content-Length": {"16"}}},
		{"missing", "GET", "/absent.txt", nil, 404, "404 page not found\n", true, nil},
		{"index-redirect", "GET", "/index.html", nil, 301, "", false, http.Header{"Location": {"./"}}},
		{"directory-redirect", "GET", "/sub", nil, 301, "", false, http.Header{"Location": {"sub/"}}},
		{"range", "GET", "/note.txt", http.Header{"Range": {"bytes=3-6"}}, 206, "3456", true, http.Header{"Content-Range": {"bytes 3-6/16"}}},
		{"conditional", "GET", "/note.txt", http.Header{"If-Modified-Since": {"Thu, 01 Jan 2026 00:00:00 GMT"}}, 304, "", true, nil},
		{"post", "POST", testPath, nil, 405, "Method Not Allowed\n", true, http.Header{"Allow": {"GET, HEAD"}}},
		{"options", "OPTIONS", "/", nil, 405, "Method Not Allowed\n", true, http.Header{"Allow": {"GET, HEAD"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := siteResponse(site, tc.method, tc.path, tc.headers)
			if w.Code != tc.status {
				t.Fatalf("status=%d, want %d", w.Code, tc.status)
			}
			if tc.checkBody && w.Body.String() != tc.body {
				t.Fatalf("body=%q, want %q", w.Body.String(), tc.body)
			}
			for key, values := range tc.responseHeaders {
				if !reflect.DeepEqual(w.Header().Values(key), values) {
					t.Fatalf("%s=%v, want %v", key, w.Header().Values(key), values)
				}
			}
			if w.Header().Get("WWW-Authenticate") != "" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("static site exposed an authentication challenge or session cookie")
			}
		})
	}
}

func TestSiteConfinesPathAndSymlinkResolution(t *testing.T) {
	site, root := testSite(t)
	outside := t.TempDir()
	const secret = "outside-secret-must-not-be-served"
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"escape.txt":          filepath.Join(outside, "secret.txt"),
		"escape-dir":          outside,
		"relative-escape.txt": filepath.Join("..", filepath.Base(outside), "secret.txt"),
		"note-link.txt":       "note.txt",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/../secret.txt", "/../../secret.txt", "/%2e%2e/secret.txt", "/escape.txt", "/escape-dir/secret.txt", "/relative-escape.txt"} {
		w := siteResponse(site, http.MethodGet, path, nil)
		if w.Code < 400 || strings.Contains(w.Body.String(), secret) {
			t.Fatalf("outside path %q exposed content: status=%d", path, w.Code)
		}
	}
	w := siteResponse(site, http.MethodGet, "/note-link.txt", nil)
	if w.Code != 200 || w.Body.String() != "0123456789abcdef" {
		t.Fatal("confinement incorrectly rejected a symlink inside the public tree")
	}
}

func TestSiteRejectsInvalidRoots(t *testing.T) {
	for _, root := range []string{"", filepath.Join(t.TempDir(), "absent")} {
		if site, err := NewSite(root); err == nil {
			site.Close()
			t.Fatal("accepted invalid site root")
		}
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("regular file"), 0600); err != nil {
		t.Fatal(err)
	}
	if site, err := NewSite(file); err == nil {
		site.Close()
		t.Fatal("accepted a regular file as the site root")
	}
}

func TestRejectedAuthenticationMatchesOrdinarySite(t *testing.T) {
	client, server := tlsPair(t)
	_, otherServer := tlsPair(t)
	site, _ := testSite(t)
	g := newTestGate(t, Config{})
	var sessions atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Authorize(r) {
			site.ServeHTTP(w, r)
			return
		}
		sessions.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	valid := serverRequest(signedRequest(t, g, &client), &server)
	admitted := httptest.NewRecorder()
	handler.ServeHTTP(admitted, valid)
	if admitted.Code != http.StatusNoContent || sessions.Load() != 1 {
		t.Fatal("valid authentication did not dispatch exactly one session")
	}
	cases := []struct {
		name string
		edit func(*http.Request)
	}{
		{"no-auth", func(r *http.Request) { r.Header.Del(AuthorizationHeader) }},
		{"wrong-auth", func(r *http.Request) { changePayload(t, r, func(p []byte) { p[25] ^= 1 }) }},
		{"replay", func(*http.Request) {}},
		{"other-connection", func(r *http.Request) { r.TLS = &otherServer }},
		{"other-path-post", func(r *http.Request) { r.URL.Path = "/missing"; r.RequestURI = r.URL.RequestURI() }},
		{"public-index-get", func(r *http.Request) { r.Method = "GET"; r.URL.Path = "/"; r.RequestURI = r.URL.RequestURI() }},
		{"public-file-head", func(r *http.Request) { r.Method = "HEAD"; r.URL.Path = "/note.txt"; r.RequestURI = r.URL.RequestURI() }},
		{"public-range", func(r *http.Request) {
			r.Method = "GET"
			r.URL.Path = "/note.txt"
			r.RequestURI = r.URL.RequestURI()
			r.Header.Set("Range", "bytes=0-3")
		}},
		{"wrong-method", func(r *http.Request) { r.Method = "OPTIONS" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid.Clone(context.Background())
			tc.edit(r)
			got, ordinary := httptest.NewRecorder(), httptest.NewRecorder()
			handler.ServeHTTP(got, r.Clone(context.Background()))
			site.ServeHTTP(ordinary, r.Clone(context.Background()))
			if got.Code != ordinary.Code || got.Body.String() != ordinary.Body.String() || !reflect.DeepEqual(got.Header(), ordinary.Header()) {
				t.Fatalf("fallback differs from site: status %d/%d, headers %v/%v, body %q/%q", got.Code, ordinary.Code, got.Header(), ordinary.Header(), got.Body.String(), ordinary.Body.String())
			}
			if sessions.Load() != 1 || len(g.nonces) != 1 {
				t.Fatal("negative authentication created session or replay state")
			}
		})
	}
}
