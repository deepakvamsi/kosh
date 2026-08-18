// Package seal enforces Kosh's network air-seal at build/test time.
//
// Kosh must make no network connections and expose no listener. This is a design
// invariant, not a runtime toggle. The test in this package walks the dependency graph
// of the whole module and fails if any first-party (kosh/...) package imports a
// forbidden networking package. That way the air-seal cannot regress silently: adding
// an import like net/http anywhere in internal/... or cmd/... breaks CI.
//
// We intentionally allow the platform sys packages (golang.org/x/sys) and the pure-Go
// SQLite driver, neither of which performs network I/O in our usage.
package seal

// ForbiddenImports lists package import paths that would break the air-seal if any
// first-party package depended on them. Kept here so the list is easy to review.
var ForbiddenImports = []string{
	"net/http",
	"net/rpc",
	"net/smtp",
	"net/http/httptest",
	"golang.org/x/net/http2",
}

// ForbiddenPrefixes catches whole families (e.g. gRPC, websocket clients).
var ForbiddenPrefixes = []string{
	"google.golang.org/grpc",
	"github.com/gorilla/websocket",
	"nhooyr.io/websocket",
}
