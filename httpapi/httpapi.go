package httpapi

import (
	"log"
	"net/http"

	"gopkg.in/inconshreveable/log15.v2"

	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"sourcegraph.com/sourcegraph/csp"
	"sourcegraph.com/sourcegraph/sourcegraph/conf"
	httpapiauth "sourcegraph.com/sourcegraph/sourcegraph/httpapi/auth"
	apirouter "sourcegraph.com/sourcegraph/sourcegraph/httpapi/router"
	"sourcegraph.com/sourcegraph/sourcegraph/util/eventsutil"
	"sourcegraph.com/sourcegraph/sourcegraph/util/handlerutil"
	"sourcegraph.com/sourcegraph/sourcegraph/util/metricutil"
)

// NewHandler returns a new API handler that uses the provided API
// router, which must have been created by httpapi/router.New, or
// creates a new one if nil.
func NewHandler(m *mux.Router) http.Handler {
	if m == nil {
		m = apirouter.New(nil)
	}
	m.StrictSlash(true)

	// SECURITY NOTE: The HTTP API should not accept cookies as
	// authentication. Doing so would open it up to CSRF
	// attacks. By requiring users use HTTP Basic authentication,
	// we mitigate the risk of CSRF.
	var mw []handlerutil.Middleware
	mw = append(mw, httpapiauth.PasswordMiddleware, httpapiauth.OAuth2AccessTokenMiddleware)
	if !metricutil.DisableMetricsCollection() {
		mw = append(mw, eventsutil.AgentMiddleware)
		mw = append(mw, eventsutil.DeviceIdMiddleware)
	}

	if conf.GetenvBool("SG_USE_CSP") {
		// Set the CSP handler. Determine the report URI by seeing what
		// path prefix m currently has (if it was just /.csp-report, then
		// it'd never match, since this handler is usually mounted at
		// /.api/).
		reportURI, err := m.Path(cspConfig.Policy.ReportURI).URLPath()
		if err != nil {
			panic(err.Error())
		}
		cspConfig.Policy.ReportURI = reportURI.String()
		cspHandler := csp.NewHandler(cspConfig)
		mw = append(mw, cspHandler.ServeHTTP)
	}

	// Set handlers for the installed routes.
	m.Get(apirouter.Annotations).Handler(handler(serveAnnotations))
	m.Get(apirouter.BlackHole).Handler(handler(serveBlackHole))
	m.Get(apirouter.Build).Handler(handler(serveBuild))
	m.Get(apirouter.Builds).Handler(handler(serveBuilds))
	m.Get(apirouter.Def).Handler(handler(serveDef))
	m.Get(apirouter.DefRefs).Handler(handler(serveDefRefs))
	m.Get(apirouter.Defs).Handler(handler(serveDefs))
	m.Get(apirouter.Repo).Handler(handler(serveRepo))
	m.Get(apirouter.RepoBranches).Handler(handler(serveRepoBranches))
	m.Get(apirouter.RepoCommits).Handler(handler(serveRepoCommits))
	m.Get(apirouter.RepoTree).Handler(handler(serveRepoTree))
	m.Get(apirouter.RepoTreeList).Handler(handler(serveRepoTreeList))
	m.Get(apirouter.RepoTreeSearch).Handler(handler(serveRepoTreeSearch))
	m.Get(apirouter.RepoBuildTasks).Handler(handler(serveBuildTasks))
	m.Get(apirouter.RepoBuildsCreate).Handler(handler(serveRepoBuildsCreate))
	m.Get(apirouter.RepoTags).Handler(handler(serveRepoTags))
	m.Get(apirouter.Repos).Handler(handler(serveRepos))
	m.Get(apirouter.SrclibImport).Handler(handler(serveSrclibImport))
	m.Get(apirouter.SrclibCoverage).Handler(handler(serveCoverage))
	m.Get(apirouter.SrclibDataVer).Handler(handler(serveSrclibDataVersion))

	m.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("API no route: %s %s from %s", r.Method, r.URL, r.Referer())
		http.Error(w, "no route", http.StatusNotFound)
	})

	return handlerutil.WithMiddleware(m, mw...)
}

// handler is a wrapper func for API handlers.
func handler(h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return handlerutil.HandlerWithErrorReturn{
		Handler: h,
		Error:   handleError,
	}
}

// cspConfig is the Content Security Policy config for API handlers.
var cspConfig = csp.Config{
	// Strict because API responses should never be treated as page
	// content.
	Policy: &csp.Policy{DefaultSrc: []string{"'none'"}, ReportURI: "/.csp-report"},
}

var schemaDecoder = schema.NewDecoder()

func handleError(w http.ResponseWriter, r *http.Request, status int, err error) {
	// Handle custom errors
	if ee, ok := err.(*handlerutil.URLMovedError); ok {
		err := handlerutil.RedirectToNewRepoURI(w, r, ee.NewURL)
		if err != nil {
			log.Printf("error redirecting to new URI (%s)", err)
		}
		return
	}

	// Never cache error responses.
	w.Header().Set("cache-control", "no-cache, max-age=0")

	errBody := err.Error()

	var displayErrBody string
	if handlerutil.DebugMode(r) {
		// Only display error message to admins or locally, since it
		// can contain sensitive info (like API keys in net/http error
		// messages).
		displayErrBody = string(errBody)
	}
	http.Error(w, displayErrBody, status)
	if status < 200 || status >= 500 {
		log15.Error("API HTTP handler error response", "method", r.Method, "request_uri", r.URL.RequestURI(), "status_code", status, "error", err)
	}
}
