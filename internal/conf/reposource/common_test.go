package reposource

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
)

// urlToRepoName represents a cloneURL and expected corresponding repo name
type urlToRepoName struct {
	cloneURL string
	repoName string
}

// urlToRepoNameErr is similar to urlToRepoName, but with an expected error value
type urlToRepoNameErr struct {
	cloneURL string
	repoName string
	err      error
}

func TestParseCloneURL(t *testing.T) {
	tests := []struct {
		input  string
		output *url.URL
	}{
		{
			input: "git@github.com:gorilla/mux.git",
			output: &url.URL{
				Scheme: "",
				User:   url.User("git"),
				Host:   "github.com",
				Path:   "gorilla/mux.git",
			},
		}, {
			input: "git+https://github.com/gorilla/mux.git",
			output: &url.URL{
				Scheme: "git+https",
				Host:   "github.com",
				Path:   "/gorilla/mux.git",
			},
		}, {
			input: "https://github.com/gorilla/mux.git",
			output: &url.URL{
				Scheme: "https",
				Host:   "github.com",
				Path:   "/gorilla/mux.git",
			},
		}, {
			input: "https://github.com/gorilla/mux",
			output: &url.URL{
				Scheme: "https",
				Host:   "github.com",
				Path:   "/gorilla/mux",
			},
		}, {
			input: "ssh://git@github.com/gorilla/mux",
			output: &url.URL{
				Scheme: "ssh",
				User:   url.User("git"),
				Host:   "github.com",
				Path:   "/gorilla/mux",
			},
		}, {
			input: "ssh://github.com/gorilla/mux.git",
			output: &url.URL{
				Scheme: "ssh",
				Host:   "github.com",
				Path:   "/gorilla/mux.git",
			},
		}, {
			input: "ssh://git@github.com:/my/repo.git",
			output: &url.URL{
				Scheme: "ssh",
				User:   url.User("git"),
				Host:   "github.com:",
				Path:   "/my/repo.git",
			},
		}, {
			input: "git://git@github.com:/my/repo.git",
			output: &url.URL{
				Scheme: "git",
				User:   url.User("git"),
				Host:   "github.com:",
				Path:   "/my/repo.git",
			},
		}, {
			input: "user@host.xz:/path/to/repo.git/",
			output: &url.URL{
				User: url.User("user"),
				Host: "host.xz",
				Path: "/path/to/repo.git/",
			},
		}, {
			input: "host.xz:/path/to/repo.git/",
			output: &url.URL{
				Host: "host.xz",
				Path: "/path/to/repo.git/",
			},
		}, {
			input: "ssh://user@host.xz:1234/path/to/repo.git/",
			output: &url.URL{
				Scheme: "ssh",
				User:   url.User("user"),
				Host:   "host.xz:1234",
				Path:   "/path/to/repo.git/",
			},
		}, {
			input: "host.xz:~user/path/to/repo.git/",
			output: &url.URL{
				Host: "host.xz",
				Path: "~user/path/to/repo.git/",
			},
		}, {
			input: "ssh://host.xz/~/path/to/repo.git",
			output: &url.URL{
				Scheme: "ssh",
				Host:   "host.xz",
				Path:   "/~/path/to/repo.git",
			},
		}, {
			input: "git://host.xz/~user/path/to/repo.git/",
			output: &url.URL{
				Scheme: "git",
				Host:   "host.xz",
				Path:   "/~user/path/to/repo.git/",
			},
		}, {
			input: "file:///path/to/repo.git/",
			output: &url.URL{
				Scheme: "file",
				Path:   "/path/to/repo.git/",
			},
		}, {
			input: "file://~/path/to/repo.git/",
			output: &url.URL{
				Scheme: "file",
				Host:   "~",
				Path:   "/path/to/repo.git/",
			},
		},
	}
	for _, test := range tests {
		out, err := parseCloneURL(test.input)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(test.output, out) {
			got, _ := json.MarshalIndent(out, "", "  ")
			exp, _ := json.MarshalIndent(test.output, "", "  ")
			t.Errorf("for input %s, expected %s, but got %s", test.input, string(exp), string(got))
		}
	}
}

func TestNameTransformations(t *testing.T) {
	opts := []NameTransformationOptions{
		{
			Regex:       `\.d/`,
			Replacement: "/",
		},
		{
			Regex:       "-git$",
			Replacement: "",
		},
	}

	nts := make([]NameTransformation, len(opts))
	for i, opt := range opts {
		nt, err := NewNameTransformation(opt)
		if err != nil {
			t.Fatalf("NewNameTransformation: %v", err)
		}
		nts[i] = nt
	}

	tests := []struct {
		input  string
		output string
	}{
		{"path/to.d/repo-git", "path/to/repo"},
		{"path/to.d/repo-git.git", "path/to/repo-git.git"},
		{"path/to.de/repo-git.git", "path/to.de/repo-git.git"},
	}
	for _, test := range tests {
		got := NameTransformations(nts).Transform(test.input)
		if test.output != got {
			t.Errorf("for input %s, expected %s, but got %s", test.input, test.output, got)
		}
	}
}
