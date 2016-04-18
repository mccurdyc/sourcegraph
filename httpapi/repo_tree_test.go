package httpapi

import (
	"net/http"
	"reflect"
	"testing"

	"sourcegraph.com/sourcegraph/sourcegraph/go-sourcegraph/sourcegraph"
)

func TestRepoTree(t *testing.T) {
	c, mock := newTest()

	want := &sourcegraph.TreeEntry{
		BasicTreeEntry: &sourcegraph.BasicTreeEntry{
			Name:     "f",
			Type:     sourcegraph.FileEntry,
			Contents: []byte("c"),
		},
	}

	calledGet := mock.RepoTree.MockGet_Return_NoCheck(t, want)
	calledGetSrclibDataVersionForPath := mock.Repos.MockGetSrclibDataVersionForPath_Current(t)

	var entry *sourcegraph.TreeEntry
	if err := c.GetJSON("/repos/r/-/tree/f", &entry); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entry, want) {
		t.Errorf("got %+v, want %+v", entry, want)
	}
	if !*calledGet {
		t.Error("!calledGet")
	}
	if !*calledGetSrclibDataVersionForPath {
		t.Error("!calledGetSrclibDataVersionForPath")
	}
}

func TestRepoTree_notFound(t *testing.T) {
	c, mock := newTest()

	calledGet := mock.RepoTree.MockGet_NotFound(t)
	calledGetSrclibDataVersionForPath := mock.Repos.MockGetSrclibDataVersionForPath_Current(t)

	resp, err := c.Get("/repos/r/-/tree/f")
	if err != nil {
		t.Fatal(err)
	}
	if want := http.StatusNotFound; resp.StatusCode != want {
		t.Errorf("got HTTP %d, want %d", resp.StatusCode, want)
	}
	if !*calledGet {
		t.Error("!calledGet")
	}
	if !*calledGetSrclibDataVersionForPath {
		t.Error("!calledGetSrclibDataVersionForPath")
	}
}
