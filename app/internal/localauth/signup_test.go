package localauth

import (
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-querystring/query"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	appauth "sourcegraph.com/sourcegraph/sourcegraph/app/auth"
	"sourcegraph.com/sourcegraph/sourcegraph/app/internal/apptest"
	"sourcegraph.com/sourcegraph/sourcegraph/app/router"
	"sourcegraph.com/sourcegraph/sourcegraph/go-sourcegraph/sourcegraph"
)

func TestSignUp_form(t *testing.T) {
	c, _ := apptest.New()

	if _, err := c.GetOK(router.Rel.URLTo(router.SignUp).String()); err != nil {
		t.Fatal(err)
	}
}

func TestSignUp_submit(t *testing.T) {
	c, mock := apptest.New()

	frm := sourcegraph.NewAccount{Login: "u", Email: "a@a.com", Password: "password"}
	data, err := query.Values(frm)
	if err != nil {
		t.Fatal(err)
	}

	var calledAccountsCreate bool
	mock.Accounts.Create_ = func(ctx context.Context, op *sourcegraph.NewAccount) (*sourcegraph.UserSpec, error) {
		if !reflect.DeepEqual(*op, frm) {
			t.Errorf("got form == %+v, want %+v", op, frm)
		}
		calledAccountsCreate = true
		return &sourcegraph.UserSpec{UID: 123, Login: op.Login}, nil
	}
	var calledAuthGetAccessToken bool
	mock.Auth.GetAccessToken_ = func(ctx context.Context, op *sourcegraph.AccessTokenRequest) (*sourcegraph.AccessTokenResponse, error) {
		resOwnerPassword := op.GetResourceOwnerPassword()
		if resOwnerPassword == nil {
			t.Errorf("got empty ResourceOwnerPassword")
		} else {
			if resOwnerPassword.Login != frm.Login {
				t.Errorf("got login == %q, want %q", resOwnerPassword.Login, frm.Login)
			}
			if resOwnerPassword.Password != frm.Password {
				t.Errorf("got password == %q, want %q", resOwnerPassword.Password, frm.Password)
			}
		}
		calledAuthGetAccessToken = true
		return &sourcegraph.AccessTokenResponse{AccessToken: "k"}, nil
	}

	resp, err := c.PostFormNoFollowRedirects(router.Rel.URLTo(router.SignUp).String(), data)
	if err != nil {
		t.Fatal(err)
	}

	// Check redirected to user page.
	if want := http.StatusSeeOther; resp.StatusCode != want {
		t.Errorf("got HTTP %d, want %d", resp.StatusCode, want)
	}
	if want, got := "/", resp.Header.Get("location"); got != want {
		t.Errorf("got Location %q, want %q", got, want)
	}

	// Check that user session cookie is set.
	cookie, err := appauth.ReadSessionCookieFromResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if want := (&appauth.Session{AccessToken: "k"}); !reflect.DeepEqual(cookie, want) {
		t.Errorf("got cookie %+v, want %+v", cookie, want)
	}

	if !calledAccountsCreate {
		t.Error("!calledAccountsCreate")
	}
	if !calledAuthGetAccessToken {
		t.Error("!calledAuthGetAccessToken")
	}
}

func TestSignUp_loginAlreadyExists(t *testing.T) {
	c, mock := apptest.New()

	frm := sourcegraph.NewAccount{Login: "u", Email: "a@a.com", Password: "password"}
	data, err := query.Values(frm)
	if err != nil {
		t.Fatal(err)
	}

	var calledAccountsCreate bool
	mock.Accounts.Create_ = func(ctx context.Context, op *sourcegraph.NewAccount) (*sourcegraph.UserSpec, error) {
		calledAccountsCreate = true
		return nil, grpc.Errorf(codes.AlreadyExists, "account %q already exists", op.Login)
	}

	resp, err := c.PostFormNoFollowRedirects(router.Rel.URLTo(router.SignUp).String(), data)
	if err != nil {
		t.Fatal(err)
	}

	// Check that signup form is re-rendered.
	if want := http.StatusOK; resp.StatusCode != want {
		t.Errorf("got HTTP %d, want %d", resp.StatusCode, want)
	}

	// Check that user session cookie is NOT set.
	if _, err := appauth.ReadSessionCookieFromResponse(resp); err != appauth.ErrNoSession {
		t.Fatalf("got err %v, want ErrNoSession", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(body), formErrorUsernameAlreadyTaken) {
		t.Error("form error not found")
	}

	if !calledAccountsCreate {
		t.Error("!calledAccountsCreate")
	}
}

func TestSignUp_emailAlreadyExists(t *testing.T) {
	c, mock := apptest.New()

	frm := sourcegraph.NewAccount{Login: "u", Email: "a@a.com", Password: "password"}
	data, err := query.Values(frm)
	if err != nil {
		t.Fatal(err)
	}

	var calledAccountsCreate bool
	mock.Accounts.Create_ = func(ctx context.Context, op *sourcegraph.NewAccount) (*sourcegraph.UserSpec, error) {
		calledAccountsCreate = true
		return nil, grpc.Errorf(codes.AlreadyExists, "primary email already associated with a user: %v", op.Email)
	}

	resp, err := c.PostFormNoFollowRedirects(router.Rel.URLTo(router.SignUp).String(), data)
	if err != nil {
		t.Fatal(err)
	}

	// Check that signup form is re-rendered.
	if want := http.StatusOK; resp.StatusCode != want {
		t.Errorf("got HTTP %d, want %d", resp.StatusCode, want)
	}

	// Check that user session cookie is NOT set.
	if _, err := appauth.ReadSessionCookieFromResponse(resp); err != appauth.ErrNoSession {
		t.Fatalf("got err %v, want ErrNoSession", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(body), formErrorEmailAlreadyTaken) {
		t.Error("form error not found")
	}

	if !calledAccountsCreate {
		t.Error("!calledAccountsCreate")
	}
}
