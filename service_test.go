package security

import (
	"github.com/dottics/dutil"
	"github.com/johannesscr/micro/microtest"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestNewService(t *testing.T) {
	// Test without a token
	s1 := NewService("")
	x11 := s1.Header.Get("X-User-Token")
	if x11 != "" {
		t.Errorf("expected '%v' got '%v'", "", x11)
	}
	x12 := s1.Header.Get("Content-Type")
	if x12 != "application/json" {
		t.Errorf("expected '%v' got '%v'", "application/json", x12)
	}

	// Test with a token
	s2 := NewService("my secret token")
	x21 := s2.Header.Get("X-User-Token")
	if x21 != "my secret token" {
		t.Errorf("expected '%v' got '%v'", "my secret token", x21)
	}
	x22 := s2.Header.Get("Content-Type")
	if x22 != "application/json" {
		t.Errorf("expected '%v' got '%v'", "application/json", x22)
	}
}

func TestNewService_2(t *testing.T) {
	err := os.Setenv("SECURITY_SERVICE_SCHEME", "https")
	if err != nil {
		log.Println(err)
	}
	err = os.Setenv("SECURITY_SERVICE_HOST", "test.dottics.com")
	if err != nil {
		log.Println(err)
	}

	// Test without a token
	s1 := NewService("")
	if s1.URL.Scheme != "https" {
		t.Errorf("expected '%v' got '%v'", "https", s1.URL.Scheme)
	}
	if s1.URL.Host != "test.dottics.com" {
		t.Errorf("expected '%v' got '%v'", "test.dottics.com", s1.URL.Scheme)
	}
	x11 := s1.Header.Get("X-User-Token")
	if x11 != "" {
		t.Errorf("expected '%v' got '%v'", "", x11)
	}
	x12 := s1.Header.Get("Content-Type")
	if x12 != "application/json" {
		t.Errorf("expected '%v' got '%v'", "application/json", x12)
	}

	// Test with a token
	s2 := NewService("my secret token")
	if s2.URL.Scheme != "https" {
		t.Errorf("expected '%v' got '%v'", "https", s2.URL.Scheme)
	}
	if s2.URL.Host != "test.dottics.com" {
		t.Errorf("expected '%v' got '%v'", "test.dottics.com", s2.URL.Scheme)
	}

	x21 := s2.Header.Get("X-User-Token")
	if x21 != "my secret token" {
		t.Errorf("expected '%v' got '%v'", "my secret token", x21)
	}
	x22 := s2.Header.Get("Content-Type")
	if x22 != "application/json" {
		t.Errorf("expected '%v' got '%v'", "application/json", x22)
	}
}

func TestService_SetURL(t *testing.T) {
	s := Service{}
	if s.URL.Scheme != "" {
		t.Errorf("expected '%v' got '%v'", "", s.URL.Scheme)
	}
	if s.URL.Host != "" {
		t.Errorf("expected '%v' got '%v'", "", s.URL.Host)
	}

	s.SetURL("https", "test.dottics.com")
	if s.URL.Scheme != "https" {
		t.Errorf("expected '%v' got '%v'", "https", s.URL.Scheme)
	}
	if s.URL.Host != "test.dottics.com" {
		t.Errorf("expected '%v' got '%v'", "test.dottics.com", s.URL.Host)
	}
}

func TestService_SetEnv(t *testing.T) {
	s := Service{
		URL: url.URL{
			Scheme: "http",
			Host:   "test.dottics.com",
		},
	}
	err := s.SetEnv()
	if err != nil {
		t.Errorf("unexpected error: %v", err.Error())
	}

	x1 := os.Getenv("SECURITY_SERVICE_SCHEME")
	if x1 != s.URL.Scheme {
		t.Errorf("expected '%v' got '%v'", s.URL.Scheme, x1)
	}
	x2 := os.Getenv("SECURITY_SERVICE_HOST")
	if x2 != s.URL.Host {
		t.Errorf("expected '%v' got '%v'", s.URL.Host, x2)
	}
}

// TestService_NewRequest is to test that the service can make a
// successful request to the micro-service.
func TestService_NewRequest(t *testing.T) {
	// test the request is made to the service
	s := NewService("my test token")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	ex := &microtest.Exchange{
		Response: microtest.Response{
			Status: 200,
		},
	}
	ms.Append(ex)

	s.URL.Path = "/my/path"
	q := url.Values{}
	q.Add("u", "test-value")
	s.URL.RawQuery = q.Encode()

	h := map[string][]string{
		"X-Random": {"my content"},
	}
	b := strings.NewReader("{\"name\":\"james\"}")

	_, e := s.NewRequest("PUT", s.URL.String(), h, b)
	if e != nil {
		t.Errorf("unexpected error: %v", e)
	}
	// now test the actual request was generated correctly
	if ex.Request.URL.Path != "/my/path" {
		t.Errorf("expected '%v' got '%v'", "/my/path", ex.Request.URL.Path)
	}
	// test query params
	if ex.Request.URL.RawQuery != s.URL.RawQuery {
		t.Errorf("expected '%v' got '%v'", s.URL.RawQuery, ex.Request.URL.RawQuery)
	}
	// test headers
	h1 := ex.Request.Header.Get("Content-Type")
	h2 := ex.Request.Header.Get("X-Random")
	h3 := ex.Request.Header.Get("X-User-Token")
	if h1 != "application/json" {
		t.Errorf("expected '%v' got '%v'", "application/json", h1)
	}
	if h2 != "my content" {
		t.Errorf("expected '%v' got '%v'", "my content", h2)
	}
	if h3 != "my test token" {
		t.Errorf("expected '%v' got '%v'", "my test token", h3)
	}
	// test the body
	//xb, err := ioutil.ReadAll(ex.Request.Body)
	//sb := string(xb)
	//if err != nil {
	//	t.Errorf("unexpected error: %v", err)
	//}
	//if sb != "{\"name\":\"james\"}" {
	//	t.Errorf("expected '%s' got '%s'", "{\"name\":\"james\"}", sb)
	//}
}

// TestService_decode is to test that the service is able to successfully
// decode any request from the micro-service.
func TestService_decode(t *testing.T) {
	res := &http.Response{
		Status:     http.StatusText(201),
		StatusCode: 201,
		Header: map[string][]string{
			"Content-Type": {"application/json"},
			"X-Random":     {"not-so-random"},
		},
		Body: ioutil.NopCloser(strings.NewReader("{\"name\":\"james\"}")),
	}

	b := struct {
		Name string `json:"name"`
	}{}

	s := NewService("")
	xb, e := s.decode(res, &b)
	if e != nil {
		t.Errorf("unexpected error: %v", e)
	}
	if string(xb) != "{\"name\":\"james\"}" {
		t.Errorf("expected '%v' got '%v'", "{\"name\":\"james\"}", string(xb))
	}

}

func TestService_decode_error(t *testing.T) {
	res := &http.Response{
		Status:     http.StatusText(201),
		StatusCode: 201,
		Header: map[string][]string{
			"Content-Type": {"application/json"},
			"X-Random":     {"not-so-random"},
		},
		Body: ioutil.NopCloser(strings.NewReader("{\"name\":\"james\"}")),
	}

	b := struct {
		Name int `json:"name"`
	}{}

	s := NewService("")
	xb, e := s.decode(res, &b)

	errMessage := "map[marshal:[json: cannot unmarshal string into Go struct field .name of type int]]"
	if e.Error() != errMessage {
		t.Errorf("expected '%v' got '%v'", errMessage, e.Error())
	}
	if string(xb) != "" {
		t.Errorf("expected '%v' got '%v'", "", string(xb))
	}

}

// TestService_GetHome test that the health check function is available and
// working as expected.
func TestService_GetHome(t *testing.T) {
	type E struct {
		alive bool
		e     dutil.Err
	}
	tt := []struct {
		name     string
		Exchange *microtest.Exchange
		E        E
	}{
		{
			name: "service alive",
			Exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
				},
			},
			E: E{
				alive: true,
			},
		},
		{
			name: "service down",
			Exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 500,
				},
			},
			E: E{
				alive: false,
			},
		},
	}

	s := NewService("")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ms.Append(tc.Exchange)

			b, e := s.GetHome()
			if b != tc.E.alive {
				t.Errorf("expected '%v' got '%v'", tc.E.alive, b)
			}
			if e != nil {
				if e.Error() != tc.E.e.Error() {
					t.Errorf("expected '%v' got '%v", tc.E.e.Error(), e.Error())
				}
			}
		})
	}
}
