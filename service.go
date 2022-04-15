package security

import (
	"encoding/json"
	"github.com/dottics/dutil"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

// service is the shorthand for the integration to the Security Micro-Service
type Service struct {
	Header http.Header
	URL url.URL
}


func NewService(token string) *Service {
	s := &Service{
		URL: url.URL{
			Scheme: os.Getenv("SECURITY_SERVICE_SCHEME"),
			Host: os.Getenv("SECURITY_SERVICE_HOST"),
		},
		Header: make(http.Header),
	}
	// default micro-service required headers
	(*s).Header.Set("Content-Type", "application/json")
	(*s).Header.Set("X-User-Token", token)

	return s
}

// SetURL sets the URL for the Security Micro-Service to point to
// the micro-service. SetURL is also the interface function that makes it a
// mock service
func (s *Service) SetURL(sc string, h string) {
	s.URL.Scheme = sc
	s.URL.Host = h
}

// SetEnv set the current service scheme and host as environmental variables.
//
// Mostly used for testing when the Env Vars need to be set dynamically when
// service instances need to be mocked in tests
func (s *Service) SetEnv() error {
	err := os.Setenv("SECURITY_SERVICE_SCHEME", s.URL.Scheme)
	if err != nil {
		return err
	}
	err = os.Setenv("SECURITY_SERVICE_HOST", s.URL.Host)
	if err != nil {
		return err
	}
	return nil
}

// NewRequest consistently maps and executes requests to the security service
// and returns the response
func (s *Service) NewRequest(method string, target string, headers map[string][]string, payload io.Reader) (*http.Response, dutil.Error) {
	client := http.Client{}
	req, err := http.NewRequest(method, target, payload)
	if err != nil {
		e := dutil.NewErr(500, "request", []string{err.Error()})
		return nil, e
	}
	// set the default security service headers
	req.Header = s.Header
	// set/override additional headers iff necessary
	for key, values := range headers {
		req.Header.Set(key, values[0])
	}
	res, err := client.Do(req)
	log.Println(err)
	log.Printf("- security-service -> [ %v %v ] <- %d",
		req.Method, req.URL.String(), res.StatusCode)
	if err != nil {
		e := dutil.NewErr(500, "request", []string{err.Error()})
		return nil, e
	}
	return res, nil
}

// decode id a function that decodes a body into a slice of bytes and
// error if there is one. Of the interface pointer value is given then
// unmarshal the slice of bytes into the value pointed to by the
// interface and return the slice of bytes.
func (s *Service) decode(res *http.Response, v interface{}) ([]byte, dutil.Error) {
	xb, err := io.ReadAll(res.Body)
	err = res.Body.Close()
	if err != nil {
		e := dutil.NewErr(500, "decode", []string{err.Error()})
		return []byte{}, e
	}
	//log.Printf("SECURITY SERVICE DECODE: %s\n", xb)

	if v != nil {
		err = json.Unmarshal(xb, v)
		if err != nil {
			e := dutil.NewErr(500, "marshal", []string{err.Error()})
			return []byte{}, e
		}
	}
	return xb, nil
}

// GetHome is a PING function to test connection to the Security Micro-Service
// is healthy.
func (s *Service) GetHome() (bool, dutil.Error) {
	res, err := http.Get(s.URL.String())
	if err != nil {
		e := dutil.NewErr(500, "request", []string{err.Error()})
		return false, e
	}
	if res.StatusCode == 200 {
		return true, nil
	}
	return false, nil
}