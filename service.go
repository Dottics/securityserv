package security

import (
	"encoding/json"
	"github.com/dottics/dutil"
	"github.com/johannesscr/micro/msp"
	"io"
	"log"
	"net/http"
	"net/url"
)

// Service is the shorthand for the integration to the Security MicroService
type Service struct {
	msp.Service
	//Header http.Header
	//URL    url.URL
}

type Config struct {
	UserToken string
	APIKey    string
	Header    http.Header
	Values    url.Values
}

func NewService(config Config) *Service {
	s := &Service{
		Service: *msp.NewService(msp.Config{
			Name:      "security",
			UserToken: config.UserToken,
			APIKey:    config.APIKey,
			Values:    config.Values,
			Header:    config.Header,
		}),
	}

	return s
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

// GetHome is a PING function to test connection to the Security MicroService
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
