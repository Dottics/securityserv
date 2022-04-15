package security

import (
	"github.com/dottics/dutil"
	"io"
)

// Login sends the payload to the micro-service. If the login is successful
// a Redis session is created. And the user token is returned included in
// the Headers Login parses the response and extracts the token, user data
// and permissions codes.
func (s *Service) Login(payload io.Reader) (string, User, PermissionCodes, dutil.Error) {
	s.URL.Path = "/login"

	type data struct {
		User            User            `json:"user"`
		PermissionCodes PermissionCodes `json:"permission"`
	}
	resp := struct {
		Message string              `json:"message"`
		Data    data                `json:"data"`
		Errors  map[string][]string `json:"errors"`
	}{}

	res, e := s.NewRequest("POST", s.URL.String(), nil, payload)
	//xb, _ := ioutil.ReadAll(payload)
	//xb, _ := ioutil.ReadAll(req.Body)
	//log.Println("::1::", string(xb))
	//_ = payload.Close()
	if e != nil {
		return "", User{}, nil, e
	}
	_, e = s.decode(res, &resp)
	if e != nil {
		return "", User{}, nil, e
	}

	if res.StatusCode == 200 {
		token := res.Header.Get("X-User-Token")
		return token, resp.Data.User, resp.Data.PermissionCodes, nil
	}

	e = &dutil.Err{
		Status: res.StatusCode,
		Errors: resp.Errors,
	}
	return "", User{}, nil, e
}

// Logout sends request to the micro-service, the header contains the user
// token of the user to be logged out. The security-service returns 200 if
// request was successful.
func (s *Service) Logout() dutil.Error {
	s.URL.Path = "/logout"

	resp := struct {
		Message string              `json:"message"`
		Data    interface{}         `json:"data"`
		Errors  map[string][]string `json:"errors"`
	}{}

	res, e := s.NewRequest("GET", s.URL.String(), nil, nil)
	if e != nil {
		return e
	}
	_, e = s.decode(res, &resp)
	if e != nil {
		return e
	}

	if res.StatusCode == 200 {
		return nil
	}

	e = &dutil.Err{
		Status: res.StatusCode,
		Errors: resp.Errors,
	}

	return e
}
