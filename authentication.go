package security

import (
	"github.com/dottics/dutil"
	"github.com/google/uuid"
	"io"
	"net/url"
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

// PasswordResetToken makes and HTTP exchange to the security microservice
// the body should contain the email of the user. The security service will
// then return the password reset token otherwise an error.
func (s *Service) PasswordResetToken(p PasswordResetTokenPayload) (string, dutil.Error) {
	s.URL.Path = "/reset-password/token"

	type data struct {
		PasswordResetToken string `json:"password_reset_token"`
	}
	resp := struct {
		Message string              `json:"message"`
		Data    data                `json:"data"`
		Errors  map[string][]string `json:"errors"`
	}{}

	payload, e := dutil.MarshalReader(p)
	if e != nil {
		return "", e
	}

	res, e := s.NewRequest("post", s.URL.String(), nil, payload)
	if e != nil {
		return "", e
	}
	_, e = s.decode(res, &resp)
	if e != nil {
		return "", e
	}

	if res.StatusCode != 200 {
		e := &dutil.Err{
			Status: res.StatusCode,
			Errors: resp.Errors,
		}
		return "", e
	}

	return resp.Data.PasswordResetToken, nil
}

// ResetPassword handles the exchange with the security microservice to
// reset a user's password.
func (s *Service) ResetPassword(p ResetPasswordPayload) dutil.Error {
	s.URL.Path = "/reset-password/reset"

	resp := struct {
		Message string              `json:"message"`
		Data    interface{}         `json:"data"`
		Errors  map[string][]string `json:"errors"`
	}{}

	payload, e := dutil.MarshalReader(p)
	if e != nil {
		return e
	}

	res, e := s.NewRequest("post", s.URL.String(), nil, payload)
	if e != nil {
		return e
	}
	_, e = s.decode(res, &resp)
	if e != nil {
		return e
	}

	if res.StatusCode != 200 {
		e := &dutil.Err{
			Status: res.StatusCode,
			Errors: resp.Errors,
		}
		return e
	}

	return nil
}

// RevokePasswordResetToken handles the exchange with the security
// microservice to revoke a user's password reset token.
func (s *Service) RevokePasswordResetToken(passwordResetToken uuid.UUID) dutil.Error {
	s.URL.Path = "/revoke-password-reset-token"
	qs := url.Values{}
	qs.Add("password_reset_token", passwordResetToken.String())
	s.URL.RawQuery = qs.Encode()

	resp := struct {
		Message string              `json:"message"`
		Errors  map[string][]string `json:"errors"`
	}{}

	res, e := s.NewRequest("delete", s.URL.String(), nil, nil)
	if e != nil {
		return e
	}
	_, e = s.decode(res, &resp)
	if e != nil {
		return e
	}

	if res.StatusCode != 200 {
		e := &dutil.Err{
			Status: res.StatusCode,
			Errors: resp.Errors,
		}
		return e
	}

	return nil
}
