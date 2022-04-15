package security

import (
	"github.com/dottics/dutil"
	"github.com/google/uuid"
	"github.com/johannesscr/micro/microtest"
	"io"
	"strings"
	"testing"
)

func TestService_Login(t *testing.T) {
	u, _ := uuid.Parse("9b615709-cc9a-48c3-b1ea-a04d4375ea86")

	// E denotes "Expected" as in statistics
	type E struct {
		token string
		user User
		permissionCodes PermissionCodes
		e dutil.Err
	}
	tt := []struct{
		name string
		payload io.Reader
		exchange *microtest.Exchange
		E E
	}{
		{
			name: "400 bad request",
			payload: strings.NewReader(`{"email":"tp@test.dottics.com","password":"password123"}`),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 400,
					Body: `{"message":"BadRequest: unable to process request","data":{},"errors":{"auth":["Invalid email or password"]}}`,
				},
			},
			E: E{
				token: "",
				user: User{},
				permissionCodes: PermissionCodes{},
				e: dutil.Err{
					Status: 400,
					Errors: map[string][]string{
						"auth": {"Invalid email or password"},
					},
				},
			},
		},
		{
			name: "500 server down",
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 500,
					Body: `{"message":"InternalServerError: unable to process request","data":{},"errors":{"internal_server_error":["some internal error"]}}`,
				},
			},
			E: E{
				token: "",
				user: User{},
				permissionCodes: PermissionCodes{},
				e: dutil.Err{
					Status: 500,
					Errors: map[string][]string{
						"internal_server_error": {"some internal error"},
					},
				},
			},
		},
		{
			name: "200 successful login",
			payload: strings.NewReader(`{"email":"tp@test.dottics.com","password":"correct-password"}`),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
					Header: map[string][]string{
						"X-User-Token": {"some-long-jwt-encrypted-token"},
					},
					Body: `{"message":"login successful","data":{"user":{"uuid":"9b615709-cc9a-48c3-b1ea-a04d4375ea86","first_name":"james","last_name":"bond","active":true},"permission":["abcd", "1234", "ab34"]},"errors":{}}`,
				},
			},
			E: E{
				token: "some-long-jwt-encrypted-token",
				user: User{
					UUID:               u,
					FirstName:          "james",
					LastName:           "bond",
					Email:              "",
					ContactNumber:      "",
					PasswordResetToken: "",
					Active:             true,
				},
				permissionCodes: PermissionCodes{"abcd", "1234", "ab34"},
				e: dutil.Err{},
			},
		},
	}

	s := NewService("")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for _, tc := range tt {
		t.Run(tc.name, func (t *testing.T) {
			// add the new exchange to the micro-service
			ms.Append(tc.exchange)
			// test the login function
			token, u, xp, e := s.Login(tc.payload)
			if token != tc.E.token {
				t.Errorf("expected '%v' got '%v'", tc.E.token, token)
			}
			if tc.E.e.Errors != nil {
				if e.Error() != tc.E.e.Error() {
					t.Errorf("expected '%v' got '%v'", tc.E.e.Error(), e.Error())
				}
			}
			// check if empty
			if tc.E.user != (User{}) {
				if u.UUID != tc.E.user.UUID {
					t.Errorf("expected '%v' got '%v'", tc.E.user.UUID, u.UUID)
				}
			}
			// check if empty
			if len(tc.E.permissionCodes) > 0 {
				if xp[0] != tc.E.permissionCodes[0] {
					t.Errorf("expected '%v' got '%v'", tc.E.permissionCodes[0], xp[0])
				}
			}
		})
	}
}

func TestService_Logout(t *testing.T) {
	type E struct {
		e dutil.Err
	}
	tt := []struct{
		name string
		payload io.Reader
		exchange *microtest.Exchange
		E E
	}{
		{
			name: "400 bad request",
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 401,
					Body: `{"message":"Unauthorised: Unable to process request","data":{},"errors":{"auth":["Auth token required","Please login"]}}`,
				},
			},
			E: E{
				e: dutil.Err{
					Status: 401,
					Errors: map[string][]string{
						"auth": {"Auth token required","Please login"},
					},
				},
			},
		},
		{
			name: "500 bad request",
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 500,
					Body: `{"message":"InternalServerError: Unable to process request","data":{},"errors":{"internal_server_error":["some internal server error"]}}`,
				},
			},
			E: E{
				e: dutil.Err{
					Status: 500,
					Errors: map[string][]string{
						"internal_server_error": {"some internal server error"},
					},
				},
			},
		},
		{
			name: "200 logout successful",
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
					Body: `{"message":"logout successful","data":{},"errors":{}}`,
				},
			},
			E: E{
				e: dutil.Err{},
			},
		},
	}

	token := "my-very-secure-token"
	s := NewService(token)
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for _, tc := range tt  {
		t.Run(tc.name, func(t *testing.T) {
			ms.Append(tc.exchange)

			e := s.Logout()

			// token should automatically be added to the request from the server
			reqToken := tc.exchange.Request.Header.Get("X-User-Token")
			if reqToken != token {
				t.Errorf("expected '%v' got '%v'", reqToken, token)
			}

			if tc.E.e.Status != 0 {
				if e.Error() != tc.E.e.Error() {
					t.Errorf("expected '%v' got '%v'", tc.E.e.Error(), e.Error())
				}
			}
		})
	}
}
