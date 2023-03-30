package security

import (
	"fmt"
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
		token           string
		user            User
		permissionCodes PermissionCodes
		e               dutil.Err
	}
	tt := []struct {
		name     string
		payload  io.Reader
		exchange *microtest.Exchange
		E        E
	}{
		{
			name:    "400 bad request",
			payload: strings.NewReader(`{"email":"tp@test.dottics.com","password":"password123"}`),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 400,
					Body:   `{"message":"BadRequest: unable to process request","data":{},"errors":{"auth":["Invalid email or password"]}}`,
				},
			},
			E: E{
				token:           "",
				user:            User{},
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
					Body:   `{"message":"InternalServerError: unable to process request","data":{},"errors":{"internal_server_error":["some internal error"]}}`,
				},
			},
			E: E{
				token:           "",
				user:            User{},
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
			name:    "200 successful login with email",
			payload: strings.NewReader(`{"email":"tp@test.dottics.com","password":"correct-password"}`),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
					Header: map[string][]string{
						"X-User-Token": {"some-long-jwt-encrypted-token"},
					},
					Body: `{
						"message":"login successful",
						"data":{
							"user":{
								"uuid":"9b615709-cc9a-48c3-b1ea-a04d4375ea86",
								"username":"tp",
								"email":"tp@test.dottics.com",
								"first_name":"james",
								"last_name":"bond",
								"active":true
							},
							"permission":["abcd", "1234", "ab34"]
						},
						"errors":{}
					}`,
				},
			},
			E: E{
				token: "some-long-jwt-encrypted-token",
				user: User{
					UUID:               u,
					Username:           "tp",
					FirstName:          "james",
					LastName:           "bond",
					Email:              "tp@test.dottics.com",
					ContactNumber:      "",
					PasswordResetToken: "",
					Active:             true,
				},
				permissionCodes: PermissionCodes{"abcd", "1234", "ab34"},
				e:               dutil.Err{},
			},
		},
		{
			name:    "200 successful login with username",
			payload: strings.NewReader(`{"username":"tp","password":"correct-password"}`),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
					Header: map[string][]string{
						"X-User-Token": {"some-long-jwt-encrypted-token"},
					},
					Body: `{
						"message":"login successful",
						"data":{
							"user":{
								"uuid":"9b615709-cc9a-48c3-b1ea-a04d4375ea86",
								"email":"tp@test.dottics.com",
								"username":"tp",
								"first_name":"james",
								"last_name":"bond",
								"active":true
							},
							"permission":["abcd", "1234", "ab34"]
						},
						"errors":{}
					}`,
				},
			},
			E: E{
				token: "some-long-jwt-encrypted-token",
				user: User{
					UUID:               u,
					Username:           "tp",
					FirstName:          "james",
					LastName:           "bond",
					Email:              "tp@test.dottics.com",
					ContactNumber:      "",
					PasswordResetToken: "",
					Active:             true,
				},
				permissionCodes: PermissionCodes{"abcd", "1234", "ab34"},
				e:               dutil.Err{},
			},
		},
	}

	s := NewService("")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// add the new exchange to the microservice
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
	tt := []struct {
		name     string
		payload  io.Reader
		exchange *microtest.Exchange
		E        E
	}{
		{
			name: "400 bad request",
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 401,
					Body:   `{"message":"Unauthorised: Unable to process request","data":{},"errors":{"auth":["Auth token required","Please login"]}}`,
				},
			},
			E: E{
				e: dutil.Err{
					Status: 401,
					Errors: map[string][]string{
						"auth": {"Auth token required", "Please login"},
					},
				},
			},
		},
		{
			name: "500 bad request",
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 500,
					Body:   `{"message":"InternalServerError: Unable to process request","data":{},"errors":{"internal_server_error":["some internal server error"]}}`,
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
					Body:   `{"message":"logout successful","data":{},"errors":{}}`,
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

	for _, tc := range tt {
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

func TestService_PasswordResetToken(t *testing.T) {
	type E struct {
		token string
		e     dutil.Error
	}
	tests := []struct {
		name     string
		payload  PasswordResetTokenPayload
		exchange *microtest.Exchange
		E        E
	}{
		{
			name: "bad request",
			payload: PasswordResetTokenPayload{
				Email: "i@dont.exist",
			},
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 400,
					Body:   `{"message":"password reset token successful","data":null,"errors":{"email":["required field"]}}`,
				},
			},
			E: E{
				token: "",
				e: &dutil.Err{
					Status: 400,
					Errors: map[string][]string{
						"email": {"required field"},
					},
				},
			},
		},
		{
			name: "successful",
			payload: PasswordResetTokenPayload{
				Email: "i@do.exist",
			},
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
					Body:   `{"message":"password reset token successful","data":{"password_reset_token":"f7c349f6-fbde-4241-871d-6a20827ef74e"},"errors":null}`,
				},
			},
			E: E{
				token: "f7c349f6-fbde-4241-871d-6a20827ef74e",
				e:     nil,
			},
		},
	}

	s := NewService("")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for i, tc := range tests {
		ms.Append(tc.exchange)

		name := fmt.Sprintf("%d %s", i, tc.name)
		t.Run(name, func(t *testing.T) {
			passResetToken, e := s.PasswordResetToken(tc.payload)
			if !dutil.ErrorEqual(e, tc.E.e) {
				t.Errorf("expected %v got %v", tc.E.e, e)
			}
			if passResetToken != tc.E.token {
				t.Errorf("expected token %s got %s", tc.E.token, passResetToken)
			}
		})
	}
}

func TestService_ResetPassword(t *testing.T) {
	tests := []struct {
		// test input
		name     string
		payload  ResetPasswordPayload
		exchange *microtest.Exchange
		// expected output
		e dutil.Error
	}{

		{
			name: "decode error",
			payload: ResetPasswordPayload{
				Email:              "i@dont.exist",
				PasswordResetToken: "f7c349f6-fbde-4241-871d-6a20827ef74e",
				Password:           "password",
			},
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 400,
					Body:   `{"message":"BadRequest","data":null,"errors":{"user:["not found"]}}`,
				},
			},
			e: &dutil.Err{
				Status: 500,
				Errors: map[string][]string{
					"marshal": {"invalid character 'n' after object key"},
				},
			},
		},
		{
			name: "bad request",
			payload: ResetPasswordPayload{
				Email:              "i@dont.exist",
				PasswordResetToken: "f7c349f6-fbde-4241-871d-6a20827ef74e",
				Password:           "password",
			},
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 400,
					Body:   `{"message":"BadRequest","data":null,"errors":{"user":["not found"]}}`,
				},
			},
			e: &dutil.Err{
				Status: 400,
				Errors: map[string][]string{
					"user": {"not found"},
				},
			},
		},
		{
			name: "password reset successful",
			payload: ResetPasswordPayload{
				Email:              "i@do.exist",
				PasswordResetToken: "f7c349f6-fbde-4241-871d-6a20827ef74e",
				Password:           "password",
			},
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 400,
					Body:   `{"message":"password reset successful","data":null,"errors":null}`,
				},
			},
			e: nil,
		},
	}

	s := NewService("")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for i, tc := range tests {
		name := fmt.Sprintf("%d %s", i, tc.name)
		t.Run(name, func(t *testing.T) {
			// add exchange
			ms.Append(tc.exchange)
			// reset password
			e := s.ResetPassword(tc.payload)
			// validate responses
			if !dutil.ErrorEqual(e, tc.e) {
				t.Errorf("expected error %v got %v", tc.e, e)
			}
		})
	}
}

func TestService_RevokePasswordResetToken(t *testing.T) {
	tests := []struct {
		name               string
		PasswordResetToken uuid.UUID
		exchange           *microtest.Exchange
		e                  dutil.Error
	}{
		{
			name:               "bad request",
			PasswordResetToken: uuid.MustParse("db3fb95d-f157-476c-b1cc-8637d98b5999"),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 404,
					Body:   `{"message":"BadRequest","data":{},"errors":{"user":["not found"]}}`,
				},
			},
			e: &dutil.Err{
				Status: 404,
				Errors: map[string][]string{
					"user": {"not found"},
				},
			},
		},
		{
			name:               "revoke password reset token",
			PasswordResetToken: uuid.MustParse("db3fb95d-f157-476c-b1cc-8637d98b5999"),
			exchange: &microtest.Exchange{
				Response: microtest.Response{
					Status: 200,
					Body:   `{"message":"revoke password reset token successful","data":{},"errors":{}}`,
				},
			},
			e: nil,
		},
	}

	s := NewService("")
	ms := microtest.MockServer(s)
	defer ms.Server.Close()

	for i, tc := range tests {
		name := fmt.Sprintf("%d %s", i, tc.name)
		t.Run(name, func(t *testing.T) {
			ms.Append(tc.exchange)

			e := s.RevokePasswordResetToken(tc.PasswordResetToken)

			if !dutil.ErrorEqual(e, tc.e) {
				t.Errorf("expected error %v got %v", tc.e, e)
			}
		})
	}
}
