package security

type LoginPayload struct {
	Email    string
	Password string
}

type PasswordResetTokenPayload struct {
	Email string `json:"email"`
}
