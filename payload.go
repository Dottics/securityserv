package security

type LoginPayload struct {
	Email    string
	Password string
}

type PasswordResetTokenPayload struct {
	Email string `json:"email"`
}

type ResetPasswordPayload struct {
	Email              string `json:"email"`
	PasswordResetToken string `json:"password_reset_token"`
	Password           string `json:"password"`
}

type RegisterPayload struct {
	Username      string `json:"username"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	ContactNumber string `json:"contact_number"`
	Password      string `json:"password"`
}
