package security

import "github.com/google/uuid"

type User struct {
	UUID               uuid.UUID `json:"uuid"`
	FirstName          string    `json:"first_name"`
	LastName           string    `json:"last_name"`
	Email              string    `json:"email"`
	ContactNumber      string    `json:"contact_number"`
	PasswordResetToken string    `json:"password_reset_token"`
	Active             bool      `json:"active"`
}

type PermissionCodes []string
