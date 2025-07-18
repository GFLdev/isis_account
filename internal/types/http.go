package types

import "github.com/google/uuid"

type SuccessMessages string

const (
	LoggedOut        SuccessMessages = "User logged out successfully"
	AlreadyLoggedOut SuccessMessages = "User already logged out"
)

type HTTPMessageResponse struct {
	Message string `json:"message"`
}

type HTTPAuthLoginRes struct {
	AccountID uuid.UUID `json:"account_id" validate:"required,uuid"`
	RoleId    uuid.UUID `json:"role_id" validate:"required,uuid"`
}

type HTTPAuthLoginReq struct {
	Username string `json:"username" validate:"required,min=4,max=30"`
	Password string `json:"password" validate:"required,min=4,max=16"`
}
