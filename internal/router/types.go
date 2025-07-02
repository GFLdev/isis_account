package router

type MessageResponse struct {
	Message string `json:"message"`
}

type AuthLogin struct {
	Username string `json:"username" validate:"required,min=4,max=30"`
	Password string `json:"password" validate:"required,min=4,max=16"`
}
