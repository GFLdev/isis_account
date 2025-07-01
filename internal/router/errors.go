package router

type ErrorMessage string

const (
	CannotReadBodyError ErrorMessage = "Could not read body"
)
