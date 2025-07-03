package types

type ANSIColor string

const (
	BoldBlue  ANSIColor = "\033[1;34m"
	BoldWhite ANSIColor = "\033[1;37m"
	Reset     ANSIColor = "\033[0m"
)
