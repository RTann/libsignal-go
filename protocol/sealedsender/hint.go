package sealedsender

type ContentHint uint32

const (
	DefaultContentHint ContentHint = iota
	ResendableContentHint
	ImplicitContentHint
)
