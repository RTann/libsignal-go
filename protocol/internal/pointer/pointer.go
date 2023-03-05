// Package pointer implements utility functions for pointers.
package pointer

// To returns a pointer to the given type.
func To[T any](t T) *T {
	return &t
}
