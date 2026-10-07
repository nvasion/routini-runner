//go:build !unix

package config

// fileOwner is unknown off Unix; SaveKeepOwner then behaves like Save.
func fileOwner(string) (uid, gid int, ok bool) { return 0, 0, false }
