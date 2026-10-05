// Package version holds the runner version reported to the Routini server.
package version

// Version is the runner version. Release builds override it with
//
//	-ldflags "-X github.com/nvasion/routini-runner/internal/version.Version=0.1.0"
var Version = "0.1.0"
