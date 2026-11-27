package version

import "fmt"

var (
	// Version and GitCommit are set at build time via -ldflags, see the Makefile
	Version   = "0.0.0-dev"
	Name      string
	GitCommit string

	HumanVersion = fmt.Sprintf("%s v%s (%s)", Name, Version, GitCommit)
)
