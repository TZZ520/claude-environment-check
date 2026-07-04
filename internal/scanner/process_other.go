//go:build !windows

package scanner

import "os/exec"

func hideCommand(*exec.Cmd) {}
