//go:build windows

package scanner

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

func hideCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
