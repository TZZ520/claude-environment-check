//go:build !windows

package main

import "fmt"

func showFatalError(title, message string) { fmt.Printf("%s: %s\n", title, message) }
