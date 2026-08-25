package main

import (
	"os/exec"
	"runtime"
)

// openFile opens a path in the OS default application. Reports false when it
// cannot, so a caller can say so instead of pretending it worked.
func openFile(path string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", path)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		command = exec.Command("xdg-open", path)
	}
	return command.Start() == nil
}
