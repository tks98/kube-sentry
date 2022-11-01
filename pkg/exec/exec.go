package exec

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"
)

const defaultFailedCode = 1

func RunCommand(name string, args ...string) (string, error) {

	var stdout, stderr string
	var exitCode int

	var outbuf, errbuf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()
	stdout = outbuf.String()
	stderr = errbuf.String()

	if err != nil {
		// attempt to get the error code from the failed program
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			exitCode = defaultFailedCode
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// command executed successfully, exit code should be 0 in this case
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}

	// return results of the command
	if exitCode == 0 {
		return stdout, nil // command executed successfully
	} else {
		return stdout, fmt.Errorf(stderr + stdout) // there was a problem
	}
}
