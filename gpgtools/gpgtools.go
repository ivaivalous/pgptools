package gpgtools

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	identityRegex = `^gpg: key [A-Z0-9]+: "(?P<ID>.*?)".*$`
	notFoundError = "key not found"
)

const (
	PGPCommand          = "gpg"
	ReceiveKeysArgument = "--recv-keys"
	KeyServerArgument   = "--keyserver"
	ExportArgument      = "--export"
	KeyServer           = "pgp.mit.edu"
	PGPTimeout          = 5 * time.Second
)

func GetPublicKey(fingerprint string) (string, error) {
	command := exec.Command(PGPCommand, KeyServerArgument, KeyServer, ReceiveKeysArgument, fingerprint)
	timeCommandOut(command)

	output, err := command.CombinedOutput()
	if err != nil {
		return "", err
	}

	ID, found := extractID(string(output))
	if !found {
		return "", errors.New(notFoundError)
	}

	return readKey(ID)
}

func timeCommandOut(cmd *exec.Cmd) {
	// Prevent the command from potentially hanging
	// by terminating it in case it fails to respond in
	// five seconds
	var timer *time.Timer
	timer = time.AfterFunc(PGPTimeout, func() {
		timer.Stop()
		(*cmd).Process.Kill()
	})
}

func extractID(gpgOutput string) (ID string, found bool) {
	re := regexp.MustCompile(identityRegex)
	scanner := bufio.NewScanner(strings.NewReader(gpgOutput))

	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			match := re.FindStringSubmatch(scanner.Text())
			result := make(map[string]string)

			for i, name := range re.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}
			return result["ID"], true
		}
	}

	return "", false
}

func readKey(ID string) (string, error) {
	IDWrapped := fmt.Sprintf(`"%s"`, ID)
	command := exec.Command(PGPCommand, ExportArgument, "-a", IDWrapped)
	timeCommandOut(command)

	output, err := command.CombinedOutput()
	if err != nil {
		return "", err
	}

	return string(output), nil
}
