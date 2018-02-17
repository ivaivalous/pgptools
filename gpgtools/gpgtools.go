package gpgtools

import (
	"bufio"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	identityRegex = `^gpg: key [A-Z0-9]+: "(?P<ID>.*?)".*$`
)

const (
	PGPCommand          = "gpg"
	ReceiveKeysArgument = "--recv-keys"
	PGPTimeout          = 5 * time.Second
)

func GetPublicKey(fingerprint string) (string, error) {
	command := exec.Command(PGPCommand, ReceiveKeysArgument, fingerprint)

	// Prevent the command from potentially hanging
	// by terminating it in case it fails to respond in
	// five seconds
	var timer *time.Timer
	timer = time.AfterFunc(PGPTimeout, func() {
		timer.Stop()
		command.Process.Kill()
	})

	output, err := command.CombinedOutput()
	if err != nil {
		return "", err
	}

	ID := extractID(string(output))
	return ID, nil
}

func extractID(gpgOutput string) string {
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
			return result["ID"]
		}
	}

	return ""
}
