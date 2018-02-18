package gpgtools

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	GetAddress = "%s/pks/lookup?op=get&search=0x%s&options=mr"
)

// GetPublicKey retrieves one's public key from a selected
// SKS key server via the key's fingerprint
func GetPublicKey(keyServer, fingerprint string) (string, error) {
	URL := fmt.Sprintf(GetAddress, keyServer, fingerprint)
	response, err := http.Get(URL)
	if err != nil {
		return "", err
	}
	if response.StatusCode == http.StatusNotFound {
		return "", errors.New("not found")
	}

	defer response.Body.Close()

	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(content), nil
}
