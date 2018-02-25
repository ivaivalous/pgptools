package pgptools

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	getKeyAddress     = "%s/pks/lookup?op=get&search=0x%s&options=mr"
	getUIDAddress     = "%s/pks/lookup?op=vindex&search=0x%s"
	userIDStartMarker = `<span class="uid">`
	userIDEndMarker   = `</span>`
	notFoundError     = "not found"
	badFormatError    = "bad format"
)

// GetPublicKey retrieves one's public key from a selected
// SKS key server via the key's fingerprint
func GetPublicKey(keyServer, fingerprint string) (string, error) {
	URL := fmt.Sprintf(getKeyAddress, keyServer, fingerprint)
	return get(URL)
}

// GetUID retrieves one's UID from a selected
// SKS key server via the key's fingerprint
func GetUID(keyServer, fingerprint string) (string, error) {
	URL := fmt.Sprintf(getUIDAddress, keyServer, fingerprint)
	content, err := get(URL)
	if err != nil {
		return "", err
	}

	split := strings.SplitAfter(content, userIDStartMarker)
	if len(split) == 0 {
		err = errors.New(badFormatError)
		return "", err
	}

	content = strings.SplitAfter(content, userIDStartMarker)[1]
	content = strings.Split(content, userIDEndMarker)[0]
	return content, err
}

func get(URL string) (content string, err error) {
	response, err := http.Get(URL)
	if err != nil {
		return content, err
	}
	if response.StatusCode != http.StatusOK {
		return content, errors.New(notFoundError)
	}
	defer response.Body.Close()

	contentRaw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return content, err
	}
	content = string(contentRaw)
	return content, err
}
