package pgptools

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	GetAddress    = "%s/pks/lookup?op=get&search=0x%s&options=mr"
	GetUIDAddress = "%s/pks/lookup?op=vindex&search=0x%s"
)

// GetPublicKey retrieves one's public key from a selected
// SKS key server via the key's fingerprint
func GetPublicKey(keyServer, fingerprint string) (string, error) {
	URL := fmt.Sprintf(GetAddress, keyServer, fingerprint)
	return get(URL)
}

// GetUID retrieves one's UID from a selected
// SKS key server via the key's fingerprint
func GetUID(keyServer, fingerprint string) (string, error) {
	URL := fmt.Sprintf(GetUIDAddress, keyServer, fingerprint)
	content, err := get(URL)
	if err != nil {
		return "", err
	}
	content = strings.SplitAfter(content, `<span class="uid">`)[0]
	content = strings.Split(content, "</span>")[0]
	return content, err
}

func get(URL string) (content string, err error) {
	response, err := http.Get(URL)
	if err != nil {
		return content, err
	}
	if response.StatusCode != http.StatusOK {
		return content, errors.New("not found")
	}
	defer response.Body.Close()

	contentRaw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return content, err
	}
	content = string(contentRaw)
	return content, err
}
