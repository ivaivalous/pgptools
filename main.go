package main

import (
	"fmt"
	"gpgtools/gpgtools"
)

func main() {
	key, err := gpgtools.GetPublicKey("AA967D520AF181BBC86725B3AB9F0F4F2D6A49E4")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(key)
}
