package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

func encrypting(name string, key []byte) error {
	data, err := ioutil.ReadFile(name)
	if err != nil {
		log.Fatal(err)
		return err
	}

	text := []byte(data)

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		return err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
		return err
	}

	err = ioutil.WriteFile("enc_"+name, gcm.Seal(nonce, nonce, text, nil), 0777)
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

func decrypting(name string, key []byte) error {
	ciphertext, err := ioutil.ReadFile(name)
	if err != nil {
		log.Fatal(err)
		return err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		return err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal(err)
		return err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
		return err
	}

	err = ioutil.WriteFile(name[4:], plaintext, 0777)
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}

func main() {
	var cmdEncrypt = &cobra.Command{
		Use:   "encrypt [filename, key]",
		Short: "Encrypting file",
		Long:  "Encrypting the file by privat key",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			encrypting(args[0], []byte(args[1]))
			fmt.Println("Print: " + strings.Join(args, " "))
		},
	}

	var cmdDecrypt = &cobra.Command{
		Use:   "decrypt [filename, key]",
		Short: "Decrypting file",
		Long:  "Decrypting file by privat key",
		Args:  cobra.MaximumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			decrypting(args[0], []byte(args[1]))
			fmt.Println("Echo: " + strings.Join(args, " "))
		},
	}

	var rootCmd = &cobra.Command{Use: "app"}
	rootCmd.AddCommand(cmdEncrypt, cmdDecrypt)
	rootCmd.Execute()
}
