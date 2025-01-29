package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	// gnark packages for circuit definition

	// gnark-crypto packages for key generation and signing

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	crypto_eddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	//crypto_eddsa "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"
)

func Create() {
	// Generate a key pair using gnark-crypto
	// Generate a key pair using gnark-crypto
	privateKey, err := crypto_eddsa.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}
	publicKey := privateKey.PublicKey

	// Example message to sign
	message := []byte("Hello, World!")
	message2 := []byte("Hello, World!2")

	// Initialize the MiMC hash function
	hFunc := mimc.NewMiMC()

	// Sign the message (returns a serialized signature as []byte)
	serializedSignature, err := privateKey.Sign(message, hFunc)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}

	// Deserialize the signature
	var signature crypto_eddsa.Signature
	if _, err := signature.SetBytes(serializedSignature); err != nil {
		fmt.Println("Error deserializing signature:", err)
		return
	}
	hFunc.Reset()
	// sign message2
	serializedSignature2, err := privateKey.Sign(message2, hFunc)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	var signature2 crypto_eddsa.Signature
	if _, err := signature2.SetBytes(serializedSignature2); err != nil {
		fmt.Println("Error deserializing signature:", err)
		return
	}

	// Convert R.X and R.Y to big.Int and then to string
	rX := new(big.Int)
	rY := new(big.Int)
	signature.R.X.ToBigIntRegular(rX)
	signature.R.Y.ToBigIntRegular(rY)
	//convert signature2
	rX2 := new(big.Int)
	rY2 := new(big.Int)
	signature2.R.X.ToBigIntRegular(rX2)
	signature2.R.Y.ToBigIntRegular(rY2)
	s2 := new(big.Int).SetBytes(signature2.S[:])
	// Convert S to big.Int and then to string
	s := new(big.Int).SetBytes(signature.S[:])

	// Display the components
	fmt.Println("Message:", string(message))
	fmt.Println("Public Key X:", publicKey.A.X.String())
	fmt.Println("Public Key Y:", publicKey.A.Y.String())
	fmt.Println("Signature R.X:", rX.String())
	fmt.Println("Signature R.Y:", rY.String())
	fmt.Println("Signature S:", s.String())
	fmt.Println("Message2:", string(message2))
	fmt.Println("Signature2 R.X:", rX2.String())
	fmt.Println("Signature2 R.Y:", rY2.String())
	fmt.Println("Signature2 S:", s2.String())

}
