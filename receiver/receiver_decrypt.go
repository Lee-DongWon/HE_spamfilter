
package main

import (
	"os"
	"io/ioutil"
	"fmt"
	"math"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

type Params struct {
	params      ckks.Parameters
	ringQ       *ring.Ring
	ringP       *ring.Ring
	prng        utils.PRNG
	encoder     ckks.Encoder
	kgen        rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	rlk         *rlwe.RelinearizationKey
	encryptorPk ckks.Encryptor
	encryptorSk ckks.Encryptor
	decryptor   ckks.Decryptor
	evaluator   ckks.Evaluator
}

const threshold float64 = 0.95

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	argsWithoutProg := os.Args[1:]

	var defaultParam ckks.ParametersLiteral
	defaultParam = ckks.PN16QP1761
	params, err := ckks.NewParametersFromLiteral(defaultParam)
	check(err)

	skBinary, err := ioutil.ReadFile("sk")
	check(err)

	resSecretKey := new(rlwe.SecretKey)
	err = resSecretKey.UnmarshalBinary(skBinary)
	check(err)

	ctBinary, err := ioutil.ReadFile(argsWithoutProg[0])
	check(err)

	ct := new(ckks.Ciphertext)
	err = ct.UnmarshalBinary(ctBinary)
	check(err)

	context := new(Params)
	context.sk = resSecretKey
	context.params = params
	
	context.encoder = ckks.NewEncoder(context.params)
	context.decryptor = ckks.NewDecryptor(context.params, context.sk)

	result_plain := context.decryptor.DecryptNew(ct)
	result := context.encoder.Decode(result_plain, context.params.LogSlots())

	fmt.Println(result[0])
	if real(result[0]) < math.Log(1/threshold-1) {
		fmt.Println("spam")
	} else {
		fmt.Println("ham")
	}
}