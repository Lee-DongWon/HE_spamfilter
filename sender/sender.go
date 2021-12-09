package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

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

func constructPublicKey(filename string) *rlwe.PublicKey {
	// file --> rlwe.PublicKey

	pkBinary, err := ioutil.ReadFile(filename)
	check(err)

	pkTest := new(rlwe.PublicKey)
	err = pkTest.UnmarshalBinary(pkBinary)
	check(err)

	return pkTest
}

func main() {
	////////// Lattigo Setting //////////
	// go run sender.go [ public key filename ] [ ham | spam ] [index]
	argsWithoutProg := os.Args[1:]
	ham_or_spam := argsWithoutProg[1]
	testIndex, err := strconv.Atoi(argsWithoutProg[2])
	check(err)

	var defaultParam ckks.ParametersLiteral
	defaultParam = ckks.PN16QP1761
	params, err := ckks.NewParametersFromLiteral(defaultParam)
	check(err)

	context := new(Params)
	context.params = params
	context.kgen = ckks.NewKeyGenerator(context.params)
	context.pk = constructPublicKey(argsWithoutProg[0])
	context.encoder = ckks.NewEncoder(context.params)
	context.encryptorPk = ckks.NewEncryptor(context.params, context.pk)
	// settingExecTime := time.Since(settingStartTime)
	////////// read spam token file //////////
	fmt.Println(fmt.Sprintf("%s CASE", ham_or_spam))
	filename := fmt.Sprintf("./enron/%s_index", ham_or_spam)
	plain_filename := fmt.Sprintf("./enron/enron%s", strings.Title(ham_or_spam))

	data, err := os.Open(filename)
	check(err)
	plain_data, err := os.Open(plain_filename)
	check(err)
	scanner := bufio.NewScanner(data)
	plain_scanner := bufio.NewScanner(plain_data)

	lineNum := 0

	logSlots := context.params.LogSlots()

	//split spam mails
	for scanner.Scan() {
		plain_scanner.Scan()
		lineNum += 1
		if lineNum == testIndex {
			fmt.Println(testIndex)

			spamEmail := make([]complex128, 1<<logSlots)
			line := scanner.Text()
			slice := strings.Split(line, " ")
			fmt.Println(plain_scanner.Text())
			//split tokens
			for _, str := range slice {
				tokenIndex, _ := strconv.ParseInt(str, 0, 64)
				spamEmail[tokenIndex] = complex(1, 0)
			}

			//encoding and encrypting a spam email
			encryptionStartTime := time.Now()
			spam_plain := context.encoder.EncodeNTTAtLvlNew(context.params.MaxLevel(), spamEmail, logSlots)
			spam_ctxt := context.encryptorPk.EncryptNew(spam_plain)
			encryptionExecTime := time.Since(encryptionStartTime)
			fmt.Println(fmt.Sprintf("Encode + Encrypt %s email time:", ham_or_spam), encryptionExecTime)

			marshalledCtxt, err := spam_ctxt.MarshalBinary()
			check(err)

			err = ioutil.WriteFile("./ct", marshalledCtxt, 0644)
			check(err)
			break
		}

	}

}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
