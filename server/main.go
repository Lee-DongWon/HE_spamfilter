package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

const logSlots int = 15

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

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type User struct {
	id    uint
	inbox []Mail
}

type MailForm struct {
	encrypted_emb  *multipart.FileHeader `form:"embedding" binding:"required"`
	plaintext_mail string                `form:"mail" binding:"required"`
}

type Mail struct {
	plaintext_mail string
	uuid           string
}

func parse_uint_id(c *gin.Context, query string) uint {
	requestID, err := strconv.ParseUint(c.Param(query), 10, 32)
	if err != nil || requestID > math.MaxUint32 || requestID == 0 {
		c.Status(http.StatusBadRequest)
		return 0
	}
	return uint(requestID)
}

func constructPublicKey(id uint) *rlwe.PublicKey {
	// file --> rlwe.PublicKey

	pkBinary, err := ioutil.ReadFile(fmt.Sprintf("%d.pk", id))
	check(err)

	pkTest := new(rlwe.PublicKey)
	err = pkTest.UnmarshalBinary(pkBinary)
	check(err)

	return pkTest
}

func constructRotationKey(id uint) *rlwe.RotationKeySet {
	// file --> rlwe.RotationKeySet
	rtBinary, err := ioutil.ReadFile(fmt.Sprintf("%d.rok", id))
	check(err)

	resRotationKey := new(rlwe.RotationKeySet)
	err = resRotationKey.UnmarshalBinary(rtBinary)
	check(err)
	return resRotationKey
}

func constructRelinearizationKey(id uint) *rlwe.RelinearizationKey {
	// file --> rlwe.RelinarizationKey
	relinBinary, err := ioutil.ReadFile(fmt.Sprintf("%d.rek", id))
	check(err)

	resRelinKey := new(rlwe.RelinearizationKey)
	err = resRelinKey.UnmarshalBinary(relinBinary)
	check(err)
	return resRelinKey
}

func constructEmbedding(id uint, uuid string) *ckks.Ciphertext {
	// file --> ckks.Ciphertext
	ctBinary, err := ioutil.ReadFile(fmt.Sprintf("%d_%s.ct", id, uuid))
	check(err)

	ctTest := new(ckks.Ciphertext)
	err = ctTest.UnmarshalBinary(ctBinary)
	check(err)

	return ctTest
}

// // TODO : ckks.Ciphertext (spamness) --> store as file

func find_user(userbase []User, id uint) int {
	for i, u := range userbase {
		if u.id == id {
			return i
		}
	}
	return -1
}

func user_id_404(c *gin.Context, id uint) {
	c.String(http.StatusNotFound, "user (%d) does not exist", id)
}

func main() {
	// common settings (probdiff, probdiff_plain)
	filename := "./probdiff"
	data, err := os.Open(filename)
	check(err)

	probdiff := make([]complex128, 1<<logSlots)
	scanner := bufio.NewScanner(data)
	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println(line)
		var temp_probdiff float64
		temp_probdiff, err = strconv.ParseFloat(line, 64)
		probdiff[lineNum] = complex(temp_probdiff, 0)
		lineNum = lineNum + 1
	}

	// server code
	r := gin.Default()
	specific_id := r.Group("/:id")
	userbase := []User{}
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
	r.GET("/flush", func(c *gin.Context) {
		userbase = []User{}
		// cmd := exec.Command("rm", "-f", "*.ct", "*.ctr")
		// stdoutStderr, _ := cmd.CombinedOutput()
		// fmt.Println(string(stdoutStderr))
		c.String(http.StatusOK, "flushed")
	})

	specific_id.POST("/rek", func(c *gin.Context) {
		id := parse_uint_id(c, "id")
		// given pubkey --> save at `id.rek`
		file, err := c.FormFile("rek")
		if err != nil {
			c.String(http.StatusBadRequest, "no relin key")
			return
		}
		fmt.Println(file.Filename)
		c.SaveUploadedFile(file, fmt.Sprintf("./%d.rek", id))

		// if not in `userbase`, enroll
		i := find_user(userbase, id)
		if i < 0 {
			new_user := User{id, []Mail{}}
			userbase = append(userbase, new_user)
		}
		c.String(http.StatusOK, "ok")
	})

	specific_id.POST("/rok", func(c *gin.Context) {
		id := parse_uint_id(c, "id")
		// given pubkey --> save at `id.rok`
		file, err := c.FormFile("rok")
		if err != nil {
			c.String(http.StatusBadRequest, "no rotation key")
			return
		}
		fmt.Println(file.Filename)
		c.SaveUploadedFile(file, fmt.Sprintf("./%d.rok", id))

		// if not in `userbase`, enroll
		i := find_user(userbase, id)
		if i < 0 {
			new_user := User{id, []Mail{}}
			userbase = append(userbase, new_user)
		}
		c.String(http.StatusOK, "ok")
	})

	specific_id.POST("/pk", func(c *gin.Context) {
		id := parse_uint_id(c, "id")
		// given pubkey --> save at `id.pk`
		file, err := c.FormFile("pk")
		if err != nil {
			c.String(http.StatusBadRequest, "no pubkey")
			return
		}
		fmt.Println(file.Filename)
		c.SaveUploadedFile(file, fmt.Sprintf("./%d.pk", id))

		// if not in `userbase`, enroll
		i := find_user(userbase, id)
		if i < 0 {
			new_user := User{id, []Mail{}}
			userbase = append(userbase, new_user)
		}
		c.String(http.StatusOK, "ok")
	})
	specific_id.GET("/pk", func(c *gin.Context) {
		// return file `id.pk`
		query_id := parse_uint_id(c, "id")
		i := find_user(userbase, query_id)

		if i >= 0 {
			c.File(fmt.Sprintf("./%d.pk", query_id))
		} else {
			user_id_404(c, query_id)
		}
	})
	specific_id.POST("/send", func(c *gin.Context) {
		fmt.Println("starting send")
		query_id := parse_uint_id(c, "id")
		i := find_user(userbase, query_id)
		if i < 0 {
			user_id_404(c, query_id)
			return
		}

		var form MailForm
		// in this case proper binding will be automatically selected
		// if err := c.ShouldBind(&form); err != nil {
		// 	c.String(http.StatusBadRequest, "bad request")
		// 	return
		// }
		file, err := c.FormFile("ct")
		if err != nil {
			c.String(http.StatusBadRequest, "no encrypted file")
			return
		}
		emb_uuid := uuid.New()
		filename := fmt.Sprintf("%d_%s.ct", query_id, emb_uuid)
		err = c.SaveUploadedFile(file, filename)
		if err != nil {
			c.String(http.StatusInternalServerError, "error saving file")
			return
		}

		new_mail := Mail{form.plaintext_mail, fmt.Sprintf("%s", emb_uuid)}
		rcv_user := userbase[i]
		rcv_user.inbox = append(rcv_user.inbox, new_mail)
		userbase[i] = rcv_user
		c.String(http.StatusOK, "start calculating HE")
		// TODO
		// context & params
		////////// Lattigo Setting //////////
		var defaultParam ckks.ParametersLiteral
		defaultParam = ckks.PN16QP1761
		params, err := ckks.NewParametersFromLiteral(defaultParam)
		check(err)

		context := new(Params)
		context.params = params
		context.kgen = ckks.NewKeyGenerator(context.params)
		context.pk = constructPublicKey(query_id)
		rotKey := constructRotationKey(query_id)
		context.rlk = constructRelinearizationKey(query_id)

		ct := constructEmbedding(query_id, fmt.Sprintf("%s", emb_uuid))
		context.evaluator = ckks.NewEvaluator(context.params, rlwe.EvaluationKey{Rlk: context.rlk})
		evaluator := context.evaluator.WithKey(rlwe.EvaluationKey{Rlk: context.rlk, Rtks: rotKey})
		context.encoder = ckks.NewEncoder(context.params)
		probdiff_plain := context.encoder.EncodeNTTAtLvlNew(context.params.MaxLevel(), probdiff, logSlots)

		// calc
		evaluator.MulRelin(ct, probdiff_plain, ct)

		for rot_time := 0; rot_time < logSlots; rot_time++ {
			rot_index := math.Pow(2, float64(rot_time))
			//fmt.Println(rot_index)
			tmp_ctxt := evaluator.RotateNew(ct, int(rot_index))
			//fmt.Println(rot_index)
			evaluator.Add(ct, tmp_ctxt, ct)
		}
		// calc done
		// store
		marshalledCtxt, err := ct.MarshalBinary()
		check(err)

		err = ioutil.WriteFile(fmt.Sprintf("%d_%s.ctr", query_id, emb_uuid),
			marshalledCtxt, 0644)
		check(err)

		// file --> ckks.Ciphertext
		// file --> rlwe.PublicKey
		// calculate HE
		// ckks.Ciphertext --> file
		// store file
		c.String(http.StatusOK, "done calculating HE")
	})

	specific_id.GET("/inbox/len", func(c *gin.Context) {
		query_id := parse_uint_id(c, "id")
		i := find_user(userbase, query_id)
		if i < 0 {
			user_id_404(c, query_id)
			return
		}
		c.String(http.StatusOK, fmt.Sprintf("%d", len(userbase[i].inbox)))
	})

	specific_id.GET("/inbox/:index", func(c *gin.Context) {
		query_id := parse_uint_id(c, "id")
		i := find_user(userbase, query_id)
		if i < 0 {
			user_id_404(c, query_id)
		}
		query_index := parse_uint_id(c, "index")
		inbox_len := uint(len(userbase[i].inbox))
		if query_index >= inbox_len {
			c.String(http.StatusBadRequest, "index out of bound")
		}
		// stream file `ctr`
		emb_uuid := userbase[i].inbox[query_index].uuid
		c.File(fmt.Sprintf("./%d_%s.ctr", query_id, emb_uuid))
	})
	r.Run() // 8080
}
