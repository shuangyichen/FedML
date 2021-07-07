package main

import (
	"C"
    "bufio"
	"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/dckks"
	"github.com/ldsec/lattigo/v2/ring"
	//"github.com/ldsec/lattigo/v2/utils"
	//"math/rand"
	//"net"
	//"os"
	//"strconv"
	"strings"
	//"time"
)

type party struct {
	sk           []*ckks.SecretKey
	secretShares []*ring.Poly
	shamirShare  *ring.Poly
	ckgShare     dckks.CKGShare
	pcksShare    []dckks.PCKSShare
	input        [][]complex128
}

var encInput []*ckks.Ciphertext
//export encryptMsg
func encryptMsg(inputs []float64, cpkString string, shamirShareString string, robust bool, logDegree uint64, scale float64) (encInput_cstring *C.char) {
	var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
	params, err := ckks.NewParametersFromModuli(logDegree, moduli)
	params.SetScale(scale)
	params.SetLogSlots(logDegree - 1)
	if err != nil {
		panic(err)
	}
	///////// Ring for the common reference polynomials sampling
	ringQP, _ := ring.NewRing(params.N(), append(params.Qi(), params.Pi()...))
	///////// Common reference polynomial generator that uses the PRNG
	//pcks := dckks.NewPCKSProtocol(params, 3.19)
	///////// generate evaluation points for secret sharing

	///////// create the party object and setup keys
	pi := &party{}
	pi.shamirShare = ringQP.NewPoly()
	pi.shamirShare.SetCoefficients(polyCoeffsDecode(shamirShareString))
	///////// Create party, and allocate the memory for all the shares that the protocols will need
	// creating inputs
	numPieces := 0
	inputLength := len(inputs)
	packSize := 2 * int(params.Slots())
	if inputLength%packSize == 0 {
		numPieces = inputLength / packSize
	} else {
		numPieces = inputLength/packSize + 1
	}
	//fmt.Println("Working with ", numPieces, " pieces")
	pi.input = make([][]complex128, numPieces)
	for i := 0; i < numPieces; i++ {
		pi.input[i] = make([]complex128, params.Slots())
		for j := range pi.input[i] {
			if i*packSize+2*j < inputLength && i*packSize+2*j+1 < inputLength {
				firstElem := inputs[i*packSize+2*j]
				secElem := inputs[i*packSize+2*j+1]
				pi.input[i][j] = complex(firstElem, secElem)
			} else if i*packSize+2*j < inputLength {
				firstElem := inputs[i*packSize+2*j]
				pi.input[i][j] = complex(firstElem, 0)
			} else {
				pi.input[i][j] = complex(0, 0)
			}

		}
	}
	pi.pcksShare = make([]dckks.PCKSShare, numPieces)
	/// set the collective public key
	itemsString := strings.Split(cpkString, "/")
	itemsString = itemsString[0 : len(itemsString)-1]
	if len(itemsString) != 2 {
		//fmt.Println("Collective Public Key error")
		return
	}
	var itemsPoly [2]*ring.Poly
	for counter := range itemsPoly {
		tmp := polyCoeffsDecode(itemsString[counter])
		itemsPoly[counter] = ringQP.NewPoly()
		itemsPoly[counter].SetCoefficients(tmp)
	}
	pk := ckks.NewPublicKey(params)
	pk.Set(itemsPoly)
	//fmt.Println("Public key installed")
	//startTime = time.Now()

	///////// Encrypt and transmit
	encInput = make([]*ckks.Ciphertext, numPieces)
	encryptor := ckks.NewEncryptorFromPk(params, pk)
	encoder := ckks.NewEncoder(params)
	//fmt.Println("Encryption threads launched")
	for pieceCounter := range encInput {
		encInput[pieceCounter] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.Scale())
		pt := ckks.NewPlaintext(params, params.MaxLevel(), params.Scale())
		encoder.Encode(pt, pi.input[pieceCounter], params.Slots())
		encryptor.Encrypt(pt, encInput[pieceCounter])
	}
    

	encInputStr := ""
	for idx := range encInput {
        for ctPolyCounter := range encInput[idx].Value(){
            encInputStr += polyCoeffsEncode(encInput[idx].Value()[ctPolyCounter].Coeffs) + "/"
        }
        encInputStr += ":"
		//encInputStr += fmt.Sprintf("%f", encInput[idx]) + " "
	}
    encInputStr += "\n"

	encInput_cstring = C.CString(encInputStr)

	return
}

//export aggregateEncrypted
func aggregateEncrypted(encInputsCstringList []*C.char, numPeers int,length int, logDegree uint64, scale float64, inputLength int) (encResult_cstring *C.char) {
    var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001

    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
	params, err := ckks.NewParametersFromModuli(logDegree, moduli)

	params.SetScale(scale)
	params.SetLogSlots(logDegree - 1)

    numPieces := 0
	packSize := 2 * int(params.Slots())
	if inputLength%packSize == 0 {
		numPieces = inputLength / packSize
	} else {
		numPieces = inputLength/packSize + 1
	}
	if err != nil {
		panic(err)
	}

    encInputs := make([][]*ckks.Ciphertext, numPeers)
    encClientInputs := make([]string, numPeers)
	for i := range encClientInputs {
		encInputsGostring := C.GoString(encInputsCstringList[i])
        encInput_reader := strings.NewReader(encInputsGostring)
		message, err := bufio.NewReader(encInput_reader).ReadString('\n')
		if err != nil {
			panic(err)
		}
		encClientInputs[i] = message[0 : len(message)-1]
	}

	evaluator := ckks.NewEvaluator(params)
	for encCounter := range encClientInputs {
		encInputs[encCounter] = make([]*ckks.Ciphertext, numPieces)
		crtClient := encClientInputs[encCounter]
		piecesArr := strings.Split(crtClient, ":")
		piecesArr = piecesArr[0 : len(piecesArr)-1]
		if len(piecesArr) != numPieces {
			fmt.Println("Encryted files received incorrectly")
		}
		for pieceCounter := range encInputs[encCounter] {
			crt := piecesArr[pieceCounter]
			polyCoeffsStringArr := strings.Split(crt, "/")
			polyCoeffsStringArr = polyCoeffsStringArr[0 : len(polyCoeffsStringArr)-1]
			ctContents := make([]*ring.Poly, len(polyCoeffsStringArr))
			for ctContentCounter := range ctContents {
				ctContents[ctContentCounter] = ring.NewPoly(params.N(), params.MaxLevel()+1)
				ctContents[ctContentCounter].SetCoefficients(polyCoeffsDecode(polyCoeffsStringArr[ctContentCounter]))
			}
			encInputs[encCounter][pieceCounter] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.Scale())
			encInputs[encCounter][pieceCounter].SetValue(ctContents)
		}
	}
	encResult := make([]*ckks.Ciphertext, numPieces)
	for pieceCounter := range encResult {
		encResult[pieceCounter] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.Scale())
		evaluator.Add(encInputs[0][pieceCounter], encInputs[1][pieceCounter], encResult[pieceCounter])
		for i := 2; i < numPeers; i++ {
			evaluator.Add(encResult[pieceCounter], encInputs[i][pieceCounter], encResult[pieceCounter])
		}
	}
    encResultStr := ""
	for pieceCounter := range encResult {
		for ctPolyCounter := range encResult[pieceCounter].Value() {
			encResultStr += polyCoeffsEncode(encResult[pieceCounter].Value()[ctPolyCounter].Coeffs) + "/"
		}
		encResultStr += ":"
	}
	encResultStr += "\n"
	encResult_cstring = C.CString(encResultStr)
	return
}
