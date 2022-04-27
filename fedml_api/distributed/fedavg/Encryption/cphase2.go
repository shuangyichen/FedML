package main

import (
    "C"
    //"bufio"
    "fmt"
    //"github.com/ldsec/lattigo/v2/ckks"
    //"github.com/ldsec/lattigo/v2/dckks"
    "github.com/ldsec/lattigo/v2/ring"
    "github.com/ldsec/lattigo/v2/bfv"
    "github.com/ldsec/lattigo/v2/dbfv"
    //"github.com/ldsec/lattigo/v2/utils"
    //"math/rand"
    //"net"
    //"os"
    //"strconv"
    //"strings"
    "unsafe"
    //"time"
)

type party struct {
    sk           []*bfv.SecretKey
    secretShares []*ring.Poly
    shamirShare  *ring.Poly
    ckgShare     dbfv.CKGShare
    pcksShare    []dbfv.PCKSShare
    input        [][]int64
}

var encInput []*bfv.Ciphertext
//export encryptMsg
func encryptMsg(inputs []int64, cpk []uint64, shamirShare []uint64, robust bool, logDegree uint64, scale float64, numPeers int) (encInputList uintptr, numPieces int) {
    //var ringPrime uint64 = 0x10000000001d0001
    var ringPrime uint64 = 0xfffffffffffc001
    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,65537)
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,2652353003)
    //params.SetScale(scale)
    //params.SetLogSlots(logDegree - 1)
    if err != nil {
        panic(err)
    }
    ///////// Ring for the common reference polynomials sampling
    ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    //ringQ, _ := ring.NewRing(1<<params.LogN(), params.Qi())
    ///////// Common reference polynomial generator that uses the PRNG
    //pcks := dckks.NewPCKSProtocol(params, 3.19)
    ///////// generate evaluation points for secret sharing
    shamirShareArray := unsqueezedArray(shamirShare,2)
    ///////// create the party object and setup keys
    pi := &party{}
    pi.shamirShare = ringQP.NewPoly()
    pi.shamirShare.SetCoefficients(shamirShareArray)
    ///////// Create party, and allocate the memory for all the shares that the protocols will need
    // creating inputs
    numPieces = 0
    inputLength := len(inputs)
    //fmt.Println("input length",inputLength)
    packSize := 8192//2 * int(params.Slots())
    if inputLength%packSize == 0 {
        numPieces = inputLength / packSize
    } else {
        numPieces = inputLength/packSize + 1
    }
    //fmt.Println("Working with ", numPieces, " pieces")
    //pi.input = make([][]complex128, numPieces)
    pi.input = make([][]int64, numPieces) 
    for i := 0; i < numPieces; i++ {
        //pi.input[i] = make([]complex128, 8192)
        pi.input[i] = make([]int64, 8192)

        for j := range pi.input[i] {
            if i*packSize+j < inputLength{
                pi.input[i][j] = inputs[i*packSize+j]
            } else{
                pi.input[i][j] = int64(0)
            }
        }
    }
    pi.pcksShare = make([]dbfv.PCKSShare, numPieces)
    /// set the collective public key
    cpk_unsqueezed := unsqueezedArray(cpk,2)
    var itemsPoly [2]*ring.Poly
    for counter := range itemsPoly {
        tmp := unsqueezedArray(cpk_unsqueezed[counter],2)
        itemsPoly[counter] = ringQP.NewPoly()
        itemsPoly[counter].SetCoefficients(tmp)
    }

    //itemsString := strings.Split(cpk, "/")
    //itemsString = itemsString[0 : len(itemsString)-1]
    //if len(itemsString) != 2 {
    //    fmt.Println("Collective Public Key error")
    //    return
    //}
    //var itemsPoly [2]*ring.Poly
   // for counter := range itemsPoly {
    //    tmp := polyCoeffsDecode(itemsString[counter])
    //    itemsPoly[counter] = ringQP.NewPoly()
    //    itemsPoly[counter].SetCoefficients(tmp)
    //}

    pk := bfv.NewPublicKey(params)
    pk.Set(itemsPoly)
    //fmt.Println("Public key installed")
    //startTime = time.Now()

    ///////// Encrypt and transmit
    encInput = make([]*bfv.Ciphertext, numPieces)
    encryptor := bfv.NewEncryptorFromPk(params, pk)
    encoder := bfv.NewEncoder(params)
    //fmt.Println("Encryption threads launched")
    for pieceCounter := range encInput {
        encInput[pieceCounter] = bfv.NewCiphertext(params, 1)
        pt := bfv.NewPlaintext(params)
        encoder.EncodeInt(pi.input[pieceCounter], pt)
        encryptor.Encrypt(pt, encInput[pieceCounter])
    }

    encInputArray  := make([][]uint64,numPieces)
    for idx := range encInput {
        //fmt.Println("encinput length", len(encInput[idx].Value()))
        encinput := make([][]uint64, len(encInput[idx].Value()))
        for ctPolyCounter := range encInput[idx].Value(){
            encinput[ctPolyCounter] = squeezedArray(encInput[idx].Value()[ctPolyCounter].Coeffs)
            //tmp := encInput[idx].Value()[ctPolyCounter].Coeffs
            //fmt.Println("tmp size",len(tmp))
            //fmt.Println("tmp size", len(tmp[0]))
        }
        encInputArray[idx] = squeezedArray(encinput)
    }
    squeezed_encInputArrayLength := numPieces* len(encInputArray[0])
    squeezed_encInputArray := make([]uint64, squeezed_encInputArrayLength)
    squeezed_encInputArray = squeezedArray(encInputArray)
    //fmt.Println("len of squeezed_encInputArray", len(squeezed_encInputArray))
    //for idx := range squeezed_encInputArray{
    //    if squeezed_encInputArray[idx] ==0{
    //        fmt.Println(idx)
    //    }
    //}

    fmt.Println("squeezed_encInputArray",squeezed_encInputArray[squeezed_encInputArrayLength-2:])
    encInputList = uintptr(unsafe.Pointer(&squeezed_encInputArray[0]))


    return
}

//export genPCKSShare
func genPCKSShare(enc_aggr_model []uint64, TPK []uint64,shamirShareString []uint64,numPeers int,  decryptionCoefficient uint64,inputLength int,robust bool, logDegree uint64, scale float64)(res uintptr){
    //var ringPrime uint64 = 0x10000000001d0001
    var ringPrime uint64 = 0xfffffffffffc001
    //fmt.Println("enc_aggr_model",enc_aggr_model[0:10])
    //fmt.Println("shamirShareString",shamirShareString[0:10])
    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
	//params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65537)
	params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,2652353003)
    //params.SetScale(scale)
	//params.SetLogSlots(logDegree - 1)
	if err != nil {
		panic(err)
	}
    numPieces := 0
	//inputLength := len(inputs)
	packSize := 8192//2 * int(params.Slots())
	if inputLength%packSize == 0 {
		numPieces = inputLength / packSize
	} else {
		numPieces = inputLength/packSize + 1
	}
    //fmt.Println("numpieces",numPieces)
	///////// Ring for the common reference polynomials sampling
	ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    pcks := dbfv.NewPCKSProtocol(params, 3.19)

    pi := &party{}
    pi.shamirShare = ringQP.NewPoly()
	pi.shamirShare.SetCoefficients(unsqueezedArray(shamirShareString, 2))

    pieceArr := unsqueezedArray(enc_aggr_model, numPieces)
	encResult := make([]*bfv.Ciphertext, numPieces)
	for pieceCounter := range pieceArr {
        message := pieceArr[pieceCounter]
		polyCoeffsArr := unsqueezedArray(message,2)

		ctContents := make([]*ring.Poly, len(polyCoeffsArr))
		for ctContentCounter := range ctContents {
			ctContents[ctContentCounter] = ring.NewPoly(params.N(),1)
			ctContents[ctContentCounter].SetCoefficients(unsqueezedArray(polyCoeffsArr[ctContentCounter],1))
		}
		encResult[pieceCounter] = bfv.NewCiphertext(params, 1)
		encResult[pieceCounter].SetValue(ctContents)

	}


    //itemsString := strings.Split(TPK, "/")
    //		itemsString = itemsString[0 : len(itemsString)-1]
    tpkArray := unsqueezedArray(TPK,2)
		if len(tpkArray) != 2 {
			//fmt.Println("Target Public Key error")
			return
		}
		var itemsPoly [2]*ring.Poly
		for counter := range itemsPoly {
			tmp := unsqueezedArray(tpkArray[counter],2)
			itemsPoly[counter] = ringQP.NewPoly()
			itemsPoly[counter].SetCoefficients(tmp)
		}
		tpk := bfv.NewPublicKey(params)
		tpk.Set(itemsPoly)
		//fmt.Println("Target public key receieved")
		/////// Generate collective public key switch share and transmit
		//fmt.Println("Generating pcks share")
		pi.pcksShare = make([]dbfv.PCKSShare, numPieces)
        for pieceCounter := range pi.pcksShare {
			pi.pcksShare[pieceCounter] = pcks.AllocateShares()
			if robust {
				scaledSecretKey := ringQP.NewPoly()
				ringQP.MulScalar(pi.shamirShare, decryptionCoefficient, scaledSecretKey)
				pcks.GenShare(scaledSecretKey, tpk, encResult[pieceCounter], pi.pcksShare[pieceCounter])

			} else {
				pcks.GenShare(pi.shamirShare, tpk, encResult[pieceCounter], pi.pcksShare[pieceCounter])
			}
		}
        pcksShareList := make([][]uint64,numPieces)
		for pieceCounter := range pi.pcksShare {
            pckstmp := make([][]uint64,numPeers)
			for i := range pi.pcksShare[pieceCounter] {
				pckstmp[i] = squeezedArray(pi.pcksShare[pieceCounter][i].Coeffs)
			}
			pcksShareList[pieceCounter] = squeezedArray(pckstmp)
		}
        squeezedpcksShareListLength := numPieces* len(pcksShareList[0])
      //  fmt.Println("pcks length", squeezedpcksShareListLength)
        squeezedpcksShareList := make([]uint64,squeezedpcksShareListLength)
        squeezedpcksShareList = squeezedArray(pcksShareList)

    fmt.Println("squeezedpcksShareList",squeezedpcksShareList[squeezedpcksShareListLength-2:])

    res = uintptr(unsafe.Pointer(&squeezedpcksShareList[0]))


  return

}
