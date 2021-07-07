package main                                                                                                                                                                       

import (
    "C"
    //"bufio"
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





//export aggregateEncrypted
func aggregateEncrypted(encInputsString string, numPeers int, logDegree uint64, scale float64, inputLength int) (encResult_cstring *C.char) {
    var ringPrime uint64 = 0x10000000001d0001
    var ringPrimeP uint64 = 0xfffffffffffc001
    //fmt.Println("aggregateEncrypted")
    //fmt.Println("numPeers",numPeers)
    //fmt.Println("logDegree",logDegree)
    //fmt.Println("inputLength",inputLength)
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
    encClientInputs := strings.Split(encInputsString, ",")

    encInputs := make([][]*ckks.Ciphertext, numPeers)
    //encClientInputs := make([]string, numPeers)
    for i := range encClientInputs {
        encClientInputs[i] = strings.Split(encClientInputs[i], "\n")[0]
        //encClientInputs[i] = message[0 : len(message)-1]
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

//export genTPK
func genTPK(logDegree uint64, scale float64)(res *C.char, tsk_Cstring *C.char){
    var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001
    //fmt.Println("genTPK")
    //fmt.Println("logDegree",logDegree) 
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
	params, err := ckks.NewParametersFromModuli(logDegree, moduli)
    if err != nil {
		panic(err)
	}
	params.SetScale(scale)
	params.SetLogSlots(logDegree - 1)
    
    tsk, tpk := ckks.NewKeyGenerator(params).GenKeyPair()
    targetPublicKeyStr := ""
	targetPKContent := tpk.Get()

	for itemIdx := range targetPKContent {
		targetPublicKeyStr += polyCoeffsEncode(targetPKContent[itemIdx].Coeffs) + "/"
	}
    tsk_string := polyCoeffsEncode(tsk.Get().Coeffs)
    tsk_string += "\n"
    tsk_Cstring =  C.CString(tsk_string)
	targetPublicKeyStr += "\n"
    res = C.CString(targetPublicKeyStr)
    return
}

//export decrypt
func decrypt(tsk_string string, pcksShareString string, encResultStr string,logDegree uint64, scale float64, inputLength int, numPeers int)(res *C.char){
	var ringPrime uint64 = 0x10000000001d0001
    var ringPrimeP uint64 = 0xfffffffffffc001
    //fmt.Println("decrypt")
    //fmt.Println("logDegree",logDegree)
    //fmt.Println("scale",scale)
    //fmt.Println("inputLength",inputLength)
    //fmt.Println("numPeers",numPeers)
    tsk_string = tsk_string[0:len(tsk_string)]
    //tsk_poly := ring.NewPoly()
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
    params, err := ckks.NewParametersFromModuli(logDegree, moduli)
    if err != nil {
        panic(err)
    }
    params.SetScale(scale)
    params.SetLogSlots(logDegree - 1)
    //tsk_poly := ring.NewPoly(params.N())
    numPieces := 0
    //inputLength := len(inputs)
    packSize := 2 * int(params.Slots())
    if inputLength%packSize == 0 {
        numPieces = inputLength / packSize
    } else {
        numPieces = inputLength/packSize + 1
    }
    
    tsk, _ := ckks.NewKeyGenerator(params).GenKeyPair()
    //tsk_poly = ring
    //tsk.Set(polyCoeffsDecode(tsk_string))
    ringQP, _ := ring.NewRing(params.N(), append(params.Qi(), params.Pi()...))
    ringQ, _ := ring.NewRing(params.N(), params.Qi())
    tsk_poly := ringQP.NewPoly()
    tsk_poly.SetCoefficients(polyCoeffsDecode(tsk_string))
    tsk.Set(tsk_poly)

    pcks := dckks.NewPCKSProtocol(params, 3.19)
    pieceArr := strings.Split(encResultStr, ":")
    pieceArr = pieceArr[0 : len(pieceArr)-1]
    encResult := make([]*ckks.Ciphertext, numPieces)
    for pieceCounter := range pieceArr {
        message := pieceArr[pieceCounter]
        polyCoeffsStringArr := strings.Split(message, "/")
        polyCoeffsStringArr = polyCoeffsStringArr[0 : len(polyCoeffsStringArr)-1]
        ctContents := make([]*ring.Poly, len(polyCoeffsStringArr))
        for ctContentCounter := range ctContents {
            ctContents[ctContentCounter] = ring.NewPoly(params.N(), params.MaxLevel()+1)
            ctContents[ctContentCounter].SetCoefficients(polyCoeffsDecode(polyCoeffsStringArr[ctContentCounter]))
        }
        encResult[pieceCounter] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.Scale())
        encResult[pieceCounter].SetValue(ctContents)                                                                                                                               

    }
 
    pcksShares := make([][]dckks.PCKSShare, numPeers)
    pcksCombined := make([]dckks.PCKSShare, numPieces)
	for i := range pcksCombined {
		pcksCombined[i] = pcks.AllocateShares(params.MaxLevel())
	}
    pcksSharesStr := strings.Split(pcksShareString, ",")
	for peerIdx := range pcksShares {
		//if decryptionParticipation[peerIdx] == 1 {
			pcksShares[peerIdx] = make([]dckks.PCKSShare, numPieces)
            pcksShareStr  := pcksSharesStr[peerIdx]
            crtStrPiece := pcksShareStr[0 : len(pcksShareStr)-1]
			crtStrPieceArr := strings.Split(crtStrPiece, ":")
			crtStrPieceArr = crtStrPieceArr[0 : len(crtStrPieceArr)-1]
			if len(crtStrPieceArr) != numPieces {
				fmt.Println("pcks error!")
			}
			for pieceCounter := range pcksShares[peerIdx] {
				crtStr := crtStrPieceArr[pieceCounter]
				polyCoeffStr := strings.Split(crtStr, "/")
				pcksShares[peerIdx][pieceCounter] = pcks.AllocateShares(params.MaxLevel())
				for contentCounter := range pcksShares[peerIdx][pieceCounter] {
					pcksShares[peerIdx][pieceCounter][contentCounter] = ringQ.NewPolyLvl(params.MaxLevel())
					pcksShares[peerIdx][pieceCounter][contentCounter].SetCoefficients(polyCoeffsDecode(polyCoeffStr[contentCounter]))
				}
				pcks.AggregateShares(pcksShares[peerIdx][pieceCounter], pcksCombined[pieceCounter], pcksCombined[pieceCounter])
			}
	//	}
	}
	encOut := make([]*ckks.Ciphertext, numPieces)
	decryptor := ckks.NewDecryptor(params, tsk)
	encoder := ckks.NewEncoder(params)
	ptres := ckks.NewPlaintext(params, params.MaxLevel(), params.Scale())
	output := make([]float64, numPieces*packSize)
	for pieceCounter := range encOut {
		encOut[pieceCounter] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.Scale())
		pcks.KeySwitch(pcksCombined[pieceCounter], encResult[pieceCounter], encOut[pieceCounter])
		decryptor.Decrypt(encOut[pieceCounter], ptres)
		tmp := encoder.Decode(ptres, params.Slots())
		for i := 0; i < int(params.Slots()); i++ {
			output[pieceCounter*packSize+i*2] = real(tmp[i])
			output[pieceCounter*packSize+i*2+1] = imag(tmp[i])
		}
	}
	output = output[0:inputLength]
	//fmt.Println(output[19990:])
	outputStr := ""
	for idx := range output {
		outputStr += fmt.Sprintf("%f", output[idx]) + " "
	}

	res = C.CString(outputStr)
    return

}
