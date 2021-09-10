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
    "strconv"
    "strings"
    //"time"
    "unsafe"
)

//export genDecryptionCoefficients
func genDecryptionCoefficients(clientsParticipated string)(res_Cstring *C.char){
    var ringPrime uint64 = 0x10000000001d0001
    clientsParticipated_list := strings.Split(clientsParticipated,",")
    evalPointsParticipated := make([]uint64, len(clientsParticipated_list))
    for idx:= range clientsParticipated_list{
        evalPointsParticipated[idx],_ = strconv.ParseUint(clientsParticipated_list[idx], 10, 64)
    }
		tmpCoefficients := GenerateVandermondeInverse(evalPointsParticipated, ringPrime)
		//for peerIdx := range clientIPs {
    res := ""
    for idx:= range clientsParticipated_list{
		res += clientsParticipated_list[idx]
        res += ":"
        res += strconv.FormatUint(tmpCoefficients[idx],10)
        res += ","
        //decryptionCoefficients[peerIdx] = tmpCoefficients[tmpCntr]
	}
    res += "\n"
    res_Cstring = C.CString(res)
    return

}




//export aggregateEncrypted
func aggregateEncrypted(encInputList []uint64, numPeers int, logDegree uint64, scale float64, inputLength int) (encResultList uintptr, numPieces int) {
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

    numPieces = 0
    packSize := 2 * int(params.Slots())
    if inputLength%packSize == 0 {
        numPieces = inputLength / packSize
    } else {
        numPieces = inputLength/packSize + 1
    }
    if err != nil {
        panic(err)
    }
    encClientInputs := unsqueezedArray(encInputList, numPeers)

    //fmt.Println("encClientInputs",encInputList[0:10])
    //fmt.Println("encClientInputs width",len(encClientInputs[0]))
    encInputs := make([][]*ckks.Ciphertext, numPeers)

    evaluator := ckks.NewEvaluator(params)
    for encCounter := range encClientInputs {
        encInputs[encCounter] = make([]*ckks.Ciphertext, numPieces)
        crtClient := encClientInputs[encCounter]
        piecesArr := unsqueezedArray(crtClient, numPieces)
        //fmt.Println("piecesArr",len(piecesArr))
        // fmt.Println("piecesArr height",len(piecesArr[0]))
        //fmt.Println("numPieces",numPieces)
        if len(piecesArr) != numPieces {
            fmt.Println("Encryted files received incorrectly")
        }
        for pieceCounter := range encInputs[encCounter] {
            crt := piecesArr[pieceCounter]
            polyCoeffsArr := unsqueezedArray(crt,2)
            //fmt.Println("len of polyCoeffsArr",len(polyCoeffsArr))
            //fmt.Println("polyCoeffsArr height", len(polyCoeffsArr[0]))
            ctContents := make([]*ring.Poly, len(polyCoeffsArr))
            for ctContentCounter := range ctContents {
                ctContents[ctContentCounter] = ring.NewPoly(params.N(), params.MaxLevel()+1)
                ctContents[ctContentCounter].SetCoefficients(unsqueezedArray(polyCoeffsArr[ctContentCounter],1))
                //tmp :=unsqueezedArray(polyCoeffsArr[ctContentCounter],1)
                //fmt.Println("len of tmp",len(tmp))
                //fmt.Println("tmp height", len(tmp[0]))
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

    encResultArray := make([][]uint64, numPieces)
    for pieceCounter := range encResult {
        encTmpArray := make([][]uint64, numPeers)
        for ctPolyCounter := range encResult[pieceCounter].Value() {
            encTmpArray[ctPolyCounter] = squeezedArray(encResult[pieceCounter].Value()[ctPolyCounter].Coeffs)
        }
        encResultArray[pieceCounter]  = squeezedArray(encTmpArray)
        //fmt.Println("encResultArray",len(encResultArray[pieceCounter]))
    }
    squeezed_encResultArray_Length := numPieces * len(encResultArray[0])
    squeezed_encResultArray := make([]uint64,squeezed_encResultArray_Length)
    squeezed_encResultArray = squeezedArray(encResultArray)
    fmt.Println("squeezed_encResultArray last 2 ", squeezed_encResultArray[squeezed_encResultArray_Length-2:])
    encResultList = uintptr(unsafe.Pointer(&squeezed_encResultArray[0]))



    return
}

//export genTPK
func genTPK(logDegree uint64, scale float64)(tpkPointer uintptr, tskPointer uintptr){
    var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
	params, err := ckks.NewParametersFromModuli(logDegree, moduli)
    if err != nil {
		panic(err)
	}
	params.SetScale(scale)
	params.SetLogSlots(logDegree - 1)

    tsk, tpk := ckks.NewKeyGenerator(params).GenKeyPair()
    //targetPublicKeyStr := ""
	targetPKContent := tpk.Get()
    tpkArray := make([][]uint64,len(targetPKContent))
	for itemIdx := range targetPKContent {
        tpkArray[itemIdx] = squeezedArray(targetPKContent[itemIdx].Coeffs)
        //targetPublicKeyStr += polyCoeffsEncode(targetPKContent[itemIdx].Coeffs) + "/"
	}
    tpkheight := len(tpkArray[0])
    tpkLength := tpkheight*len(targetPKContent)
    tskheight := len(tsk.Get().Coeffs[0])
    tskLength := tskheight*len(tsk.Get().Coeffs)

    tskArray := make([]uint64,tskLength)
    tskArray = squeezedArray(tsk.Get().Coeffs)
    tskPointer = uintptr(unsafe.Pointer(&tskArray[0]))
    tpkList := make([]uint64,tpkLength)
    tpkList = squeezedArray(tpkArray)
    tpkPointer = uintptr(unsafe.Pointer(&tpkList[0]))

    return
}

//export decrypt
func decrypt(client_chosen string,tskList []uint64, pcksShareList []uint64, encResultList []uint64,logDegree uint64, scale float64, inputLength int, numPeers int)(decrypted uintptr){
	var ringPrime uint64 = 0x10000000001d0001
    var ringPrimeP uint64 = 0xfffffffffffc001
    //fmt.Println("decrypt")
    //fmt.Println("logDegree",logDegree)
    //fmt.Println("scale",scale)
    //fmt.Println("inputLength",inputLength)
    //fmt.Println("numPeers",numPeers)

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
    tsk := ckks.NewSecretKey(params)
    //tsk, _ := ckks.NewKeyGenerator(params).GenKeyPair()
    //tsk_poly = ring
    //tsk.Set(polyCoeffsDecode(tsk_string))
    ringQP, _ := ring.NewRing(params.N(), append(params.Qi(), params.Pi()...))
    ringQ, _ := ring.NewRing(params.N(), params.Qi())
    tsk_poly := ringQP.NewPoly()
    tsk_poly.SetCoefficients(unsqueezedArray(tskList,2))
    tsk.Set(tsk_poly)

    pcks := dckks.NewPCKSProtocol(params, 3.19)
    pieceArr := unsqueezedArray(encResultList,numPieces)
    encResult := make([]*ckks.Ciphertext, numPieces)
    for pieceCounter := range pieceArr {
        message := pieceArr[pieceCounter]
        polyCoeffsArr := unsqueezedArray(message,2)
        ctContents := make([]*ring.Poly, len(polyCoeffsArr))
        for ctContentCounter := range ctContents {
            ctContents[ctContentCounter] = ring.NewPoly(params.N(), params.MaxLevel()+1)
            ctContents[ctContentCounter].SetCoefficients(unsqueezedArray(polyCoeffsArr[ctContentCounter],1))
        }
        encResult[pieceCounter] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.Scale())
        encResult[pieceCounter].SetValue(ctContents)
    }
    //clients := strings.Split(client_chosen,",")
    pcksShares := make([][]dckks.PCKSShare, numPeers)
    pcksCombined := make([]dckks.PCKSShare, numPieces)
	for i := range pcksCombined {
		pcksCombined[i] = pcks.AllocateShares(params.MaxLevel())
	}
    pcksSharesArray := unsqueezedArray(pcksShareList,numPeers)
	for peerIdx := range pcksShares {
    //for Idx:= range clients{
		//if decryptionParticipation[peerIdx] == 1 {
			//peerIdx, err := strconv.Atoi(clients[Idx])
            if err != nil {
                panic(err)
            }
            //peerIdx = peerIdx-1

            pcksShares[peerIdx] = make([]dckks.PCKSShare, numPieces)
            pcksSharePiece  := pcksSharesArray[peerIdx]
			crtPieceArr := unsqueezedArray(pcksSharePiece, numPieces)
			if len(crtPieceArr) != numPieces {
				fmt.Println("pcks error!")
			}
			for pieceCounter := range pcksShares[peerIdx] {
				crt := crtPieceArr[pieceCounter]
				polyCoeff := unsqueezedArray(crt,2)
				pcksShares[peerIdx][pieceCounter] = pcks.AllocateShares(params.MaxLevel())
				for contentCounter := range pcksShares[peerIdx][pieceCounter] {
					pcksShares[peerIdx][pieceCounter][contentCounter] = ringQ.NewPolyLvl(params.MaxLevel())
					pcksShares[peerIdx][pieceCounter][contentCounter].SetCoefficients(unsqueezedArray(polyCoeff[contentCounter],1))
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
    fmt.Println("output",output[inputLength-2:inputLength])
    decrypted = uintptr(unsafe.Pointer(&output[0]))
    return
}
