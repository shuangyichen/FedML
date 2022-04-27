package main

import (
	"C"
	//"bufio"
	//"fmt"
	//"time"

	//"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"github.com/ldsec/lattigo/v2/bfv"
    "github.com/ldsec/lattigo/v2/dbfv"
    //"net"
	//"os"
	//"strconv"
	//"strings"
	//"sync"
	//"time"
    "unsafe"
)

//export genSKforNewUser
func genSKforNewUser(k int,logDegree uint64, shareList []uint64)(sharePointer uintptr){
    var ringPrime uint64 = 0xfffffffffffc001
    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    if err != nil {
        panic(err)
    }
    ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    pi := &party{}
    shareArray := unsqueezedArray(shareList, k)
    Shares := make([]*ring.Poly, k)
    for partyCounter := 0; partyCounter < k; partyCounter++ {
            share := shareArray[partyCounter]
            polyCoeff := unsqueezedArray(share,2)
            Shares[partyCounter] = ringQP.NewPoly()
            Shares[partyCounter].SetCoefficients(polyCoeff)
    }
    pi.shamirShare = ringQP.NewPoly()
        ringQP.Add(Shares[0], Shares[1], pi.shamirShare)
        for i := 2; i < k; i++ {
            ringQP.Add(pi.shamirShare, Shares[i], pi.shamirShare)
        }
    Share_array := pi.shamirShare.Coeffs
    shareLength := len(pi.shamirShare.Coeffs) * len(pi.shamirShare.Coeffs[0])
    newshareList := make([]uint64,shareLength)
    newshareList = squeezedArray(Share_array)
    sharePointer = uintptr(unsafe.Pointer(&newshareList[0]))
    //fmt.Println("new user ss length")
    //fmt.Println(len(pi.shamirShare.Coeffs))
    //fmt.Println(len(pi.shamirShare.Coeffs[0]))
    return
}

//export genShamirsharesforUser
func genShamirsharesforUser(shamirShare []uint64, numPeers int, logDegree uint64)(SSPointer uintptr){
    var ringPrime uint64 = 0x10000000001d0001
    //var ringPrimeP uint64 = 0xfffffffffffc001

    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    if err != nil {
        panic(err)
    }
    ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    shamirShareArray := unsqueezedArray(shamirShare, numPeers)
    pi := &party{}
    secretShares := make([]*ring.Poly, numPeers*numPeers)
    for partyCounter := 0; partyCounter < numPeers; partyCounter++ {
        share_i := shamirShareArray[partyCounter]
        share := unsqueezedArray(share_i,numPeers)
        for counter:=0; counter<numPeers; counter++{
            ss := share[counter]
            polyCoeff := unsqueezedArray(ss,2)
            secretShares[partyCounter*numPeers+counter] = ringQP.NewPoly()
            secretShares[partyCounter*numPeers+counter].SetCoefficients(polyCoeff)
        }
    }
    pi.secretShares = make([]*ring.Poly, numPeers)
    for o_idx:= 0;o_idx<numPeers;o_idx++{
        res := ringQP.NewPoly()
        ringQP.Add(secretShares[o_idx], secretShares[1*numPeers+o_idx], res)
        for in_idx:=2;in_idx<numPeers;in_idx++{
        ringQP.Add(res, secretShares[in_idx*numPeers+o_idx], res)
        //pi.secretShares[o_idx] = res
    }
    pi.secretShares[o_idx] = res
    }
    secretSharesArray := make([][]uint64,numPeers)
    for clientIndex, share := range pi.secretShares {
            secretSharesArray[clientIndex] = squeezedArray(share.Coeffs)
        }
    secretShareArrayHeight := len(secretSharesArray[0])
    secretShareLength := numPeers*secretShareArrayHeight
    secretSharesList := make([]uint64,secretShareLength)
    //fmt.Println("secretSharesList",secretShareLength)                         
    secretSharesList = squeezedArray(secretSharesArray)
    //fmt.Println("secretSharesList",secretSharesList[0:5])
    SSPointer = uintptr(unsafe.Pointer(&secretSharesList[0]))
    return

}


//export genCollectivePK
func genCollectivePK(cpk []uint64,numPeers int, logDegree uint64, scale float64)(res uintptr){
	//var ringPrime uint64 = 0x10000000001d0001
	var ringPrime uint64 = 0xfffffffffffc001
    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}

    //params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65537)
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,2652353003)
    if err != nil {
        panic(err)
    }
	//params.SetScale(scale)
	//params.SetLogSlots(logDegree - 1)
    lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}
	ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    //ringQ, _ := ring.NewRing(1<<params.LogN(), params.Qi())
    crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
	crs := crsGen.ReadNew() // for the public-key
    ckg := dbfv.NewCKGProtocol(params)

    cpkgShares := make([]dbfv.CKGShare, numPeers)

    pk := bfv.NewPublicKey(params)

    ckgCombined := ckg.AllocateShares()

    coeffsArray := unsqueezedArray(cpk, numPeers)//for peerIdx := range clientIPs {
    for Idx:=0;Idx<numPeers;Idx++{
        coeffs := unsqueezedArray(coeffsArray[Idx], 2)
        poly := ringQP.NewPoly()
        poly.SetCoefficients(coeffs)
		cpkgShares[Idx] = dbfv.CKGShare{poly}
		ckg.AggregateShares(cpkgShares[Idx], ckgCombined, ckgCombined)
        //ckg.AggregateShares(poly, ckgCombined, ckgCombined)
	}



	ckg.GenPublicKey(ckgCombined, crs, pk)
    //ckg1.GenPublicKey(ckgCombined1, crs, pk1)
    pkContent := pk.Get()
    publicKey := make([][]uint64, len(pkContent))
	//pkContent := pk.Get()
	for itemIdx := range pkContent {
		publicKey[itemIdx] = squeezedArray(pkContent[itemIdx].Coeffs)
    }
    PK := squeezedArray(publicKey)
    //fmt.Println("publicKey array last 5",PK[len(PK)-10:])
    //fmt.Println("publicKey array",len(PK))
    p := unsafe.Pointer(&PK)
    s := *(*[]uint64)(p)
    res = uintptr(unsafe.Pointer(&s[0]))

    return
}
