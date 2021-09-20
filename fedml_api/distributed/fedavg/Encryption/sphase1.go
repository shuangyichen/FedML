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





//export genCollectivePK
func genCollectivePK(cpk []uint64,numPeers int, logDegree uint64, scale float64)(res uintptr){
	//var ringPrime uint64 = 0x10000000001d0001
	var ringPrime uint64 = 0xfffffffffffc001
    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}

    //params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65537)
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
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
