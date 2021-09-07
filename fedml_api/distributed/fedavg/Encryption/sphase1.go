package main

import (
	"C"
	//"bufio"
	//"fmt"
	//"time"

	//"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/dckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
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
	var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}

    params, err := ckks.NewParametersFromModuli(logDegree, moduli)
    if err != nil {
        panic(err)
    }
	params.SetScale(scale)
	params.SetLogSlots(logDegree - 1)
    lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}
	ringQP, _ := ring.NewRing(params.N(), append(params.Qi(), params.Pi()...))
    crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
	crs := crsGen.ReadNew() // for the public-key
    ckg := dckks.NewCKGProtocol(params)

    cpkgShares := make([]dckks.CKGShare, numPeers)

    pk := ckks.NewPublicKey(params)

    ckgCombined := ckg.AllocateShares()

    coeffsArray := unsqueezedArray(cpk, numPeers)//for peerIdx := range clientIPs {
    for Idx:=0;Idx<numPeers;Idx++{
        coeffs := unsqueezedArray(coeffsArray[Idx], 2)
        poly := ringQP.NewPoly()
		poly.SetCoefficients(coeffs)

		cpkgShares[Idx] = poly

		ckg.AggregateShares(cpkgShares[Idx], ckgCombined, ckgCombined)

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

    //fmt.Println("publicKey array",len(PK))
    p := unsafe.Pointer(&PK)
    s := *(*[]uint64)(p)
    res = uintptr(unsafe.Pointer(&s[0]))

    return
}
