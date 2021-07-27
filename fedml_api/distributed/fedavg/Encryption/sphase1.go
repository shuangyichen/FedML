package main

import (
	"C"
	//"bufio"
	//"fmt"
	//"time"

//	"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/dckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	//"net"
	//"os"
	//"strconv"
	"strings"
	//"sync"
	//"time"
)





//export genCollectivePK
func genCollectivePK(cpkStr string,numPeers int, logDegree uint64, scale float64)(res *C.char){
	var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001
    //cpkStr = cpkStr[1:len(cpkStr)-1]
    //cpkgSharesStr := strings.Split(cpkStr, ",")
    //fmt.Println("genCollectivePK")
	//fmt.Println("numpeers:",numPeers)
    //fmt.Println("logDegree:",logDegree)
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
    //logDegree = 13

    //fmt.Println("numpeers",numPeers) 
    //fmt.Println("scale",scale)   
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
    cpkgSharesStr := strings.Split(cpkStr, ",")
    ckg := dckks.NewCKGProtocol(params)
    cpkgShares := make([]dckks.CKGShare, numPeers)
    pk := ckks.NewPublicKey(params)
	ckgCombined := ckg.AllocateShares()
	//for peerIdx := range clientIPs {
    for Idx:=0;Idx<numPeers;Idx++{
        cpkgstr := cpkgSharesStr[Idx]
        cpkgstrs := strings.Split(cpkgstr,"\n")[0]
        coeffs := polyCoeffsDecode(cpkgstrs)
		poly := ringQP.NewPoly()
		poly.SetCoefficients(coeffs)

		cpkgShares[Idx] = poly

		ckg.AggregateShares(cpkgShares[Idx], ckgCombined, ckgCombined)

	}
	ckg.GenPublicKey(ckgCombined, crs, pk)

    publicKeyStr := ""
	pkContent := pk.Get()
	for itemIdx := range pkContent {
		publicKeyStr += polyCoeffsEncode(pkContent[itemIdx].Coeffs) + "/"
	}
	publicKeyStr += "\n"
    res = C.CString(publicKeyStr)
    return
}
