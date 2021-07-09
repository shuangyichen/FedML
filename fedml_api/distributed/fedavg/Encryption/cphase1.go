package main

import (
	"C"
	//"bufio"
	"fmt"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/dckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	//"math/rand"
	//"net"
	//"os"
	"strconv"
	//"strings"
	//"time"
)
// type party struct {
// 	sk           []*ckks.SecretKey
// 	secretShares []*ring.Poly
// 	shamirShare  *ring.Poly
// 	ckgShare     dckks.CKGShare
// 	pcksShare    []dckks.PCKSShare
// 	input        [][]complex128
// }


//export genShamirShares
func genShamirShares(numPeers int,robust bool, logDegree uint64, scale float64, resiliency float64)(res *C.char){
	var ringPrime uint64 = 0x10000000001d0001
	var ringPrimeP uint64 = 0xfffffffffffc001
    k := int(float64(numPeers) * (1 - resiliency))
	if k == 0 {
		k = 1
	}
    fmt.Println("genShamirShares")
    fmt.Println("numPeers",numPeers)
    fmt.Println("logDegree",logDegree)
    fmt.Println("resiliency",resiliency)
    fmt.Println("scale",scale)
    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
	params, err := ckks.NewParametersFromModuli(logDegree, moduli)
	params.SetScale(scale)
	params.SetLogSlots(logDegree - 1)
	//lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}
	///////// Ring for the common reference polynomials sampling
	ringQP, _ := ring.NewRing(params.N(), append(params.Qi(), params.Pi()...))
	///////// Common reference polynomial generator that uses the PRNG
	//crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
	//crs := crsGen.ReadNew() // for the public-key

	///////// Target private and public keys
	ckg := dckks.NewCKGProtocol(params)

	///////// create the party object and setup keys
	pi := &party{}
	if robust {
		evalPoints := make([]uint64, numPeers)
		for i := 0; i < numPeers; i++ {
			evalPoints[i] = uint64(i) + 1
		}
		pi.sk = make([]*ckks.SecretKey, k, k)
		pi.secretShares = make([]*ring.Poly, numPeers, numPeers)
		///////// create k different secret keys for each party
		for partyCntr := 0; partyCntr < k; partyCntr++ {
			pi.sk[partyCntr] = ckks.NewKeyGenerator(params).GenSecretKey()
		}
		///////// create the shares of the secret key
		//fmt.Println("Generating shamir shares")
		for partyCntr := 0; partyCntr < numPeers; partyCntr++ {
			vandermonde := GenerateVandermonde(evalPoints[partyCntr], uint64(k), ringPrime)
			res := ringQP.NewPoly()
			ringQP.MulScalar(pi.sk[0].Get(), vandermonde[0], res)
			for i := 1; i < k; i++ {
				tmp := ringQP.NewPoly()
				ringQP.MulScalar(pi.sk[i].Get(), vandermonde[i], tmp)
				ringQP.Add(tmp, res, res)
			}
			pi.secretShares[partyCntr] = res
		}
	} else {
		pi.sk = make([]*ckks.SecretKey, 1, 1)
		///////// create k different secret keys for each party
		pi.sk[0] = ckks.NewKeyGenerator(params).GenSecretKey()
	}
	///////// Create party, and allocate the memory for all the shares that the protocols will need
	pi.ckgShare = ckg.AllocateShares()
    toSendString := "" 
	if robust {
		////// transmit shamir shares to others
		//toSendString := ""
		for clientIndex, share := range pi.secretShares {
			coeffString := polyCoeffsEncode(share.Coeffs)
			toSendString += strconv.Itoa(clientIndex) + "/" + coeffString + ":"
		}
		toSendString += "\n"
	}
	res = C.CString(toSendString)
	return
}

//export genCollectiveKeyShair_not_robust
func genCollectiveKeyShair_not_robust(numPeers int,robust bool, logDegree uint64, scale float64, resiliency float64)(res *C.char, shamirShareString *C.char){
    var ringPrime uint64 = 0x10000000001d0001
    var ringPrimeP uint64 = 0xfffffffffffc001
    k := int(float64(numPeers) * (1 - resiliency))
    if k == 0 {
        k = 1
    }
    //fmt.Println("genCollectiveKeyShair_not_robust")
    //fmt.Println("numPeers",numPeers)
    //fmt.Println("logDegree",logDegree)
    //fmt.Println("resiliency",resiliency)
    //fmt.Println("scale",scale)

    moduli := &ckks.Moduli{Qi: []uint64{ringPrime}, Pi: []uint64{ringPrimeP}}
    //fmt.Println("client go log Degree",logDegree)  
    params, err := ckks.NewParametersFromModuli(logDegree, moduli)
    params.SetScale(scale)
    params.SetLogSlots(logDegree - 1)
    lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
    if err != nil {
        panic(err)
    }
    ///////// Ring for the common reference polynomials sampling
    ringQP, _ := ring.NewRing(params.N(), append(params.Qi(), params.Pi()...))
    ///////// Common reference polynomial generator that uses the PRNG
    crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
    crs := crsGen.ReadNew() // for the public-key

    ///////// Target private and public keys
    ckg := dckks.NewCKGProtocol(params)

    ///////// create the party object and setup keys
    pi := &party{}
    pi.sk = make([]*ckks.SecretKey, 1, 1)
        ///////// create k different secret keys for each party
    pi.sk[0] = ckks.NewKeyGenerator(params).GenSecretKey()
    
    pi.ckgShare = ckg.AllocateShares()
    //toSendString := ""

    ///////// Collective public key generation
	ckg.GenShare(pi.sk[0].Get(), crs, pi.ckgShare)
	///////// Transmit collective key generation share to the master
	toSendString := polyCoeffsEncode(pi.ckgShare.Coeffs) + "\n"
    res = C.CString(toSendString)
    shamirShareString = C.CString(polyCoeffsEncode(pi.sk[0].Get().Coeffs))
    return
}
