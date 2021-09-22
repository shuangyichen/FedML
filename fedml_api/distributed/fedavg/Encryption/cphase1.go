package main

import (
	"C"
	//"bufio"
    //"fmt"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"github.com/ldsec/lattigo/v2/bfv"
    "github.com/ldsec/lattigo/v2/dbfv"
    //"math/rand"
	//"net"
	//"os"
	//"strconv"
	//"strings"
	//"time"
    "unsafe"
)



//export genShamirShareString_robust
func genShamirShareString_robust(shamirShare []uint64, numPeers int, k int, logDegree uint64, scale float64,resiliency float64)(shamirSharePointer uintptr){
    var ringPrime uint64 = 0x10000000001d0001
    //var ringPrimeP uint64 = 0xfffffffffffc001

    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65537)
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,2652353003)
    if err != nil {
        panic(err)
    }
    //k := int(float64(numPeers) * (1 - resiliency))
	//if k == 0 {
	//	k = 1
	//}
    //params.SetScale(scale)
    //params.SetLogSlots(logDegree - 1)
    ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    //ringQ, _ := ring.NewRing(1<<params.LogN(), params.Qi())

    pi := &party{}
    //shares := strings.Split(shamirShare, ":")
    shamirShareArray := unsqueezedArray(shamirShare, numPeers)
		secretShares := make([]*ring.Poly, numPeers)
		for partyCounter := 0; partyCounter < numPeers; partyCounter++ {
			share := shamirShareArray[partyCounter]
			polyCoeff := unsqueezedArray(share,2)
			secretShares[partyCounter] = ringQP.NewPoly()
			secretShares[partyCounter].SetCoefficients(polyCoeff)
		}
		// generate shamir share of collective secret key
		pi.shamirShare = ringQP.NewPoly()
		ringQP.Add(secretShares[0], secretShares[1], pi.shamirShare)
		for i := 2; i < numPeers; i++ {
			ringQP.Add(pi.shamirShare, secretShares[i], pi.shamirShare)
		}
    //shamirShare_Cstring = C.CString(polyCoeffsEncode(pi.shamirShare.Coeffs))
    shamirShare_array := pi.shamirShare.Coeffs
    shamirShareLength := len(pi.shamirShare.Coeffs) * len(pi.shamirShare.Coeffs[0])
    shamirShareList := make([]uint64,shamirShareLength)
    shamirShareList = squeezedArray(shamirShare_array)
    shamirSharePointer = uintptr(unsafe.Pointer(&shamirShareList[0]))
    return
}


//export genShamirShares
func genShamirShares(numPeers int, k int, logDegree uint64, scale float64, resiliency float64)(SSPoniter uintptr, collectiveKeyShairPointer uintptr){
	//var ringPrime uint64 = 0x10000000001d0001
	var ringPrime uint64 = 0xfffffffffffc001
    //k := int(float64(numPeers) * (1 - resiliency))
	//if k == 0 {
	//	k = 1
	//}

    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
	//params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65537)
	params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)

    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,2652353003)
    //params.SetScale(scale)
	//params.SetLogSlots(logDegree - 1)
	lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}
	///////// Ring for the common reference polynomials sampling
	ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
	///////// Common reference polynomial generator that uses the PRNG
	crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
	crs := crsGen.ReadNew() // for the public-key

	///////// Target private and public keys
	ckg := dbfv.NewCKGProtocol(params)

	///////// create the party object and setup keys
	pi := &party{}

		evalPoints := make([]uint64, numPeers)
		for i := 0; i < numPeers; i++ {
			evalPoints[i] = uint64(i)+1
		}
		pi.sk = make([]*bfv.SecretKey, k, k)
		pi.secretShares = make([]*ring.Poly, numPeers, numPeers)
		///////// create k different secret keys for each party
		for partyCntr := 0; partyCntr < k; partyCntr++ {
			pi.sk[partyCntr] = bfv.NewKeyGenerator(params).GenSecretKey()
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

	///////// Create party, and allocate the memory for all the shares that the protocols will need
	pi.ckgShare = ckg.AllocateShares()

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
    SSPoniter = uintptr(unsafe.Pointer(&secretSharesList[0]))

    ckg.GenShare(pi.sk[0].Get(), crs, pi.ckgShare)
    collectiveKeyShairLength := len(pi.ckgShare.Coeffs)*len(pi.ckgShare.Coeffs[0])
    //fmt.Println("collectiveKeyShair", collectiveKeyShairLength)
    collectiveKeyShair := make([]uint64,collectiveKeyShairLength)
    collectiveKeyShair = squeezedArray(pi.ckgShare.Coeffs)
    //fmt.Println("collectiveKeyShair", collectiveKeyShair[0:5])
    collectiveKeyShairPointer = uintptr(unsafe.Pointer(&collectiveKeyShair[0]))

    return
}

//export genCollectiveKeyShare_not_robust
//func genCollectiveKeyShare_not_robust(numPeers int, logDegree uint64, scale float64, resiliency float64)(PK_pointer uintptr, SS uintptr, res *C.char, shamirShareString *C.char){
func genCollectiveKeyShare_not_robust(numPeers int, k int, logDegree uint64, scale float64, resiliency float64)(PK_pointer uintptr, SS uintptr){
    //var ringPrime uint64 = 0x10000000001d0001
    var ringPrime uint64 = 0xfffffffffffc001
    //k := int(float64(numPeers) * (1 - resiliency))
    //if k == 0 {
    //    k = 1
    //}

    moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}
    //fmt.Println("client go log Degree",logDegree)  
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65537)
    params, err := bfv.NewParametersFromModuli(logDegree, moduli, 65929217)
    //params, err := bfv.NewParametersFromModuli(logDegree, moduli,2652353003)
    //params.SetScale(scale)
    //params.SetLogSlots(logDegree - 1)
    lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
    if err != nil {
        panic(err)
    }
    ///////// Ring for the common reference polynomials sampling
    ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
    //ringQ, _ := ring.NewRing(1<<params.LogN(), params.Qi())
    ///////// Common reference polynomial generator that uses the PRNG
    crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
    crs := crsGen.ReadNew() // for the public-key

    ///////// Target private and public keys
    ckg := dbfv.NewCKGProtocol(params)

    ///////// create the party object and setup keys
    pi := &party{}
    pi.sk = make([]*bfv.SecretKey, 1, 1)
        ///////// create k different secret keys for each party
    pi.sk[0] = bfv.NewKeyGenerator(params).GenSecretKey()

    pi.ckgShare = ckg.AllocateShares()

    ///////// Collective public key generation
	ckg.GenShare(pi.sk[0].Get(), crs, pi.ckgShare)
	///////// Transmit collective key generation share to the master
    PK := pi.ckgShare.Coeffs
    //squeezed_PK := make([]uint64,16384)
    squeezed_PK := squeezedArray(PK)
    //fmt.Println("PK",len(squeezed_PK))
    //fmt.Println("PK", squeezed_PK[len(squeezed_PK)-5:])
    PK_pointer = uintptr(unsafe.Pointer(&squeezed_PK[0]))
    //squeezed_SS := make([]uint64,16384)
    squeezed_SS := squeezedArray(pi.sk[0].Get().Coeffs)
    //fmt.Println("SS",len(squeezed_SS))
    //fmt.Println("SS", squeezed_SS[len(squeezed_SS)-5:])
    SS = uintptr(unsafe.Pointer(&squeezed_SS[0]))


    return
}
