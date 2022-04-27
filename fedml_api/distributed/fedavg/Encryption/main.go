
package main

func main() {
	//args := os.Args[1:]
	//appType := args[0]
	//fmt.Println(appType)
	//scale := float64(1 << 40)
	//robust := false
	//logDegree := uint64(13)
	//numPeers := 2
	//inLen := 20000
	//if appType == "client" {
	//	inputs := make([]float64, inLen)
	//	for i := range inputs {
	//		inputs[i] = rand.Float64()
	//	}
	//	fmt.Println(inputs[19990:])
	//	cpk, shamirShare, id := clientPhase1("localhost:8080", robust, logDegree, scale, 0.5)
	//	clientPhase2(inputs, cpk, shamirShare, id, "localhost:8080", robust, logDegree, scale, 0.5)
	//} else {
	//	serverPhase1("localhost:8080", numPeers, robust, logDegree, scale)
	//	serverPhase2("localhost:8080", numPeers, robust, 0.5, logDegree, scale, inLen)
	//}
}


/*
package main

import (
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/dbfv"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/utils"
	"log"
	"math/rand"
	"os"
	"time"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}


func main() {
	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)
	var elapsedCKGCloud time.Duration
	var elapsedCKGParty time.Duration
	l := log.New(os.Stderr, "", 0)
	var ringPrime uint64 = 0xfffffffffffc001
	//var ringPrime uint64 = 0x40002001
	var N = 2 //  number of parties
	var k = 2 // reconstruction threshold
	numElements := 200000
	var numPackets int
	if numElements % 8192 == 0{
		numPackets = numElements/8192
	} else {
		numPackets = numElements/8192 + 1
	}
	l.Println(numPackets)
	type party struct {
		sk           []*bfv.SecretKey
		secretShares []*ring.Poly
		shamirShare  *ring.Poly
		ckgShare     dbfv.CKGShare
		pcksShare    []dbfv.PCKSShare
		input        [][]uint64
	}

	moduli := &bfv.Moduli{[]uint64{ringPrime}, []uint64{ringPrime}, []uint64{ringPrime}}

	params, err := bfv.NewParametersFromModuli(13, moduli, 65537)
	//// PRNG keyed with "lattigo"
	lattigoPRNG, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	// Ring for the common reference polynomials sampling
	ringQP, _ := ring.NewRing(1<<params.LogN(), append(params.Qi(), params.Pi()...))
	ringQ, _ := ring.NewRing(1<<params.LogN(), params.Qi())
	// Common reference polynomial generator that uses the PRNG
	crsGen := ring.NewUniformSampler(lattigoPRNG, ringQP)
	crs := crsGen.ReadNew() // for the public-key

	// Target private and public keys
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	ckg := dbfv.NewCKGProtocol(params)
	pcks := dbfv.NewPCKSProtocol(params, 3.19)

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N, N)
	evalPoints := make([]uint64, N)
	for i := range P {
		rand.Seed(time.Now().UTC().UnixNano())
		evalPoints[i] = rand.Uint64() % ringPrime
	}
	// measure the time required for setup here
	for i := range P {
		//log.Println(i)
		pi := &party{}
		pi.sk = make([]*bfv.SecretKey, k, k)
		pi.secretShares = make([]*ring.Poly, N, N)
		// create k different secret keys for each party
		for partyCntr := 0; partyCntr < k; partyCntr++ {
			pi.sk[partyCntr] = bfv.NewKeyGenerator(params).GenSecretKey()
		}
		// create the shares of the secret key


		// creating inputs
		pi.input = make([][]uint64, numPackets)
		for packet := range pi.input{
			pi.input[packet] = make([]uint64, 8192)
			for i := range pi.input[packet] {
				rand.Seed(time.Now().UnixNano())
				pi.input[packet][i] = uint64(rand.Intn(3))
			}
		}
		pi.ckgShare = ckg.AllocateShares()
		for packet := range pi.pcksShare{
			pi.pcksShare[packet] = pcks.AllocateShares()
		}

		P[i] = pi
	}

	// 1) Collective public key generation
	l.Println("> CKG Phase")
	pk := bfv.NewPublicKey(params)
	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk[0].Get(), crs, pi.ckgShare)
			/*
            if k<N {
				for partyCntr := range P {
					vandermonde := GenerateVandermonde(evalPoints[partyCntr], uint64(k), ringPrime)
					res := ringQ.NewPoly()
					ringQ.MulScalar(pi.sk[0].Get(), vandermonde[0], res)
					for i := 1; i < k; i++ {
						tmp := ringQ.NewPoly()
						ringQ.MulScalar(pi.sk[i].Get(), vandermonde[i], tmp)
						ringQ.Add(tmp, res, res)
					}
					pi.secretShares[partyCntr] = res
				}
			}
		}
		if k<N {
			for i := range P {
				res := ringQ.NewPoly()
				ringQ.Add(P[0].secretShares[i], P[1].secretShares[i], res)
				for j := 2; j < N; j++ {
					ringQ.Add(res, P[j].secretShares[i], res)
				}
				P[i].shamirShare = res
			}
		}
        
	}, N)
	ckgCombined := ckg.AllocateShares()
	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P{
            ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crs, pk)
	})
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	// Pre-loading memory
	l.Println("> Memory alloc Phase")
	encInputs := make([][]*bfv.Ciphertext, N)
	for i := range encInputs {
		encInputs[i] = make([]*bfv.Ciphertext, numPackets)
		for packet := range encInputs[i] {
			encInputs[i][packet] = bfv.NewCiphertext(params, 1)
		}
	}

	encResult := make([]*bfv.Ciphertext, numPackets)
	for packet := range encResult{
		encResult[packet] = bfv.NewCiphertext(params, 1)
	}


	// Each party encrypts its input vector
	l.Println("> Encrypt Phase")
	encryptor := bfv.NewEncryptorFromPk(params, pk)
	encoder := bfv.NewEncoder(params)
	pt := bfv.NewPlaintext(params)
	elapsedEncryptParty := runTimedParty(func() {
		for i, pi := range P {
			for packet := range pi.input {
				encoder.EncodeUint(pi.input[packet], pt)
				encryptor.Encrypt(pt, encInputs[i][packet])
			}
            encInputArray  := make([][]uint64,numPieces)
    for idx := range encInputs[i] {
        encinput := make([][]uint64, len(encInputs[i][idx].Value()))
        for ctPolyCounter := range encInputs[i][idx].Value(){
            encinput[ctPolyCounter] = squeezedArray(encInputs[i][idx].Value()[ctPolyCounter].Coeffs)
        }
        encInputArray[idx] = squeezedArray(encinput)
    }
		}
	}, N)

	l.Printf("\tdone (party: %s)\n", elapsedEncryptParty)

	evaluator := bfv.NewEvaluator(params)
	elapsedEvalCloudCPU := runTimed(func() {
		for packet := range encResult{
			evaluator.Add(encInputs[0][packet], encInputs[1][packet], encResult[packet])
			for i := 2; i < N; i++ {
				evaluator.Add(encResult[packet], encInputs[i][packet], encResult[packet])
			}
		}

	})

	elapsedEvalParty := time.Duration(0)
	l.Printf("\tdone (cloud: %s , party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalParty)

	// Collective key switching from the collective secret key to
	// the target public key
	l.Println("> PCKS Phase")

	elapsedPCKSParty := runTimedParty(func() {
		for _, pi := range P {
			for packet := range pi.pcksShare {
				pcks.GenShare(pi.sk[0].Get(), tpk, encResult[packet], pi.pcksShare[packet])
			}
		}
	}, N)

	pcksCombined := pcks.AllocateShares()
	encOut := make([]*bfv.Ciphertext, numPackets)
	for packet := range encOut{
		encOut[packet] = bfv.NewCiphertext(params, 1)
	}
	elapsedPCKSCloud := runTimed(func() {
		for packet := range P[0].pcksShare{
			for _, pi := range P {
				pcks.AggregateShares(pi.pcksShare[packet], pcksCombined, pcksCombined)
			}
			pcks.KeySwitch(pcksCombined, encResult[packet], encOut[packet])
		}
	})
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	// Decrypt the result with the target secret key
	l.Println("> Result:")
	decryptor := bfv.NewDecryptor(params, tsk)
	ptres := make([]*bfv.Plaintext, numPackets)
	for packet := range ptres{
		ptres[packet] = bfv.NewPlaintext(params)
	}
	elapsedDecParty := runTimed(func() {
		for packet := range ptres{
			decryptor.Decrypt(encOut[packet], ptres[packet])
		}
	})

	// Check the result
	//res := encoder.DecodeInt(ptres)
	//l.Println(res[0:numElements])
	l.Printf("> Finished (total setup: %s, total iteration: %s)\n",
		elapsedCKGParty + elapsedCKGCloud,
		elapsedEvalCloudCPU+elapsedPCKSCloud+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty,
		)
}
*/
