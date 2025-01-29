package main

import (
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark/std/hash/mimc"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

type Circuit5 struct {
	// secret parameters
	W1  frontend.Variable
	W2  frontend.Variable
	W3  frontend.Variable
	W4  frontend.Variable
	W5  frontend.Variable
	W6  frontend.Variable
	W7  frontend.Variable
	W8  frontend.Variable
	W9  frontend.Variable
	W10 frontend.Variable
	W11 frontend.Variable
	W12 frontend.Variable
	W13 frontend.Variable
	W14 frontend.Variable
	W15 frontend.Variable
	W16 frontend.Variable
	W17 frontend.Variable
	W18 frontend.Variable
	W19 frontend.Variable
	W20 frontend.Variable
	W21 frontend.Variable
	W22 frontend.Variable
	W23 frontend.Variable
	W24 frontend.Variable
	W25 frontend.Variable
	W26 frontend.Variable
	W27 frontend.Variable
	W28 frontend.Variable
	W29 frontend.Variable
	W30 frontend.Variable
}

func (c *Circuit5) Define(api frontend.API) error {
	// hash function
	hfunc, _ := mimc.NewMiMC(api)

	//calculate hash
	hfunc.Write(c.W1)
	api.AssertIsEqual(c.W16, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W2)
	api.AssertIsEqual(c.W17, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W3)
	api.AssertIsEqual(c.W18, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W4)
	api.AssertIsEqual(c.W19, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W5)
	api.AssertIsEqual(c.W20, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W6)
	api.AssertIsEqual(c.W21, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W7)
	api.AssertIsEqual(c.W22, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W8)
	api.AssertIsEqual(c.W23, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W9)
	api.AssertIsEqual(c.W24, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W10)
	api.AssertIsEqual(c.W25, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W11)
	api.AssertIsEqual(c.W26, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W12)
	api.AssertIsEqual(c.W27, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W13)
	api.AssertIsEqual(c.W28, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W14)
	api.AssertIsEqual(c.W29, hfunc.Sum())
	hfunc.Reset()

	//loop of adding 1 to W15 10000 times then check if it is equal to X15
	for i := 0; i < 500; i++ {
		hfunc.Write(c.W15)
		c.W15 = hfunc.Sum()
		hfunc.Reset()

	}
	
	api.AssertIsEqual(c.W30, c.W15)

	return nil
}

func ComputeProofC5(field, outer *big.Int, assignment *Circuit5, bn254 bool) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit5{})
	if err != nil {
		panic(err)
	}

	innerPK, innerVK, err := groth16.Setup(innerCcs)
	if err != nil {
		panic(err)
	}

	innerWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		panic(err)
	}

	var innerProof groth16.Proof
	if bn254 {
		innerProof, err = groth16.Prove(innerCcs, innerPK, innerWitness)
	} else {
		innerProof, err = groth16.Prove(innerCcs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))
	}
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}

	return innerCcs, innerVK, innerPubWitness, innerProof
}
