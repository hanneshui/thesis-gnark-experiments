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

type Circuit3 struct {
	// public parameters
	X1  frontend.Variable `gnark:",public"`
	X2  frontend.Variable `gnark:",public"`
	X3  frontend.Variable `gnark:",public"`
	X4  frontend.Variable `gnark:",public"`
	X5  frontend.Variable `gnark:",public"`
	X6  frontend.Variable `gnark:",public"`
	X7  frontend.Variable `gnark:",public"`
	X8  frontend.Variable `gnark:",public"`
	X9  frontend.Variable `gnark:",public"`
	X10 frontend.Variable `gnark:",public"`
	X11 frontend.Variable `gnark:",public"`
	X12 frontend.Variable `gnark:",public"`
	X13 frontend.Variable `gnark:",public"`
	X14 frontend.Variable `gnark:",public"`
	X15 frontend.Variable `gnark:",public"`
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
}

func (c *Circuit3) Define(api frontend.API) error {
	// hash function
	hfunc, _ := mimc.NewMiMC(api)

	//calculate hash
	hfunc.Write(c.W1)
	api.AssertIsEqual(c.X1, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W2)
	api.AssertIsEqual(c.X2, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W3)
	api.AssertIsEqual(c.X3, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W4)
	api.AssertIsEqual(c.X4, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W5)
	api.AssertIsEqual(c.X5, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W6)
	api.AssertIsEqual(c.X6, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W7)
	api.AssertIsEqual(c.X7, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W8)
	api.AssertIsEqual(c.X8, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W9)
	api.AssertIsEqual(c.X9, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W10)
	api.AssertIsEqual(c.X10, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W11)
	api.AssertIsEqual(c.X11, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W12)
	api.AssertIsEqual(c.X12, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W13)
	api.AssertIsEqual(c.X13, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.W14)
	api.AssertIsEqual(c.X14, hfunc.Sum())
	hfunc.Reset()

	//loop of adding 1 to W15 10000 times then check if it is equal to X15
	for i := 0; i < 500; i++ {
		hfunc.Write(c.W15)
		c.W15 = hfunc.Sum()
		hfunc.Reset()

	}

	api.AssertIsEqual(c.X15, c.W15)

	return nil
}

func ComputeProofC3(field, outer *big.Int, assignment *Circuit3, bn254 bool) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit3{})
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
