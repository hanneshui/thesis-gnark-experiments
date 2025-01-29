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

type Circuit4 struct {
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
	X16 frontend.Variable `gnark:",public"`
	X17 frontend.Variable `gnark:",public"`
	X18 frontend.Variable `gnark:",public"`
	X19 frontend.Variable `gnark:",public"`
	X20 frontend.Variable `gnark:",public"`
	X21 frontend.Variable `gnark:",public"`
	X22 frontend.Variable `gnark:",public"`
	X23 frontend.Variable `gnark:",public"`
	X24 frontend.Variable `gnark:",public"`
	X25 frontend.Variable `gnark:",public"`
	X26 frontend.Variable `gnark:",public"`
	X27 frontend.Variable `gnark:",public"`
	X28 frontend.Variable `gnark:",public"`
	X29 frontend.Variable `gnark:",public"`
	X30 frontend.Variable `gnark:",public"`
	
}

func (c *Circuit4) Define(api frontend.API) error {
	// hash function
	hfunc, _ := mimc.NewMiMC(api)

	//calculate hash
	hfunc.Write(c.X1)
	api.AssertIsEqual(c.X16, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X2)
	api.AssertIsEqual(c.X17, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X3)
	api.AssertIsEqual(c.X18, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X4)
	api.AssertIsEqual(c.X19, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X5)
	api.AssertIsEqual(c.X20, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X6)
	api.AssertIsEqual(c.X21, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X7)
	api.AssertIsEqual(c.X22, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X8)
	api.AssertIsEqual(c.X23, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X9)
	api.AssertIsEqual(c.X24, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X10)
	api.AssertIsEqual(c.X25, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X11)
	api.AssertIsEqual(c.X26, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X12)
	api.AssertIsEqual(c.X27, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X13)
	api.AssertIsEqual(c.X28, hfunc.Sum())
	hfunc.Reset()

	hfunc.Write(c.X14)
	api.AssertIsEqual(c.X29, hfunc.Sum())
	hfunc.Reset()

	//loop of adding 1 to W15 10000 times then check if it is equal to X15
	for i := 0; i < 500; i++ {
		hfunc.Write(c.X15)
		c.X15 = hfunc.Sum()
		hfunc.Reset()

	}
	
	api.AssertIsEqual(c.X30, c.X15)

	return nil
}

func ComputeProofC4(field, outer *big.Int, assignment *Circuit4, bn254 bool) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {
	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit4{})
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
