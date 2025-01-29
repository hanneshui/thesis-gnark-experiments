package main

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type Circuit1 struct {
	// public parameters
	X1 frontend.Variable `gnark:",public"`
	X2 frontend.Variable `gnark:",public"`
	X3 frontend.Variable `gnark:",public"`

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
}

func (c *Circuit1) Define(api frontend.API) error {
	// hash function
	hfunc, _ := mimc.NewMiMC(api)

	// Compute the old reciever SCM
	hfunc.Reset()
	hfunc.Write(c.W3, c.W4, c.W8, c.W9, c.W5, c.W1, c.W12, c.W2)
	receiverSCMOld := hfunc.Sum()

	// Ensure that the blinded SCM was computed correctly
	hfunc.Reset()
	hfunc.Write(receiverSCMOld, c.W16)
	api.AssertIsEqual(c.W15, hfunc.Sum())

	// Ensure the transaction committment was computed correctly
	hfunc.Reset()
	hfunc.Write(c.W11, c.W10, c.W15, c.W7, c.W6)
	api.AssertIsEqual(c.X3, hfunc.Sum())

	// Ensure the new receiver SCM was computed correctly
	hfunc.Reset()
	hfunc.Write(c.W3, api.Add(c.W4, c.W10), receiverSCMOld, c.W7, c.W5, c.W1, c.W13, c.W2)
	api.AssertIsEqual(c.X1, hfunc.Sum())

	// Prove that the dependency committment was computed correctly
	hfunc.Reset()
	hfunc.Write(c.W14, receiverSCMOld, c.W7)
	api.AssertIsEqual(c.X2, hfunc.Sum())

	// Prove that the new balance is lower than the holding limit
	api.AssertIsLessOrEqual(api.Add(c.W4, c.W10), c.W2)

	// Prove epoch difference is low enough
	sign := cmp.IsLessOrEqual(api, c.W6, c.W5)
	sub := api.Select(sign, api.Sub(c.W5, c.W6), api.Sub(c.W6, c.W5))
	api.AssertIsLessOrEqual(sub, big.NewInt(50))

	return nil
}

func ComputeProofC1(field, outer *big.Int, assignment *Circuit1, bn254 bool) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit1{})
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

	innerProof, err := groth16.Prove(innerCcs, innerPK, innerWitness)
	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}

	return innerCcs, innerVK, innerPubWitness, innerProof
}
