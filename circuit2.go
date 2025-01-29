package main

import (
	"math/big"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type Circuit2 struct {
	// public parameters
	X1 frontend.Variable `gnark:",public"`
	X2 eddsa.PublicKey   `gnark:",public"`

	// secret parameters
	W1 frontend.Variable
	W2 frontend.Variable
	W3 frontend.Variable
	W4 eddsa.Signature
	W5 eddsa.Signature
}

func (c *Circuit2) Define(api frontend.API) error {
	// hash function
	hfunc, _ := mimc.NewMiMC(api)

	// prove correct calculation of the depenmdency committment
	hfunc.Write(c.W3, c.W1, c.W2)
	api.AssertIsEqual(c.X1, hfunc.Sum())

	// Prove that the signature of the old state is correct
	params, err := twistededwards.NewEdCurve(api, tedwards.BLS12_377)
	if err != nil {
		return err
	}

	hfunc.Reset()
	err = eddsa.Verify(params, c.W4, c.W1, c.X2, &hfunc)
	if err != nil {
		return err
	}

	// Prove that the signature of the counterparty state is correct
	params, err = twistededwards.NewEdCurve(api, tedwards.BLS12_377)
	if err != nil {
		return err
	}
	hfunc.Reset()
	err = eddsa.Verify(params, c.W5, c.W2, c.X2, &hfunc)
	if err != nil {
		return err
	}

	return nil
}

type Circuit2_bn254 struct {
	// public parameters
	X1 frontend.Variable `gnark:",public"`
	X2 eddsa.PublicKey   `gnark:",public"`

	// secret parameters
	W1 frontend.Variable
	W2 frontend.Variable
	W3 frontend.Variable
	W4 eddsa.Signature
	W5 eddsa.Signature
}

func (c *Circuit2_bn254) Define(api frontend.API) error {
	// hash function
	hfunc, _ := mimc.NewMiMC(api)

	// prove correct calculation of the depenmdency committment
	hfunc.Write(c.W3, c.W1, c.W2)
	api.AssertIsEqual(c.X1, hfunc.Sum())

	// Prove that the signature of the old state is correct
	params, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}

	hfunc.Reset()
	err = eddsa.Verify(params, c.W4, c.W1, c.X2, &hfunc)
	if err != nil {
		return err
	}

	// Prove that the signature of the counterparty state is correct
	params, err = twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	hfunc.Reset()
	err = eddsa.Verify(params, c.W5, c.W2, c.X2, &hfunc)
	if err != nil {
		return err
	}

	return nil
}

func ComputeProofC2(field, outer *big.Int, assignment *Circuit2) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit2{})
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

	innerProof, err = groth16.Prove(innerCcs, innerPK, innerWitness, stdgroth16.GetNativeProverOptions(outer, field))

	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof

}
func ComputeProofC2_bn254(field *big.Int, assignment *Circuit2_bn254) (constraint.ConstraintSystem, groth16.VerifyingKey, witness.Witness, groth16.Proof) {

	innerCcs, err := frontend.Compile(field, r1cs.NewBuilder, &Circuit2_bn254{})
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

	innerProof, err = groth16.Prove(innerCcs, innerPK, innerWitness)

	if err != nil {
		panic(err)
	}
	innerPubWitness, err := innerWitness.Public()
	if err != nil {
		panic(err)
	}
	return innerCcs, innerVK, innerPubWitness, innerProof

}
