package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// circuit for one level recursion with one inner circuit.
type OuterCircuit_oneInner[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitness stdgroth16.Witness[FR]                    `gnark:",public"`
}

func (c *OuterCircuit_oneInner[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	return verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
}

func Compute_Outer_1Inner(innerCcs constraint.ConstraintSystem, innerVK groth16.VerifyingKey, innerWitness witness.Witness, innerProof groth16.Proof) (groth16.Proof, groth16.VerifyingKey, witness.Witness) {
	//compute inner proof.
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	outerAssignment := &OuterCircuit_oneInner[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		//VerifyingKey: circuitVk,
	}
	outerCircuit := &OuterCircuit_oneInner[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcs),
		//VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
		VerifyingKey: circuitVk,
	}
	// compile the outer circuit. because we are using 2-chains then the outer
	// curve must correspond to the inner curve. For inner BLS12-377 the outer
	// curve is BW6-761.
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, outerCircuit)
	if err != nil {
		panic("compile failed: " + err.Error())
	}
	// create Groth16 setup. NB! UNSAFE
	pk, vk, err := groth16.Setup(ccs) // UNSAFE! Use MPC
	if err != nil {
		panic("setup failed: " + err.Error())
	}
	secretWitness, err := frontend.NewWitness(outerAssignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic("secret witness failed: " + err.Error())
	}
	// create public witness from the assignment
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic("public witness failed: " + err.Error())
	}
	outerProof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic("proving failed: " + err.Error())
	}
	//return
	return outerProof, vk, publicWitness

}
