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
type OuterCircuit_threeInner[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	ProofA        stdgroth16.Proof[G1El, G2El]
	VerifyingKeyA stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitnessA stdgroth16.Witness[FR]                    `gnark:",public"`
	ProofB        stdgroth16.Proof[G1El, G2El]
	VerifyingKeyB stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitnessB stdgroth16.Witness[FR]                    `gnark:",public"`
	ProofC        stdgroth16.Proof[G1El, G2El]
	VerifyingKeyC stdgroth16.VerifyingKey[G1El, G2El, GtEl] `gnark:"-"`
	InnerWitnessC stdgroth16.Witness[FR]                    `gnark:",public"`
}

func (c *OuterCircuit_threeInner[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier1, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	verifier1.AssertProof(c.VerifyingKeyA, c.ProofA, c.InnerWitnessA)
	verifier2, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	verifier2.AssertProof(c.VerifyingKeyB, c.ProofB, c.InnerWitnessB)

	verifier3, err := stdgroth16.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}

	verifier3.AssertProof(c.VerifyingKeyC, c.ProofC, c.InnerWitnessC)
	return nil

}

func Compute_Outer_3Inner(innerCcsA constraint.ConstraintSystem, innerVKA groth16.VerifyingKey, innerWitnessA witness.Witness, innerProofA groth16.Proof, innerCcsB constraint.ConstraintSystem, innerVKB groth16.VerifyingKey, innerWitnessB witness.Witness, innerProofB groth16.Proof, innerCcsC constraint.ConstraintSystem, innerVKC groth16.VerifyingKey, innerWitnessC witness.Witness, innerProofC groth16.Proof) (groth16.Proof, groth16.VerifyingKey, witness.Witness) {
	//prepare inner proofs
	circuitVkA, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVKA)
	if err != nil {
		panic(err)
	}
	circuitWitnessA, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitnessA)
	if err != nil {
		panic(err)
	}
	circuitProofA, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProofA)
	if err != nil {
		panic(err)
	}

	circuitVkB, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVKB)
	if err != nil {
		panic(err)
	}
	circuitWitnessB, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitnessB)
	if err != nil {
		panic(err)
	}
	circuitProofB, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProofB)
	if err != nil {
		panic(err)
	}

	circuitVkC, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVKC)
	if err != nil {
		panic(err)
	}
	circuitWitnessC, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](innerWitnessC)
	if err != nil {
		panic(err)
	}
	circuitProofC, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProofC)
	if err != nil {
		panic(err)
	}

	outerAssignment := &OuterCircuit_threeInner[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitnessA: circuitWitnessA,
		ProofA:        circuitProofA,
		InnerWitnessB: circuitWitnessB,
		ProofB:        circuitProofB,
		InnerWitnessC: circuitWitnessC,
		ProofC:        circuitProofC,
		//VerifyingKey: circuitVk,
	}
	outerCircuit := &OuterCircuit_threeInner[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitnessA: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcsA),
		//VerifyingKey: stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerCcs),
		VerifyingKeyA: circuitVkA,
		InnerWitnessB: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcsB),
		VerifyingKeyB: circuitVkB,
		InnerWitnessC: stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](innerCcsC),
		VerifyingKeyC: circuitVkC,
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
