package main

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

func Recursive_1Circuit() {
	print("------------------------------------------------\n")
	print("Circuit 1\n")
	//compute inner proof.
	assignment1 := &Circuit1{
		X1:  "2585690560765377714820150516780496525626299280834382126014056601343495264828",
		X2:  "5723314072648994917715735901255749282591600725873466147641967501831164231964",
		X3:  "4837705174467728318490563814897266391273192880073545142717072432383024977836",
		W1:  4,
		W2:  20,
		W3:  6,
		W4:  7,
		W5:  8,
		W6:  9,
		W7:  10,
		W8:  11,
		W9:  12,
		W10: 13,
		W11: 14,
		W12: 15,
		W13: 16,
		W14: 17,
		W15: "1870167978923072168062518720560234004128912238941371553587596331349824329015",
		W16: 19,
	}

	innerCCS, innerVK, innerWitness, innerProof := ComputeProofC1(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment1, false)
	//compute outer proof
	outerProof, outerVK, outerWitness := Compute_Outer_1Inner(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err := groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	var bufcircuit1_innerProof bytes.Buffer
	var bufcircuit1_outerProof bytes.Buffer
	var bufcircuit1_innerWitness bytes.Buffer
	var bufcircuit1_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit1_innerProof)
	outerProof.WriteTo(&bufcircuit1_outerProof)
	innerWitness.WriteTo(&bufcircuit1_innerWitness)
	outerWitness.WriteTo(&bufcircuit1_outerWitness)

	print("Inner Proof size: ", bufcircuit1_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit1_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit1_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit1_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 2\n")
	assignment2 := &Circuit2{
		X1: "6752855449231056321267693814255816381488594393943282535305674286289946722249", // Message
		X2: eddsa.PublicKey{
			A: twistededwards.Point{
				X: "8313108389828320643876668317341381733739848512650973615802431996739702191373",
				Y: "3682713017757992271155008825503072861837087085171901279573340560359067658758",
			},
		},
		W1: []byte("Hello, World!"),
		W2: []byte("Hello, World!2"),
		W3: "3",
		W4: eddsa.Signature{
			R: twistededwards.Point{
				X: "1281949276427518828308014773915118140357715152061955838718817705390312438534",
				Y: "2573843223670007272732953050834879914798531473627700698910346755612322787202",
			},
			S: "1884812387803760406244502024355425642054199848611821890027218951838594509979",
		},
		W5: eddsa.Signature{
			R: twistededwards.Point{
				X: "1104123814700516750588924664666145146275761015855220126221744492863160970085",
				Y: "1112175371932101329414576557723878185604846552869661807131740784072165046634",
			},
			S: "1866522081720066226851219528936262187368278513466235759453193967435186501241",
		},
	}

	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC2(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment2)

	outerProof, outerVK, outerWitness = Compute_Outer_1Inner(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	//print the sizes
	var bufcircuit2_innerProof bytes.Buffer
	var bufcircuit2_outerProof bytes.Buffer
	var bufcircuit2_innerWitness bytes.Buffer
	var bufcircuit2_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit2_innerProof)
	outerProof.WriteTo(&bufcircuit2_outerProof)
	innerWitness.WriteTo(&bufcircuit2_innerWitness)
	outerWitness.WriteTo(&bufcircuit2_outerWitness)

	print("Inner Proof size: ", bufcircuit2_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit2_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit2_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit2_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 3\n")
	assignment3 := &Circuit3{
		X1:  "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X2:  "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X3:  "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X4:  "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X5:  "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X6:  "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X7:  "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X8:  "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X9:  "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X10: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X11: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X12: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X13: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X14: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X15: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
		W1:  1,
		W2:  2,
		W3:  3,
		W4:  4,
		W5:  5,
		W6:  6,
		W7:  7,
		W8:  8,
		W9:  9,
		W10: 10,
		W11: 11,
		W12: 12,
		W13: 13,
		W14: 14,
		W15: 0,
	}
	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC3(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment3, false)
	outerProof, outerVK, outerWitness = Compute_Outer_1Inner(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	//print the sizes
	var bufcircuit3_innerProof bytes.Buffer
	var bufcircuit3_outerProof bytes.Buffer
	var bufcircuit3_innerWitness bytes.Buffer
	var bufcircuit3_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit3_innerProof)
	outerProof.WriteTo(&bufcircuit3_outerProof)
	innerWitness.WriteTo(&bufcircuit3_innerWitness)
	outerWitness.WriteTo(&bufcircuit3_outerWitness)

	print("Inner Proof size: ", bufcircuit3_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit3_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit3_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit3_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 4\n")
	assignment4 := &Circuit4{
		X1:  "1",
		X2:  "2",
		X3:  "3",
		X4:  "4",
		X5:  "5",
		X6:  "6",
		X7:  "7",
		X8:  "8",
		X9:  "9",
		X10: "10",
		X11: "11",
		X12: "12",
		X13: "13",
		X14: "14",
		X15: "0",
		X16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC4(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment4, false)
	outerProof, outerVK, outerWitness = Compute_Outer_1Inner(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit4_innerProof bytes.Buffer
	var bufcircuit4_outerProof bytes.Buffer
	var bufcircuit4_innerWitness bytes.Buffer
	var bufcircuit4_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit4_innerProof)
	outerProof.WriteTo(&bufcircuit4_outerProof)
	innerWitness.WriteTo(&bufcircuit4_innerWitness)
	outerWitness.WriteTo(&bufcircuit4_outerWitness)

	print("Inner Proof size: ", bufcircuit4_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit4_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit4_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit4_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 5\n")
	assignment5 := &Circuit5{
		W1:  "1",
		W2:  "2",
		W3:  "3",
		W4:  "4",
		W5:  "5",
		W6:  "6",
		W7:  "7",
		W8:  "8",
		W9:  "9",
		W10: "10",
		W11: "11",
		W12: "12",
		W13: "13",
		W14: "14",
		W15: "0",
		W16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		W17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		W18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		W19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		W20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		W21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		W22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		W23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		W24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		W25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		W26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		W27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		W28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		W29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		W30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC5(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment5, false)
	outerProof, outerVK, outerWitness = Compute_Outer_1Inner(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit5_innerProof bytes.Buffer
	var bufcircuit5_outerProof bytes.Buffer
	var bufcircuit5_innerWitness bytes.Buffer
	var bufcircuit5_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit5_innerProof)
	outerProof.WriteTo(&bufcircuit5_outerProof)
	innerWitness.WriteTo(&bufcircuit5_innerWitness)
	outerWitness.WriteTo(&bufcircuit5_outerWitness)

	print("Inner Proof size: ", bufcircuit5_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit5_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit5_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit5_outerWitness.Len(), "\n")

}

func Recursive_2Circuits() {
	print("------------------------------------------------\n")
	print("Circuit 1 and Circuit 2\n")
	//compute inner proof.
	assignment1 := &Circuit1{
		X1:  "2585690560765377714820150516780496525626299280834382126014056601343495264828",
		X2:  "5723314072648994917715735901255749282591600725873466147641967501831164231964",
		X3:  "4837705174467728318490563814897266391273192880073545142717072432383024977836",
		W1:  4,
		W2:  20,
		W3:  6,
		W4:  7,
		W5:  8,
		W6:  9,
		W7:  10,
		W8:  11,
		W9:  12,
		W10: 13,
		W11: 14,
		W12: 15,
		W13: 16,
		W14: 17,
		W15: "1870167978923072168062518720560234004128912238941371553587596331349824329015",
		W16: 19,
	}

	innerCCSA, innerVKA, innerWitnessA, innerProofA := ComputeProofC1(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment1, false)

	//compute inner proof B
	assignment2 := &Circuit2{
		X1: "6752855449231056321267693814255816381488594393943282535305674286289946722249", // Message
		X2: eddsa.PublicKey{
			A: twistededwards.Point{
				X: "8313108389828320643876668317341381733739848512650973615802431996739702191373",
				Y: "3682713017757992271155008825503072861837087085171901279573340560359067658758",
			},
		},
		W1: []byte("Hello, World!"),
		W2: []byte("Hello, World!2"),
		W3: "3",
		W4: eddsa.Signature{
			R: twistededwards.Point{
				X: "1281949276427518828308014773915118140357715152061955838718817705390312438534",
				Y: "2573843223670007272732953050834879914798531473627700698910346755612322787202",
			},
			S: "1884812387803760406244502024355425642054199848611821890027218951838594509979",
		},
		W5: eddsa.Signature{
			R: twistededwards.Point{
				X: "1104123814700516750588924664666145146275761015855220126221744492863160970085",
				Y: "1112175371932101329414576557723878185604846552869661807131740784072165046634",
			},
			S: "1866522081720066226851219528936262187368278513466235759453193967435186501241",
		},
	}

	innerCCSB, innerVKB, innerWitnessB, innerProofB := ComputeProofC2(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment2)

	//compute outer proof
	outerProof, outerVK, outerWitness := Compute_Outer_2Inner_same(innerCCSA, innerVKA, innerWitnessA, innerProofA, innerCCSB, innerVKB, innerWitnessB, innerProofB)
	//veryfy outer proof
	err := groth16.Verify(outerProof, outerVK, outerWitness)

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	//print the sizes
	var bufcircuit1_innerProofA bytes.Buffer
	var bufcircuit1_innerProofB bytes.Buffer
	var bufcircuit1_outerProof bytes.Buffer
	var bufcircuit1_innerWitnessA bytes.Buffer
	var bufcircuit1_innerWitnessB bytes.Buffer
	var bufcircuit1_outerWitness bytes.Buffer

	innerProofA.WriteTo(&bufcircuit1_innerProofA)
	innerProofB.WriteTo(&bufcircuit1_innerProofB)
	outerProof.WriteTo(&bufcircuit1_outerProof)
	innerWitnessA.WriteTo(&bufcircuit1_innerWitnessA)
	innerWitnessB.WriteTo(&bufcircuit1_innerWitnessB)
	outerWitness.WriteTo(&bufcircuit1_outerWitness)

	print("Inner Proof A size: ", bufcircuit1_innerProofA.Len(), "\n")
	print("Inner Proof B size: ", bufcircuit1_innerProofB.Len(), "\n")
	print("Outer Proof size: ", bufcircuit1_outerProof.Len(), "\n")
	print("Inner Witness A size: ", bufcircuit1_innerWitnessA.Len(), "\n")
	print("Inner Witness B size: ", bufcircuit1_innerWitnessB.Len(), "\n")
	print("Outer Witness size: ", bufcircuit1_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 3 twice")
	//compute inner proof.
	assignment3 := &Circuit3{
		X1:  "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X2:  "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X3:  "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X4:  "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X5:  "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X6:  "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X7:  "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X8:  "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X9:  "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X10: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X11: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X12: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X13: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X14: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X15: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
		W1:  1,
		W2:  2,
		W3:  3,
		W4:  4,
		W5:  5,
		W6:  6,
		W7:  7,
		W8:  8,
		W9:  9,
		W10: 10,
		W11: 11,
		W12: 12,
		W13: 13,
		W14: 14,
		W15: 0,
	}
	innerCCS, innerVK, innerWitness, innerProof := ComputeProofC3(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment3, false)
	outerProof, outerVK, outerWitness = Compute_Outer_2Inner_same(innerCCS, innerVK, innerWitness, innerProof, innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	//print the sizes

	var bufcircuit3_innerProof bytes.Buffer
	var bufcircuit3_outerProof bytes.Buffer
	var bufcircuit3_innerWitness bytes.Buffer
	var bufcircuit3_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit3_innerProof)
	outerProof.WriteTo(&bufcircuit3_outerProof)
	innerWitness.WriteTo(&bufcircuit3_innerWitness)
	outerWitness.WriteTo(&bufcircuit3_outerWitness)

	print("Inner Proof size: ", bufcircuit3_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit3_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit3_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit3_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")

	print("Circuit 4 and Circuit 5\n")
	//compute inner proof.
	assignment4 := &Circuit4{
		X1:  "1",
		X2:  "2",
		X3:  "3",
		X4:  "4",
		X5:  "5",
		X6:  "6",
		X7:  "7",
		X8:  "8",
		X9:  "9",
		X10: "10",
		X11: "11",
		X12: "12",
		X13: "13",
		X14: "14",
		X15: "0",
		X16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCSA, innerVKA, innerWitnessA, innerProofA = ComputeProofC4(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment4, false)

	//compute inner proof B
	assignment5 := &Circuit5{
		W1:  "1",
		W2:  "2",
		W3:  "3",
		W4:  "4",
		W5:  "5",
		W6:  "6",
		W7:  "7",
		W8:  "8",
		W9:  "9",
		W10: "10",
		W11: "11",
		W12: "12",
		W13: "13",
		W14: "14",
		W15: "0",
		W16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		W17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		W18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		W19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		W20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		W21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		W22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		W23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		W24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		W25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		W26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		W27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		W28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		W29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		W30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCSB, innerVKB, innerWitnessB, innerProofB = ComputeProofC5(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment5, false)

	//compute outer proof
	outerProof, outerVK, outerWitness = Compute_Outer_2Inner_same(innerCCSA, innerVKA, innerWitnessA, innerProofA, innerCCSA, innerVKA, innerWitnessA, innerProofA)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit4_innerProofA bytes.Buffer
	var bufcircuit4_innerProofB bytes.Buffer
	var bufcircuit4_outerProof bytes.Buffer
	var bufcircuit4_innerWitnessA bytes.Buffer
	var bufcircuit4_innerWitnessB bytes.Buffer
	var bufcircuit4_outerWitness bytes.Buffer

	innerProofA.WriteTo(&bufcircuit4_innerProofA)
	innerProofB.WriteTo(&bufcircuit4_innerProofB)
	outerProof.WriteTo(&bufcircuit4_outerProof)
	innerWitnessA.WriteTo(&bufcircuit4_innerWitnessA)
	innerWitnessB.WriteTo(&bufcircuit4_innerWitnessB)
	outerWitness.WriteTo(&bufcircuit4_outerWitness)

	print("Inner Proof A size: ", bufcircuit4_innerProofA.Len(), "\n")
	print("Inner Proof B size: ", bufcircuit4_innerProofB.Len(), "\n")
	print("Outer Proof size: ", bufcircuit4_outerProof.Len(), "\n")
	print("Inner Witness A size: ", bufcircuit4_innerWitnessA.Len(), "\n")
	print("Inner Witness B size: ", bufcircuit4_innerWitnessB.Len(), "\n")
	print("Outer Witness size: ", bufcircuit4_outerWitness.Len(), "\n")

}

func Recursive_3Circuits() {
	//compute inner proof.A
	print("------------------------------------------------\n")
	print("Circuit 3, Circuit 4 and Circuit 5\n")
	assignment4 := &Circuit4{
		X1:  "1",
		X2:  "2",
		X3:  "3",
		X4:  "4",
		X5:  "5",
		X6:  "6",
		X7:  "7",
		X8:  "8",
		X9:  "9",
		X10: "10",
		X11: "11",
		X12: "12",
		X13: "13",
		X14: "14",
		X15: "0",
		X16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCSA, innerVKA, innerWitnessA, innerProofA := ComputeProofC4(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment4, false)

	//compute inner proof B
	assignment5 := &Circuit5{
		W1:  "1",
		W2:  "2",
		W3:  "3",
		W4:  "4",
		W5:  "5",
		W6:  "6",
		W7:  "7",
		W8:  "8",
		W9:  "9",
		W10: "10",
		W11: "11",
		W12: "12",
		W13: "13",
		W14: "14",
		W15: "0",
		W16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		W17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		W18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		W19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		W20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		W21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		W22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		W23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		W24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		W25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		W26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		W27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		W28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		W29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		W30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCSB, innerVKB, innerWitnessB, innerProofB := ComputeProofC5(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment5, false)

	//compute inner proof C
	assignment3 := &Circuit3{
		X1:  "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X2:  "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X3:  "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X4:  "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X5:  "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X6:  "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X7:  "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X8:  "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X9:  "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X10: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X11: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X12: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X13: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X14: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X15: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
		W1:  1,
		W2:  2,
		W3:  3,
		W4:  4,
		W5:  5,
		W6:  6,
		W7:  7,
		W8:  8,
		W9:  9,
		W10: 10,
		W11: 11,
		W12: 12,
		W13: 13,
		W14: 14,
		W15: 0,
	}
	innerCCSC, innerVKC, innerWitnessC, innerProofC := ComputeProofC3(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment3, false)

	//compute outer proof
	//compute outer proof
	outerProof, outerVK, outerWitness := Compute_Outer_3Inner(innerCCSA, innerVKA, innerWitnessA, innerProofA, innerCCSB, innerVKB, innerWitnessB, innerProofB, innerCCSC, innerVKC, innerWitnessC, innerProofC)
	//veryfy outer proof
	err := groth16.Verify(outerProof, outerVK, outerWitness)

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit4_innerProofA bytes.Buffer
	var bufcircuit4_innerProofB bytes.Buffer
	var bufcircuit4_innerProofC bytes.Buffer
	var bufcircuit4_outerProof bytes.Buffer
	var bufcircuit4_innerWitnessA bytes.Buffer
	var bufcircuit4_innerWitnessB bytes.Buffer
	var bufcircuit4_innerWitnessC bytes.Buffer
	var bufcircuit4_outerWitness bytes.Buffer

	innerProofA.WriteTo(&bufcircuit4_innerProofA)
	innerProofB.WriteTo(&bufcircuit4_innerProofB)
	innerProofC.WriteTo(&bufcircuit4_innerProofC)
	outerProof.WriteTo(&bufcircuit4_outerProof)
	innerWitnessA.WriteTo(&bufcircuit4_innerWitnessA)
	innerWitnessB.WriteTo(&bufcircuit4_innerWitnessB)
	innerWitnessC.WriteTo(&bufcircuit4_innerWitnessC)
	outerWitness.WriteTo(&bufcircuit4_outerWitness)

	print("Inner Proof A size: ", bufcircuit4_innerProofA.Len(), "\n")
	print("Inner Proof B size: ", bufcircuit4_innerProofB.Len(), "\n")
	print("Inner Proof C size: ", bufcircuit4_innerProofC.Len(), "\n")
	print("Outer Proof size: ", bufcircuit4_outerProof.Len(), "\n")
	print("Inner Witness A size: ", bufcircuit4_innerWitnessA.Len(), "\n")
	print("Inner Witness B size: ", bufcircuit4_innerWitnessB.Len(), "\n")
	print("Inner Witness C size: ", bufcircuit4_innerWitnessC.Len(), "\n")
	print("Outer Witness size: ", bufcircuit4_outerWitness.Len(), "\n")

}

func Recursive_1Circuit_vk() {
	print("------------------------------------------------\n")
	print("Circuit 1\n")
	//compute inner proof.
	assignment1 := &Circuit1{
		X1:  "2585690560765377714820150516780496525626299280834382126014056601343495264828",
		X2:  "5723314072648994917715735901255749282591600725873466147641967501831164231964",
		X3:  "4837705174467728318490563814897266391273192880073545142717072432383024977836",
		W1:  4,
		W2:  20,
		W3:  6,
		W4:  7,
		W5:  8,
		W6:  9,
		W7:  10,
		W8:  11,
		W9:  12,
		W10: 13,
		W11: 14,
		W12: 15,
		W13: 16,
		W14: 17,
		W15: "1870167978923072168062518720560234004128912238941371553587596331349824329015",
		W16: 19,
	}

	innerCCS, innerVK, innerWitness, innerProof := ComputeProofC1(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment1, false)
	//compute outer proof
	outerProof, outerVK, outerWitness := Compute_Outer_1Inner_vk(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err := groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	var bufcircuit1_innerProof bytes.Buffer
	var bufcircuit1_outerProof bytes.Buffer
	var bufcircuit1_innerWitness bytes.Buffer
	var bufcircuit1_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit1_innerProof)
	outerProof.WriteTo(&bufcircuit1_outerProof)
	innerWitness.WriteTo(&bufcircuit1_innerWitness)
	outerWitness.WriteTo(&bufcircuit1_outerWitness)

	print("Inner Proof size: ", bufcircuit1_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit1_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit1_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit1_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 2\n")
	assignment2 := &Circuit2{
		X1: "6752855449231056321267693814255816381488594393943282535305674286289946722249", // Message
		X2: eddsa.PublicKey{
			A: twistededwards.Point{
				X: "8313108389828320643876668317341381733739848512650973615802431996739702191373",
				Y: "3682713017757992271155008825503072861837087085171901279573340560359067658758",
			},
		},
		W1: []byte("Hello, World!"),
		W2: []byte("Hello, World!2"),
		W3: "3",
		W4: eddsa.Signature{
			R: twistededwards.Point{
				X: "1281949276427518828308014773915118140357715152061955838718817705390312438534",
				Y: "2573843223670007272732953050834879914798531473627700698910346755612322787202",
			},
			S: "1884812387803760406244502024355425642054199848611821890027218951838594509979",
		},
		W5: eddsa.Signature{
			R: twistededwards.Point{
				X: "1104123814700516750588924664666145146275761015855220126221744492863160970085",
				Y: "1112175371932101329414576557723878185604846552869661807131740784072165046634",
			},
			S: "1866522081720066226851219528936262187368278513466235759453193967435186501241",
		},
	}

	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC2(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment2)

	outerProof, outerVK, outerWitness = Compute_Outer_1Inner_vk(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	//print the sizes
	var bufcircuit2_innerProof bytes.Buffer
	var bufcircuit2_outerProof bytes.Buffer
	var bufcircuit2_innerWitness bytes.Buffer
	var bufcircuit2_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit2_innerProof)
	outerProof.WriteTo(&bufcircuit2_outerProof)
	innerWitness.WriteTo(&bufcircuit2_innerWitness)
	outerWitness.WriteTo(&bufcircuit2_outerWitness)

	print("Inner Proof size: ", bufcircuit2_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit2_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit2_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit2_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 3\n")
	assignment3 := &Circuit3{
		X1:  "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X2:  "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X3:  "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X4:  "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X5:  "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X6:  "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X7:  "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X8:  "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X9:  "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X10: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X11: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X12: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X13: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X14: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X15: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
		W1:  1,
		W2:  2,
		W3:  3,
		W4:  4,
		W5:  5,
		W6:  6,
		W7:  7,
		W8:  8,
		W9:  9,
		W10: 10,
		W11: 11,
		W12: 12,
		W13: 13,
		W14: 14,
		W15: 0,
	}
	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC3(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment3, false)
	outerProof, outerVK, outerWitness = Compute_Outer_1Inner_vk(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}
	//print the sizes
	var bufcircuit3_innerProof bytes.Buffer
	var bufcircuit3_outerProof bytes.Buffer
	var bufcircuit3_innerWitness bytes.Buffer
	var bufcircuit3_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit3_innerProof)
	outerProof.WriteTo(&bufcircuit3_outerProof)
	innerWitness.WriteTo(&bufcircuit3_innerWitness)
	outerWitness.WriteTo(&bufcircuit3_outerWitness)

	print("Inner Proof size: ", bufcircuit3_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit3_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit3_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit3_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 4\n")
	assignment4 := &Circuit4{
		X1:  "1",
		X2:  "2",
		X3:  "3",
		X4:  "4",
		X5:  "5",
		X6:  "6",
		X7:  "7",
		X8:  "8",
		X9:  "9",
		X10: "10",
		X11: "11",
		X12: "12",
		X13: "13",
		X14: "14",
		X15: "0",
		X16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		X17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		X18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		X19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		X20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		X21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		X22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		X23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		X24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		X25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		X26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		X27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		X28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		X29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		X30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC4(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment4, false)
	outerProof, outerVK, outerWitness = Compute_Outer_1Inner_vk(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit4_innerProof bytes.Buffer
	var bufcircuit4_outerProof bytes.Buffer
	var bufcircuit4_innerWitness bytes.Buffer
	var bufcircuit4_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit4_innerProof)
	outerProof.WriteTo(&bufcircuit4_outerProof)
	innerWitness.WriteTo(&bufcircuit4_innerWitness)
	outerWitness.WriteTo(&bufcircuit4_outerWitness)

	print("Inner Proof size: ", bufcircuit4_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit4_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit4_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit4_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")
	print("Circuit 5\n")
	assignment5 := &Circuit5{
		W1:  "1",
		W2:  "2",
		W3:  "3",
		W4:  "4",
		W5:  "5",
		W6:  "6",
		W7:  "7",
		W8:  "8",
		W9:  "9",
		W10: "10",
		W11: "11",
		W12: "12",
		W13: "13",
		W14: "14",
		W15: "0",
		W16: "6145395493319860668016347858812770023447391082436850637703433811806758341511",
		W17: "5372639291451818191628987971947498365897136915661242063962020082645469306801",
		W18: "8345064698512194671820687215336905882316691669657975833564912000222358771005",
		W19: "7193178607344504405033547753993836694880653173395268524234673070771134267976",
		W20: "4470461308091089130206224251448025469810378595018440458704326590797798857468",
		W21: "6678246761406175258780843413326922193135114407360689709273849331117234373107",
		W22: "404268763070835680098199600806499381383582390909982678960256342138818824701",
		W23: "7800794953392462079499146387957727784082229373277763367558211409960449038486",
		W24: "3813367346515062057786064786175867430784407238287162962484267606493514556446",
		W25: "103840650972614095218186489191658409275860437069492911412866216372461777589",
		W26: "8379283844860220163200588286960265411268953736637398172518451003624827184815",
		W27: "1185798057684030474461723028914009299616366893216765321233978167021139648151",
		W28: "7103504771694579947117871628393826689850941901823538587067000859551996443317",
		W29: "2809685179282062738493635545329192261563591593943848057921088601367957607774",
		W30: "3439877582322744870714553984007157217861225243070424161034745220887004085255",
	}
	innerCCS, innerVK, innerWitness, innerProof = ComputeProofC5(ecc.BLS12_377.ScalarField(), ecc.BW6_761.ScalarField(), assignment5, false)
	outerProof, outerVK, outerWitness = Compute_Outer_1Inner_vk(innerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err = groth16.Verify(outerProof, outerVK, outerWitness)
	//print outer proof and size of the proof

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit5_innerProof bytes.Buffer
	var bufcircuit5_outerProof bytes.Buffer
	var bufcircuit5_innerWitness bytes.Buffer
	var bufcircuit5_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit5_innerProof)
	outerProof.WriteTo(&bufcircuit5_outerProof)
	innerWitness.WriteTo(&bufcircuit5_innerWitness)
	outerWitness.WriteTo(&bufcircuit5_outerWitness)

	print("Inner Proof size: ", bufcircuit5_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit5_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit5_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit5_outerWitness.Len(), "\n")

}

func Recursive_1Circuit_emulation() {
	print("------------------------------------------------\n")
	print("Curve BN254\n")
	//circuit 1 compute proof
	print("Circuit 1\n")
	//assignments
	assignment1 := &Circuit1{
		X1:  "17910351931180199812861882105709449642850843359390602813041758851296707110869",
		X2:  "17099089350943580386252292303046352502900960708386057022991813653670996392884",
		X3:  "5588992280727076441168461784199521993843604546767119360841699806309863081522",
		W1:  4,
		W2:  20,
		W3:  6,
		W4:  7,
		W5:  8,
		W6:  9,
		W7:  10,
		W8:  11,
		W9:  12,
		W10: 13,
		W11: 14,
		W12: 15,
		W13: 16,
		W14: 17,
		W15: "15228504002629183277700886123866156298254294328121208625788741836971229363435",
		W16: 19,
	}

	InnerCCS, innerVK, innerWitness, innerProof := ComputeProofC1(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField(), assignment1, true)

	//compute outer proof
	outerProof, outerVK, outerWitness := Compute_Outer_1Inner_emulation(InnerCCS, innerVK, innerWitness, innerProof)
	//veryfy outer proof
	err := groth16.Verify(outerProof, outerVK, outerWitness)

	if err != nil {
		panic("circuit verification failed: " + err.Error())
	}

	//print the sizes
	var bufcircuit1_innerProof bytes.Buffer
	var bufcircuit1_outerProof bytes.Buffer
	var bufcircuit1_innerWitness bytes.Buffer
	var bufcircuit1_outerWitness bytes.Buffer

	innerProof.WriteTo(&bufcircuit1_innerProof)
	outerProof.WriteTo(&bufcircuit1_outerProof)
	innerWitness.WriteTo(&bufcircuit1_innerWitness)
	outerWitness.WriteTo(&bufcircuit1_outerWitness)

	print("Inner Proof size: ", bufcircuit1_innerProof.Len(), "\n")
	print("Outer Proof size: ", bufcircuit1_outerProof.Len(), "\n")
	print("Inner Witness size: ", bufcircuit1_innerWitness.Len(), "\n")
	print("Outer Witness size: ", bufcircuit1_outerWitness.Len(), "\n")

	print("------------------------------------------------\n")

}
