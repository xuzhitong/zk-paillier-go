package crypto

import (
	"crypto/rand"
	"fmt"
	"hundsun.com/hsl/hschain/common/crypto"
	"math/big"
)

type CiphertextProof struct {
	Z1      big.Int
	Z2      big.Int
	C_prime big.Int
}

type CiphertextWitness struct {
	X big.Int
	R big.Int
}
type CiphertextStatement struct {
	Ek PublicKey
	C  big.Int
}
type EncryptedPairs struct {
	C1 []*big.Int
	C2 []*big.Int
}

type DataRandomnessPairs struct {
	W1 []*big.Int
	W2 []*big.Int
	R1 []*big.Int
	R2 []*big.Int
}
type ResponseOpen struct {
	W1 *big.Int
	R1 *big.Int
	W2 *big.Int
	R2 *big.Int
}
type ResponseMask struct {
	J        uint8
	Masked_x *big.Int
	Masked_r *big.Int
}
type Response struct {
	Open ResponseOpen
	Mask ResponseMask
}
type RangeProofNi struct {
	Ek              *PublicKey
	Range_num       *big.Int
	Ciphertext      *big.Int
	Encrypted_pairs *EncryptedPairs
	Proof           []*Response
	Error_factor    uint64
}
type JoinProof struct {
	CipherAmountProof  *CiphertextProof
	CipherBalanceProof *CiphertextProof
	CipherRemainProof  *CiphertextProof
	EpAmountRange      *EncryptedPairs
	AmountRangeProof   []*Response
	EpRemainRange      *EncryptedPairs
	BalanceRangeProof  []*Response
}

func zkpaillier_prove(witness *CiphertextWitness, statement *CiphertextStatement) (*CiphertextProof, error) {
	x_prime, _ := rand.Int(rand.Reader, statement.Ek.N)
	r_prime, _ := rand.Int(rand.Reader, statement.Ek.N)
	c_prime, _ := EncryptNumberWithNonce(&statement.Ek, r_prime, x_prime)
	var e_bytes []byte
	e_bytes = append(append(append(e_bytes, statement.Ek.N.Bytes()...), statement.C.Bytes()...), c_prime.Bytes()...)
	ebytes, err := crypto.HashWithOpts(e_bytes, "SHA256")
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(ebytes)
	z1 := new(big.Int).Add(x_prime, new(big.Int).Mul(&witness.X, e))
	fmt.Println("z1 is ",z1)
	if statement.Ek.N.Cmp(z1) < 0 {
		fmt.Printf("zkpaillier_prove z1 %s more than n %s!\n", z1.String(), statement.Ek.N.String())
	}
	r_e := new(big.Int).Exp(&witness.R, e, statement.Ek.NSquared)
	z2 := new(big.Int).Mod(new(big.Int).Mul(r_prime, r_e), statement.Ek.NSquared)
	proof := &CiphertextProof{
		Z1:      *z1,
		Z2:      *z2,
		C_prime: *c_prime,
	}
	return proof, nil
}
func zkpaillier_verify(proof *CiphertextProof, statement *CiphertextStatement) (bool, error) {
	var e_bytes []byte
	c_prime := proof.C_prime
	e_bytes = append(append(append(e_bytes, statement.Ek.N.Bytes()...), statement.C.Bytes()...), c_prime.Bytes()...)
	ebytes, err := crypto.HashWithOpts(e_bytes, "SHA256")
	if err != nil {
		return false, err
	}
	e := new(big.Int).SetBytes(ebytes)
	c_z, err := EncryptWithNonce(&statement.Ek, &proof.Z2, proof.Z1.Bytes())
	if err != nil {
		fmt.Println("EncryptNumberWithNonce c_z ",err.Error())
	}
	c_e := MulNumber(&statement.Ek, &statement.C, e)
	c_z_test := AddCipherNumber(&statement.Ek, c_e, &c_prime)
	if c_z.Cmp(c_z_test) == 0 {
		return true, nil
	}
	return false, nil
}

func zkpaillier_encrypted_pairs(ek *PublicKey, range_num *big.Int, error_factor uint,
) (EncryptedPairs, DataRandomnessPairs) {
	range_scaled_third := new(big.Int).Div(range_num, new(big.Int).SetInt64(3))
	var w1 []*big.Int
	var w2 []*big.Int
	var i uint
	for i = 0; i < error_factor; i++ {
		var mid *big.Int
		mid,_ = rand.Int(rand.Reader, range_scaled_third)
		num := new(big.Int).Add(range_scaled_third, mid)
		w1 = append(w1, num)
		w2 = append(w2, mid)
	}
	for i = 0; i < error_factor; i++ {
		rand_num, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(2))
		if rand_num.Int64() == 1 {
			tmp := w2[i]
			w2[i] = w1[i]
			w1[i] = tmp
		}
	}

	var r1 []*big.Int
	var r2 []*big.Int
	for i = 0; i < error_factor; i++ {
		num, _ := rand.Int(rand.Reader, ek.N)
		r1 = append(r1, num)
	}

	for i = 0; i < error_factor; i++ {
		num, _ := rand.Int(rand.Reader, ek.N)
		r2 = append(r2, num)
	}

	var c1 []*big.Int
	var c2 []*big.Int
	for i := 0; i < len(w1); i++ {
		ci, _ := EncryptWithNonce(ek, r1[i], w1[i].Bytes())
		c1 = append(c1, ci)
	}

	for i := 0; i < len(w2); i++ {
		ci, _ := EncryptWithNonce(ek, r2[i], w2[i].Bytes())
		c2 = append(c2, ci)
	}
	epairs := EncryptedPairs{c1, c2}
	drPairs := DataRandomnessPairs{w1, w2, r1, r2}
	return epairs, drPairs
}
func zkpaillier_range_prove(ek *PublicKey, secret_x *big.Int, secret_r *big.Int, e []byte,
	range_num *big.Int, data *DataRandomnessPairs, error_factor int) []*Response {
    secret_x = new(big.Int).Mod(secret_x,range_num)
	range_scaled_third := new(big.Int).Div(range_num, new(big.Int).SetInt64(3))
	range_scaled_two_thirds := new(big.Int).Mul(new(big.Int).SetInt64(2), range_scaled_third)
	var bits_of_e []byte
	var responses []*Response
	for i := 0; i < len(e); i++ {
		var j uint8
		for j = 0; j < 8; j++ {
			bit := e[i] >> j & 1
			bits_of_e = append(bits_of_e, bit)
		}
	}

	//fmt.Println("zkpaillier_range_prove e is ",bits_of_e)
	for i := 0; i < error_factor; i++ {
		ei := bits_of_e[i]
		var res *Response
		if int8(ei) == 0 {
			resOpen := ResponseOpen{
				W1: data.W1[i],
				R1: data.R1[i],
				W2: data.W2[i],
				R2: data.R2[i],
			}
			res = &Response{Open: resOpen}

		} else if new(big.Int).Add(secret_x, data.W1[i]).Cmp(range_scaled_third) > 0 &&
			new(big.Int).Add(secret_x, data.W1[i]).Cmp(range_scaled_two_thirds) < 0 {
			resMask := ResponseMask{
				J:        1,
				Masked_x: new(big.Int).Add(secret_x, data.W1[i]),
				Masked_r: new(big.Int).Mod(new(big.Int).Mul(secret_r, data.R1[i]), ek.N),
			}
			res = &Response{Mask: resMask}
		} else {
			resMask := ResponseMask{
				J:        2,
				Masked_x: new(big.Int).Add(secret_x, data.W2[i]),
				Masked_r: new(big.Int).Mod(new(big.Int).Mul(secret_r, data.R2[i]), ek.N),
			}
			res = &Response{Mask: resMask}
		}
		responses = append(responses, res)

	}
	return responses

}

func zkpaillier_range_verify(ek *PublicKey, e []byte, encrypted_pairs *EncryptedPairs, responses []*Response,
	range_num *big.Int, cipher_x *big.Int, error_factor uint) (bool, error) {
	range_scaled_third := new(big.Int).Div(range_num, new(big.Int).SetInt64(3))
	range_scaled_two_thirds := new(big.Int).Mul(new(big.Int).SetInt64(2), range_scaled_third)
	var bits_of_e []byte
	for i := 0; i < len(e); i++ {
		var j uint8
		for j = 0; j < 8; j++ {
			bit := e[i] >> j & 1
			bits_of_e = append(bits_of_e, bit)
		}
	}
	var i uint
	finalRes := true

	fmt.Println("bits_of_e is ", bits_of_e)
	for i = 0; i < error_factor; i++ {
		ei := bits_of_e[i]
		response := responses[i]
		if ei == 0 && response.Mask.J == 0 {
			expected_c1i, _ := EncryptWithNonce(ek, response.Open.R1, response.Open.W1.Bytes())
			expected_c2i, _ := EncryptWithNonce(ek, response.Open.R2, response.Open.W2.Bytes())
			if expected_c1i.Cmp(encrypted_pairs.C1[i]) != 0 {
				finalRes = false
				fmt.Println("finalRes is false 11111")
				break
			}
			if expected_c2i.Cmp(encrypted_pairs.C2[i]) != 0 {
				finalRes = false
				fmt.Println("finalRes is false 22222")
				break
			}
			w1 := response.Open.W1
			w2 := response.Open.W2
			flag := (w2.Cmp(range_scaled_third) < 0 &&
				w1.Cmp(range_scaled_third) > 0 &&
				w1.Cmp(range_scaled_two_thirds) < 0) ||
				(w1.Cmp(range_scaled_third) < 0 &&
					w2.Cmp(range_scaled_third) > 0 && w2.Cmp(range_scaled_two_thirds) < 0)
			if !flag {
				finalRes = false
				fmt.Printf("finalRes is false 33333 %v %v\n",w1,w2)
				break
			}
		} else if ei == 1 && (response.Mask.J == 1 || response.Mask.J == 2) {
			c := new(big.Int)
			if response.Mask.J == 1 {
				_,c = new(big.Int).QuoRem(new(big.Int).Mul(encrypted_pairs.C1[i], cipher_x), ek.NSquared,c)
			} else {
				_,c = new(big.Int).QuoRem(new(big.Int).Mul(encrypted_pairs.C2[i], cipher_x), ek.NSquared,c)
			}
			masked_x := response.Mask.Masked_x
			masked_r := response.Mask.Masked_r
			enc_zi, err := EncryptWithNonce(ek, masked_r, masked_x.Bytes())
			if err != nil {
				fmt.Println("finalRes is false 444444 ",err.Error())
				return false, err
			}
			if c.Cmp(enc_zi) != 0 {
				fmt.Printf("finalRes is false 5555555,enc_zi is %v,c is %v\n",enc_zi,c)
				finalRes = false
				break
			}
			if masked_x.Cmp(range_scaled_third) < 0 || masked_x.Cmp(range_scaled_two_thirds) > 0 {
				finalRes = false
				if masked_x.Cmp(range_scaled_third) < 0 {
					fmt.Println("finalRes is false 66666666")
				} else {
					fmt.Printf("finalRes is false %s > %s\n", masked_x.String(), range_scaled_two_thirds.String())
				}
				break
			}
		} else {
			finalRes = false
			fmt.Println("finalRes is false 7777777")
			break
		}
	}
	return finalRes, nil
}
func zkpaillier_ni_range_prove(ek *PublicKey, range_num *big.Int, ciphertext *big.Int,
	secret_x *big.Int, secret_r *big.Int) (*RangeProofNi, error) {
	encrypted_pairs, data_randomness_pairs := zkpaillier_encrypted_pairs(ek, range_num, 128)
	c1 := encrypted_pairs.C1
	c2 := encrypted_pairs.C2
	var vec []byte
	vec = append(vec, ek.N.Bytes()...)
	for _, c1i := range c1 {
		vec = append(vec, c1i.Bytes()...)
	}
	for _, c2i := range c2 {
		vec = append(vec, c2i.Bytes()...)
	}

	e, err := crypto.HashWithOpts(vec, "SHA256")
	if err != nil {
		return nil, err
	}

	//assuming digest length > error factor
	proof := zkpaillier_range_prove(ek, secret_x, secret_r, e, range_num, &data_randomness_pairs, 128)
	ep := &EncryptedPairs{c1, c2}
	rpNi := &RangeProofNi{Ek: ek, Range_num: range_num, Ciphertext: ciphertext,
		Encrypted_pairs: ep, Proof: proof, Error_factor: 128}
	return rpNi, nil
}

func zkpaillier_ni_range_verify(ek *PublicKey, proof []*Response, encrypted_pairs *EncryptedPairs,
	ciphertext *big.Int, range_num *big.Int) (bool, error) {
	c1 := encrypted_pairs.C1
	c2 := encrypted_pairs.C2
	var vec []byte
	vec = append(vec, ek.N.Bytes()...)
	for _, c1i := range c1 {
		vec = append(vec, c1i.Bytes()...)
	}
	for _, c2i := range c2 {
		vec = append(vec, c2i.Bytes()...)
	}

	e, err := crypto.HashWithOpts(vec, "SHA256")
	if err != nil {
		return false, err
	}
	return zkpaillier_range_verify(ek, e, encrypted_pairs, proof, range_num, ciphertext, 128)

}
//func zkpaillier_prove_positive(ek *PublicKey, proof []*Response, encrypted_pairs *EncryptedPairs,
//	ciphertext *big.Int, range_num *big.Int) (bool,error){
//	ret,err := zkpaillier_ni_range_verify(ek,proof,encrypted_pairs,ciphertext,range_num)
//	if err != nil {
//		return false,err
//	}
//	if !ret {
//		one_third_range := new(big.Int).Div(range_num,new(big.Int).SetInt64(3))
//		r,_ := rand.Int(rand.Reader,ek.N)
//		cipher_one_third_range,_ := EncryptNumberWithNonce(ek,r,one_third_range)
//		cipher_sum := AddCipherNumber(ek,ciphertext,cipher_one_third_range)
//		ret1,err := zkpaillier_ni_range_verify(ek,proof,encrypted_pairs,ciphertext,range_num)
//
//	}
//}
//func zkpaillier_verify_positive(ek *PublicKey, proof []*Response, encrypted_pairs *EncryptedPairs,
//	ciphertext *big.Int, range_num *big.Int) (bool,error){
//    ret,err := zkpaillier_ni_range_verify(ek,proof,encrypted_pairs,ciphertext,range_num)
//    if err != nil {
//    	return false,err
//	}
//	if !ret {
//		one_third_range := new(big.Int).Div(range_num,new(big.Int).SetInt64(3))
//		r,_ := rand.Int(rand.Reader,ek.N)
//		cipher_one_third_range,_ := EncryptNumberWithNonce(ek,r,one_third_range)
//		cipher_sum := AddCipherNumber(ek,ciphertext,cipher_one_third_range)
//		ret1,err := zkpaillier_ni_range_verify(ek,proof,encrypted_pairs,ciphertext,range_num)
//
//	}
//}