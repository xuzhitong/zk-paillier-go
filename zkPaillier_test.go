package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"
)

func TestZkPaillier(t *testing.T) {
	for i := 0; i < 10000;i++ {
		privateKey, _ := GenerateKey(rand.Reader, 512)
		publicKey := privateKey.PublicKey
		num := new(big.Int).SetInt64(-100)
		//num1,_ := new(big.Int).SetString("1000",10)
		r, _ := rand.Int(rand.Reader, publicKey.N)
		//r1, _ := rand.Int(rand.Reader, publicKey.N)
		cipherNum, _ := EncryptNumberWithNonce(&publicKey, r, num)
		//cipherNum1,_ := EncryptWithNonce(&publicKey, r, num1.Bytes())
		num_test, _ := DecryptNumber(privateKey, cipherNum)
		fmt.Println("decrypted num is ", num_test)
		if num_test.Cmp(num) != 0 {
			fmt.Println("DecryptNumber failed")
			return
		}
		cw := &CiphertextWitness{X: *num, R: *r}
		ct := &CiphertextStatement{Ek: publicKey, C: *cipherNum}
		proof, err := zkpaillier_prove(cw, ct)
		if err != nil {
			fmt.Println("zkpaillier_prove failed ", err.Error())
			return
		}
		fmt.Printf("zkpaillier_prove proof is %v %v %v\n", proof.Z1.Bytes(), proof.Z2.Bytes(), proof.C_prime.Bytes())
		ret, err := zkpaillier_verify(proof, ct)
		if err != nil {
			fmt.Println("zkpaillier_verify failed", err.Error())
			return
		}
		fmt.Println("zkpaillier_verify result is ", ret)
		if !ret {
			fmt.Println("zkpaillier_verify failed")
			return
		}
	}
	fmt.Println("test ok!")
}
func TestBalanceZkPaillier(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	balance, _ := new(big.Int).SetString("1000", 10)
	amount, _ := new(big.Int).SetString("20", 10)
	//num1,_ := new(big.Int).SetString("1000",10)
	r, _ := rand.Int(rand.Reader, publicKey.N)
	cipherBalance, _ := EncryptWithNonce(&publicKey, r, balance.Bytes())
	r1, _ := rand.Int(rand.Reader, publicKey.N)
	cipherAmount, _ := EncryptWithNonce(&publicKey, r1, amount.Bytes())
	newBalance := new(big.Int).Add(balance, amount)
	cipherNewBalance := AddCipher(&publicKey, cipherBalance.Bytes(), cipherAmount.Bytes())
	//cipherNewBalanceNum := new(big.Int).SetBytes(cipherNewBalance)
	cipherNewBalance1 := AddCipher(&publicKey, cipherNewBalance, cipherAmount.Bytes())
	cipherNewBalanceNum1 := new(big.Int).SetBytes(cipherNewBalance1)
	newBalance1 := new(big.Int).Add(newBalance, amount)
	r2 := new(big.Int).Mod(new(big.Int).Mul(r, r1), publicKey.N)
	r3 := new(big.Int).Mod(new(big.Int).Mul(r2, r1), publicKey.N)
	cw := &CiphertextWitness{X: *newBalance1, R: *r3}
	ct := &CiphertextStatement{Ek: publicKey, C: *cipherNewBalanceNum1}
	proof, err := zkpaillier_prove(cw, ct)
	if err != nil {
		fmt.Println("zkpaillier_prove failed ", err.Error())
		return
	}
	fmt.Printf("zkpaillier_prove proof is %v %v %v\n", proof.Z1.Bytes(), proof.Z2.Bytes(), proof.C_prime.Bytes())
	ret, err := zkpaillier_verify(proof, ct)
	if err != nil {
		fmt.Println("zkpaillier_verify failed", err.Error())
		return
	}
	fmt.Println("zkpaillier_verify result is ", ret)
}
func TestSliceAppend(t *testing.T) {
	var1 := "123"
	var2 := "456"
	var3 := "789"
	var varBytes []byte
	varBytes = append(append(append(varBytes, []byte(var1)...), []byte(var2)...), []byte(var3)...)
	fmt.Println(varBytes)
}
func TestBigIntDiv(t *testing.T) {
	quo := new(big.Int).Div(new(big.Int).SetInt64(5), new(big.Int).SetInt64(2))
	fmt.Println(quo)
}
func TestRandom(t *testing.T) {
	for i := 0; i < 100; i++ {
		num, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(2))
		fmt.Println(num)
	}
}
func TestZkpaillierRange(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	num, _ := new(big.Int).SetString("10", 10)
	//num1,_ := new(big.Int).SetString("1000",10)
	r, _ := rand.Int(rand.Reader, publicKey.N)
	cnum, _ := EncryptWithNonce(&publicKey, r, num.Bytes())
	rnum := new(big.Int).SetInt64(90)
	ep, drp := zkpaillier_encrypted_pairs(&publicKey, rnum, 128)
	mrand.Seed(int64(time.Now().Second()))
	eNum1 := mrand.Int63()
	eNum2 := mrand.Int63()
	var buff []byte
	buff_tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(buff_tmp, uint64(eNum1))
	buff = append(buff, buff_tmp...)
	binary.BigEndian.PutUint64(buff_tmp, uint64(eNum2))
	buff = append(buff, buff_tmp...)
	e := buff
	responses := zkpaillier_range_prove(&publicKey, num, r, e, rnum, &drp, 128)
	pass, err := zkpaillier_range_verify(&publicKey, e, &ep, responses, rnum, cnum, 128)
	if err != nil {
		fmt.Println("zkpaillier_range_verify failed", err.Error())
		return
	}
	fmt.Println("verify result is ", pass)

}
func TestZkpaillierNiRange(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	//shift_num := new(big.Int).SetInt64(0x7fffffffffffffff)
	//shift_num := new(big.Int).SetInt64(65536)
	//num,_ := new(big.Int).SetString("100", 10)
	//num1 := new(big.Int).Add(shift_num,num)
	//rstart := new(big.Int).Sub(new(big.Int).Exp(new(big.Int).SetInt64(2),new(big.Int).SetInt64(256),nil),one)
	rstart := new(big.Int).SetInt64(100)
	//rstart_one_third := new(big.Int).Div(rstart,new(big.Int).SetInt64(3))
	//num_x := new(big.Int).SetInt64(1)

	//fmt.Println(new(big.Int).Mod(num_x,new(big.Int).SetInt64(3)))
	//for i := 0; i < 1000;i++ {
		num_x := new(big.Int).SetInt64(32)
		//num_x := new(big.Int).SetInt64(100000000000000)
		//num_x = new(big.Int).Neg(num_x)
		fmt.Println("num_x is ",num_x)
		r, _ := rand.Int(rand.Reader, publicKey.N)

		//rem := new(big.Int).Div(rstart,new(big.Int).SetInt64(3))
		//enlarge_mul := new(big.Int).Exp(new(big.Int).SetInt64(2),new(big.Int).SetInt64(244),nil)
	    //fmt.Println("enlarge_mul is ",enlarge_mul.String())
       //enlarge_num := new(big.Int).Mul(enlarge_mul,num_x)
        //fmt.Println("enlarge_num is ",enlarge_num.String())
		//num1 := new(big.Int).Add(rem,enlarge_num)
	    //fmt.Println("num1 is ",num1.String())
	    cnumx, _ := EncryptNumberWithNonce(&publicKey, r, num_x)
	    cnumx1, _ := EncryptWithNonce(&publicKey, r, num_x.Bytes())
	    fmt.Printf("cnumx is %v,cnumx1 is %v\n",cnumx,cnumx1)
	    //if num1.Cmp(rstart_one_third) > 0 {
		//	fmt.Println("num1 more than one third of range")
		//	return
		//}
		//r1, _ := rand.Int(rand.Reader, publicKey.N)
		res, err := zkpaillier_ni_range_prove(&publicKey, rstart, cnumx,
			num_x,r)
		if err != nil {
			fmt.Println("zkpaillier_ni_range_prove failed ", err.Error())
			return
		}

		pass, err := zkpaillier_ni_range_verify(&publicKey, res.Proof, res.Encrypted_pairs, cnumx, rstart)
		if err != nil {
			fmt.Println("zkpaillier_range_verify failed", err.Error())
			return
		}
		if pass {
			fmt.Println("verify failed!!!!")
			return
		}

	//}
	fmt.Println("verify passed!!! ")
}
func TestRandomBytes(t *testing.T) {
	mrand.Seed(int64(time.Now().Second()))
	for i := 0; i < 100; i++ {
		eNum := mrand.Int63()
		buff := make([]byte, 8)
		binary.BigEndian.PutUint64(buff, uint64(eNum))
		fmt.Println(buff[:5])
	}
}
func TestZkpaillierAll(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	amountNum, _ := new(big.Int).SetString("20", 10)
	negAmountNum := new(big.Int).Neg(amountNum)
	fmt.Println("negAmountNum is ", negAmountNum.Int64())
	balanceNum, _ := new(big.Int).SetString("100", 10)
	//num1,_ := new(big.Int).SetString("1000",10)
	r, _ := rand.Int(rand.Reader, publicKey.N)
	cipherAmountNum, _ := EncryptWithNonce(&publicKey, r, negAmountNum.Bytes())
	//1.证明密文是由明文经过pailling加密生成
	x1 := negAmountNum
	r1 := r
	c1 := cipherAmountNum
	//pt,_ := Decrypt(privateKey,cipherAmountNum.Bytes())
	//amountNum2 := new(big.Int).SetBytes(pt)
	//fmt.Println(amountNum2)
	cw := &CiphertextWitness{*x1, *r1}
	ci := &CiphertextStatement{publicKey, *c1}
	proof_amount_paillier, err := zkpaillier_prove(cw, ci)
	if err != nil {

	}

	x2 := balanceNum
	r2, _ := rand.Int(rand.Reader, publicKey.N)
	c2, _ := EncryptNumberWithNonce(&publicKey, r2, x2)
	cw1 := &CiphertextWitness{*x2, *r2}
	ci1 := &CiphertextStatement{publicKey, *c2}
	proof_balance_paillier, err := zkpaillier_prove(cw1, ci1)
	if err != nil {

	}

	x3 := new(big.Int).Add(x2, x1)
	//x3 := new(big.Int).SetInt64(120)
	fmt.Println("balance is ", x3.Int64())
	r3 := new(big.Int).Mod(new(big.Int).Mul(r2, r1), publicKey.N)
	//r3 := new(big.Int).Mul(r2,r1)
	//r3,_ := rand.Int(rand.Reader,publicKey.N)
	c3, _ := EncryptNumberWithNonce(&publicKey, r3, x3)
	cw3 := &CiphertextWitness{*x3, *r3}
	ci3 := &CiphertextStatement{publicKey, *c3}
	proof_remain_balance_paillier, err := zkpaillier_prove(cw3, ci3)
	if err != nil {

	}
	//证明转账金额大于0
	shift_num := new(big.Int).SetInt64(65536)
	secret_x := new(big.Int).Add(shift_num, x1)
	cipher_secret_x, err := EncryptWithNonce(&publicKey, r1, secret_x.Bytes())
	if err != nil {

	}
	proof_amount_positive, err := zkpaillier_ni_range_prove(&publicKey, new(big.Int).SetInt64(65536), cipher_secret_x, secret_x, r1)
	if err != nil {

	}
	//证明余额足够
	secret_x3 := new(big.Int).Add(shift_num, x3)
	cipher_secret_x3, err1 := EncryptWithNonce(&publicKey, r3, secret_x3.Bytes())
	if err1 != nil {

	}
	proof_remain_balance_positive, err := zkpaillier_ni_range_prove(&publicKey, shift_num, cipher_secret_x3, secret_x3, r3)
	if err != nil {

	}

	join_proof := &JoinProof{
		CipherAmountProof:  proof_amount_paillier,
		CipherBalanceProof: proof_balance_paillier,
		CipherRemainProof:  proof_remain_balance_paillier,
		EpAmountRange:      proof_amount_positive.Encrypted_pairs,
		AmountRangeProof:   proof_amount_positive.Proof,
		EpRemainRange:      proof_remain_balance_positive.Encrypted_pairs,
		BalanceRangeProof:  proof_remain_balance_positive.Proof,
	}
	proof_bytes, err := rlp.EncodeToBytes(join_proof)
	if err != nil {
		return
	}
	fmt.Println("join proof is ", proof_bytes)

	//开始验证
	var join_proof_verify JoinProof
	err = rlp.DecodeBytes(proof_bytes, &join_proof_verify)
	if err != nil {
		fmt.Println("decode join proof bytes failed,err ", err.Error())
		return
	}

	//1.验证密文是否经由明文加密生成
	fmt.Println(join_proof_verify.CipherAmountProof)
	ret1, err := zkpaillier_verify(join_proof_verify.CipherAmountProof, ci)
	ret2, err := zkpaillier_verify(join_proof_verify.CipherBalanceProof, ci1)
	ret3, err := zkpaillier_verify(join_proof_verify.CipherRemainProof, ci3)
	ret4, err := zkpaillier_ni_range_verify(&publicKey, join_proof_verify.AmountRangeProof,
		join_proof_verify.EpAmountRange, cipher_secret_x, shift_num)

	cipher_remain_bytes := AddCipher(&publicKey, c2.Bytes(), c1.Bytes())
	cipher_shift := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(shift_num, publicKey.N), one), publicKey.NSquared)
	cipher_remain := new(big.Int).SetBytes(cipher_remain_bytes)
	cipher_remain1 := new(big.Int).Mod(new(big.Int).Mul(cipher_remain, cipher_shift), publicKey.NSquared)
	if cipher_remain1.Cmp(cipher_secret_x3) != 0 {
		fmt.Println("cipher_remain1 is not equal with secret_x3!")
	}
	//cipher_remain1 := new(big.Int).SetBytes(cipher_remain1_bytes)
	ret5, err := zkpaillier_ni_range_verify(&publicKey, join_proof_verify.BalanceRangeProof,
		join_proof_verify.EpRemainRange, cipher_remain1, new(big.Int).SetInt64(65536))
	fmt.Printf("ret1 = %v,ret2 = %v,ret3 = %v,ret4 = %v,ret5 = %v\n", ret1, ret2, ret3, ret4, ret5)
}

func TestMul(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	num1, _ := new(big.Int).SetString("15", 10)
	num2, _ := new(big.Int).SetString("20", 10)
	r, _ := rand.Int(rand.Reader, publicKey.N)
	cipherNum1, _ := EncryptWithNonce(&publicKey, r, num1.Bytes())
	cipherMul := Mul(&publicKey, cipherNum1.Bytes(), num2.Bytes())
	result, _ := Decrypt(privateKey, cipherMul)
	fmt.Println(new(big.Int).SetBytes(result))
}

func TestNegAmount(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	amountNum, _ := new(big.Int).SetString("20000000000", 10)
	negAmountNum := new(big.Int).Neg(amountNum)
	fmt.Println("negAmountNum is ", negAmountNum.Int64())
	//balanceNum, _ := new(big.Int).SetString("100", 10)
	//num1,_ := new(big.Int).SetString("1000",10)
	r, _ := rand.Int(rand.Reader, publicKey.N)
	cipherAmountNum, _ := EncryptWithNonce(&publicKey, r, negAmountNum.Bytes())
	//r1, _ := rand.Int(rand.Reader, publicKey.N)
	//cipherBalance, _ := EncryptWithNonce(&publicKey, r1, balanceNum.Bytes())
	//cipher_sub := AddCipher(&publicKey, cipherBalance.Bytes(), cipherAmountNum.Bytes())
	pt_sub, _ := Decrypt(privateKey, cipherAmountNum.Bytes())
	fmt.Println(new(big.Int).SetBytes(pt_sub))
}
func TestNegNum2(t *testing.T) {
	privateKey, _ := GenerateKey(rand.Reader, 1024)
	publicKey := privateKey.PublicKey
	x1 := new(big.Int).SetInt64(-30)
	r1,_ := rand.Int(rand.Reader,publicKey.N)
	c1,_ := EncryptNumberWithNonce(&publicKey,r1,x1)
	x2 := new(big.Int).SetInt64(20)
	r2,_ := rand.Int(rand.Reader,publicKey.N)
	c2,_ := EncryptNumberWithNonce(&publicKey,r2,x2)
	c3 := AddCipher(&publicKey,c2.Bytes(),c1.Bytes())
	//x3 := new(big.Int).Mul(x1,x2)
	x3,_ := Decrypt(privateKey,c3)
	fmt.Println(new(big.Int).SetBytes(x3))
}
func TestBigIntAdd(t *testing.T) {
	r := new(big.Int)
	z := new(big.Int)
    z,r = new(big.Int).QuoRem(new(big.Int).SetInt64(-5),new(big.Int).SetInt64(2),r)

    fmt.Println(z)
	fmt.Println(r)
}