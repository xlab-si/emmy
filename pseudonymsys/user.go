package pseudonymsys

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"log"
)

type User struct {
	DLog *dlog.ZpDLog
	EqualityProver *dlogproofs.DLogEqualityProver
	secret *big.Int
	a_tilde *big.Int
	b_tilde *big.Int
	a *big.Int
	b *big.Int
}

func NewUser(orgName, orgAddress string) (*User) {
	// todo:
	log.Println(orgName)
	log.Println(orgAddress)

	dlog := config.LoadPseudonymsysDLogFromConfig() // todo: load for this org
	secret := common.GetRandomInt(dlog.GetOrderOfSubgroup())

	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	prover, _ := dlogproofs.NewDLogEqualityProver()
	user := User {
		DLog: dlog,
		EqualityProver: prover,
		secret: secret,
	}
	
	return &user
}

func (user *User) GetFirstPseudonymGenMsg() (*big.Int, *big.Int) {
	gamma := common.GetRandomInt(user.DLog.GetOrderOfSubgroup())
	a_tilde, _ := user.DLog.ExponentiateBaseG(gamma)
	b_tilde, _ := user.DLog.Exponentiate(a_tilde, user.secret)
	user.a_tilde = a_tilde
	user.b_tilde = b_tilde
	return a_tilde, b_tilde
}

func (user *User) GetPseudonymGenRandomProofData(a *big.Int) (*big.Int, *big.Int) {
	b, _ := user.DLog.Exponentiate(a, user.secret)
	user.a = a
	user.b = b
	x1, x2 := user.EqualityProver.GetProofRandomData(user.secret, user.a_tilde, user.a)
	return x1, x2
}
	
func (user *User) GetPseudonymGenProofData(challenge *big.Int) *big.Int {
	z := user.EqualityProver.GetProofData(challenge)
	return z
}
	
func (user *User) GetNym() (*big.Int, *big.Int) {
	return user.a, user.b
}
	
	
	