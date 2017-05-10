package commitments

import (
	"math/big"
	"errors"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/common"
)

// Committer first needs to know H (it gets it from the receiver).
// Then committer can commit to some value x - it sends to receiver c = g^x * h^r.
// When decommitting, committer sends to receiver r, x; receiver checks whether c = g^x * h^r.
type PedersenCommitter struct {
	dLog *dlog.ZpDLog
	h *big.Int
	committedValue *big.Int
	r *big.Int
}

func NewPedersenCommitter(dlog *dlog.ZpDLog) *PedersenCommitter {
	committer := PedersenCommitter {
		dLog: dlog,
    }
    return &committer
}

// Value h needs to be obtained from a receiver and then set in a committer.
func (committer *PedersenCommitter) SetH(h *big.Int) {
	committer.h = h
}

// It receives a value x (to this value a commitment is made), chooses a random x, outputs c = g^x * g^r.
func (committer *PedersenCommitter) GetCommitMsg(val *big.Int) (*big.Int, error) {
	if (val.Cmp(committer.dLog.OrderOfSubgroup) == 1 || val.Cmp(big.NewInt(0)) == -1) { 
		err := errors.New("the committed value needs to be in Z_q (order of a base point)")	
		return nil, err
	}
	
	// c = g^x * h^r
	r := common.GetRandomInt(committer.dLog.OrderOfSubgroup)
	
	committer.r = r
	committer.committedValue = val
	t1, _ := committer.dLog.ExponentiateBaseG(val)
	t2, _ := committer.dLog.Exponentiate(committer.h, r)
	c, _ := committer.dLog.Multiply(t1, t2)

	return c, nil
}

// It returns values x and r (commitment was c = g^x * g^r).
func (committer *PedersenCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	val := committer.committedValue
	r := committer.r
	return val, r
}

func (committer *PedersenCommitter) VerifyTrapdoor(trapdoor *big.Int) (bool) {
	h, _ := committer.dLog.ExponentiateBaseG(trapdoor)
	if h.Cmp(committer.h) == 0 {
		return true
	} else {
		return false
	}
}

type PedersenReceiver struct {
	dLog *dlog.ZpDLog
	a *big.Int
	h *big.Int
	commitment *big.Int
}

func NewPedersenReceiver(dLog *dlog.ZpDLog) *PedersenReceiver {
	a := common.GetRandomInt(dLog.OrderOfSubgroup)
	h, _ := dLog.ExponentiateBaseG(a)
	
    receiver := new(PedersenReceiver)
    receiver.dLog = dLog
	receiver.a = a
    receiver.h = h
    
    return receiver
}

func NewPedersenReceiverFromExistingDLog(dLog *dlog.ZpDLog) *PedersenReceiver {
	a := common.GetRandomInt(dLog.OrderOfSubgroup)
	h, _ := dLog.ExponentiateBaseG(a)
	
    receiver := new(PedersenReceiver)
    receiver.dLog = dLog
	receiver.a = a
    receiver.h = h
    
    return receiver
}

func (s *PedersenReceiver) GetH() *big.Int {
	return s.h
}

func (s *PedersenReceiver) GetTrapdoor() *big.Int {
	return s.a
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (s *PedersenReceiver) SetCommitment(el *big.Int) {
	s.commitment = el
}

// When receiver receives a decommitment, CheckDecommitment verifies it against the stored value
// (stored by SetCommitment).
func (s *PedersenReceiver) CheckDecommitment(r, val *big.Int) bool {
	t1, _ := s.dLog.ExponentiateBaseG(val) // g^x
	t2, _ := s.dLog.Exponentiate(s.h, r) // h^r
	c, _ := s.dLog.Multiply(t1, t2) // g^x * h^r
	
	var success bool
	if c.Cmp(s.commitment) == 0 {
   		success = true
	} else {
   		success = false
	}

	return success
}







