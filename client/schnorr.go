package client

import (
	"fmt"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

func (c *Client) Schnorr(protocolType common.ProtocolType, dlog *dlog.ZpDLog, secret *big.Int) error {
	prover := dlogproofs.NewSchnorrProver(dlog, protocolType)
	c.handler.schnorrProver = prover

	initMsg := c.getInitialMsg()

	if protocolType != common.Sigma {
		commitment, err := c.open(initMsg) // sends pedersen's h=g^trapdoor
		if err != nil {
			return err
		}

		c.handler.schnorrProver.PedersenReceiver.SetCommitment(commitment)
		pedersenDecommitment, err := c.proofRandomData(false, dlog.G, secret)
		if err != nil {
			return err
		}

		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		r := new(big.Int).SetBytes(pedersenDecommitment.R)

		success := c.handler.schnorrProver.PedersenReceiver.CheckDecommitment(r, challenge)
		if success {
			proved, err := c.proofData(challenge)
			logger.Noticef("Decommitment successful, proved: %v", proved)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("Decommitment failed")
		}
	} else {
		pedersenDecommitment, err := c.proofRandomData(true, dlog.G, secret)
		if err != nil {
			return err
		}
		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		proved, err := c.proofData(challenge)
		if err != nil {
			return err
		}
		logger.Noticef("Decommitment successful, proved: %v", proved)
	}

	return nil
}

func (c *Client) open(openMsg *pb.Message) (*big.Int, error) {
	h := c.handler.schnorrProver.GetOpeningMsg()

	openMsg.Content = &pb.Message_PedersenFirst{
		&pb.PedersenFirst{H: h.Bytes()},
	}

	if err := c.send(openMsg); err != nil {
		return nil, err
	}

	resp, err := c.receive()
	if err != nil {
		return nil, err
	}

	bigint := resp.GetBigint()
	return new(big.Int).SetBytes(bigint.X1), nil
}

func (c *Client) proofRandomData(isFirstMsg bool, a, secret *big.Int) (*pb.PedersenDecommitment, error) {

	x := c.handler.schnorrProver.GetProofRandomData(secret, a)
	b, _ := c.handler.schnorrProver.DLog.Exponentiate(a, secret)

	pRandomData := pb.SchnorrProofRandomData{
		X: x.Bytes(),
		A: a.Bytes(),
		B: b.Bytes(),
	}

	msg := &pb.Message{}
	if isFirstMsg {
		msg = c.getInitialMsg()
	}

	msg.Content = &pb.Message_SchnorrProofRandomData{
		&pRandomData,
	}

	if err := c.send(msg); err != nil {
		return nil, err
	}

	resp, err := c.receive()
	if err != nil {
		return nil, err
	}

	return resp.GetPedersenDecommitment(), nil
}

func (c *Client) proofData(challenge *big.Int) (bool, error) {
	z, trapdoor := c.handler.schnorrProver.GetProofData(challenge)
	if trapdoor == nil { // sigma protocol and ZKP
		trapdoor = new(big.Int)
	}

	pData := pb.SchnorrProofData{
		Z:        z.Bytes(),
		Trapdoor: trapdoor.Bytes(),
	}

	msg := &pb.Message{
		Content: &pb.Message_SchnorrProofData{
			&pData,
		},
	}

	if err := c.send(msg); err != nil {
		return false, err
	}

	resp, err := c.receive()
	if err != nil {
		return false, err
	}
	return resp.GetStatus().Success, nil
}
