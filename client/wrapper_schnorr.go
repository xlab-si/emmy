package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

func (c *Client) Schnorr(dlog *dlog.ZpDLog, secret big.Int) {
	protocolType := c.getProtocolType()

	prover := dlogproofs.NewSchnorrProver(dlog, protocolType)
	(c.handler).schnorrProver = prover

	initMsg := c.getInitialMsg()

	if protocolType != common.Sigma {
		commitment := open(c, initMsg) // sends pedersen's h=g^trapdoor
		(c.handler).schnorrProver.PedersenReceiver.SetCommitment(commitment)
		pedersenDecommitment := proofRandomData(c, false, dlog.G, &secret)

		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		r := new(big.Int).SetBytes(pedersenDecommitment.R)

		success := (c.handler).schnorrProver.PedersenReceiver.CheckDecommitment(r, challenge)
		if success {
			proved := proofData(c, challenge)
			logger.Noticef("Decommit successful, proved: %v", proved)
		} else {
			logger.Notice("Decommitment failed")
			return
		}
	} else {
		pedersenDecommitment := proofRandomData(c, true, dlog.G, &secret)
		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		proved := proofData(c, challenge)
		logger.Noticef("Decommit successful, proved: %v", proved)
	}

}

func open(c *Client, openMsg *pb.Message) *big.Int {
	h := (c.handler).schnorrProver.GetOpeningMsg()

	openMsg.Content = &pb.Message_PedersenFirst{
		&pb.PedersenFirst{H: h.Bytes()},
	}

	err := c.send(openMsg)
	if err != nil {
		return nil
	}

	resp, err := c.recieve()
	if err != nil {
		return nil
	}

	bigint := resp.GetBigint()
	commitment := new(big.Int).SetBytes(bigint.X1)
	return commitment
}

func proofRandomData(c *Client, isFirstMsg bool, a, secret *big.Int) *pb.PedersenDecommitment {

	x := (c.handler).schnorrProver.GetProofRandomData(secret, a)
	b, _ := (c.handler).schnorrProver.DLog.Exponentiate(a, secret)

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

	err := c.send(msg)
	if err != nil {
		return nil
	}

	resp, err := c.recieve()
	if err != nil {
		return nil
	}

	pedersenDecommitment := resp.GetPedersenDecommitment()
	return pedersenDecommitment
}

func proofData(c *Client, challenge *big.Int) bool {
	z, trapdoor := (c.handler).schnorrProver.GetProofData(challenge)
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

	err := c.send(msg)
	if err != nil {
		return false
	}

	resp, err := c.recieve()
	if err != nil {
		return false
	}

	return resp.GetStatus().Success
}
