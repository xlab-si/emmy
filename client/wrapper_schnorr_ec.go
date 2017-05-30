package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

func (c *Client) SchnorrEC(dlog *dlog.ECDLog, secret big.Int) {
	protocolType := c.getProtocolType()

	prover, err := dlogproofs.NewSchnorrECProver(protocolType)
	if err != nil {
		logger.Criticalf("Could not create schnorr EC prover: %v", err)
		return
	}

	(c.handler).schnorrECProver = prover

	initMsg := c.getInitialMsg()

	a := common.ECGroupElement{
		X: dlog.Curve.Params().Gx,
		Y: dlog.Curve.Params().Gy,
	}

	if protocolType != common.Sigma { // ZKP or ZKPOK
		commitment := openEC(c, initMsg)
		(c.handler).schnorrECProver.PedersenReceiver.SetCommitment(commitment)
		pedersenDecommitment := proofRandomDataEC(c, false, &a, &secret)

		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		r := new(big.Int).SetBytes(pedersenDecommitment.R)

		success := (c.handler).schnorrECProver.PedersenReceiver.CheckDecommitment(r, challenge)
		if success {
			proved := proofDataEC(c, challenge)
			logger.Noticef("Decommit successful, proved: %v", proved)
		} else {
			logger.Notice("Decommitment failed")
			return
		}
	} else {
		pedersenDecommitment := proofRandomDataEC(c, true, &a, &secret)
		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		proved := proofDataEC(c, challenge)
		logger.Noticef("Decommit successful, proved: %v", proved)
	}

}

func openEC(c *Client, openMsg *pb.Message) *common.ECGroupElement {
	h := (c.handler).schnorrECProver.GetOpeningMsg()
	ecge := common.ToPbECGroupElement(h)

	openMsg.Content = &pb.Message_EcGroupElement{ecge}

	err := c.send(openMsg)
	if err != nil {
		return nil
	}

	resp, err := c.recieve()
	if err != nil {
		return nil
	}

	ecge = resp.GetEcGroupElement()
	commitment := common.ToECGroupElement(ecge)
	return commitment
}

func proofRandomDataEC(c *Client, isFirstMsg bool, a *common.ECGroupElement, secret *big.Int) *pb.PedersenDecommitment {
	x := (c.handler).schnorrECProver.GetProofRandomData(secret, a) // x = a^r, b = a^secret is "public key"

	b1, b2 := (c.handler).schnorrECProver.DLog.Exponentiate(a.X, a.Y, secret)
	b := &common.ECGroupElement{X: b1, Y: b2}

	req := &pb.Message{}
	if isFirstMsg {
		req = c.getInitialMsg()
	}

	req.Content = &pb.Message_SchnorrEcProofRandomData{
		&pb.SchnorrECProofRandomData{
			X: common.ToPbECGroupElement(x),
			A: common.ToPbECGroupElement(a),
			B: common.ToPbECGroupElement(b),
		},
	}

	err := c.send(req)
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

func proofDataEC(c *Client, challenge *big.Int) bool {
	z, trapdoor := (c.handler).schnorrECProver.GetProofData(challenge)
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
