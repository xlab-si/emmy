package main

import (
	"errors"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

func (c *Client) SchnorrEC(protocolType common.ProtocolType, dlog *dlog.ECDLog, secret big.Int) error {
	prover, err := dlogproofs.NewSchnorrECProver(protocolType)
	if err != nil {
		logger.Criticalf("Could not create schnorr EC prover: %v", err)
		return err
	}

	(c.handler).schnorrECProver = prover

	initMsg := c.getInitialMsg()

	a := common.ECGroupElement{
		X: dlog.Curve.Params().Gx,
		Y: dlog.Curve.Params().Gy,
	}

	if protocolType != common.Sigma { // ZKP or ZKPOK
		commitment, err := openEC(c, initMsg)
		if err != nil {
			return err
		}

		(c.handler).schnorrECProver.PedersenReceiver.SetCommitment(commitment)
		pedersenDecommitment, err := proofRandomDataEC(c, false, &a, &secret)
		if err != nil {
			return err
		}

		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		r := new(big.Int).SetBytes(pedersenDecommitment.R)

		success := (c.handler).schnorrECProver.PedersenReceiver.CheckDecommitment(r, challenge)
		if success {
			proved, err := proofDataEC(c, challenge)
			if err != nil {
				return err
			}
			logger.Noticef("Decommit successful, proved: %v", proved)
		} else {
			logger.Notice("Decommitment failed")
			return errors.New("Decommitment failed")
		}
	} else {
		pedersenDecommitment, err := proofRandomDataEC(c, true, &a, &secret)
		if err != nil {
			return err
		}
		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		proved, err := proofDataEC(c, challenge)
		if err != nil {
			return err
		}
		logger.Noticef("Decommit successful, proved: %v", proved)
	}

	return nil
}

func openEC(c *Client, openMsg *pb.Message) (*common.ECGroupElement, error) {
	h := (c.handler).schnorrECProver.GetOpeningMsg()
	ecge := common.ToPbECGroupElement(h)

	openMsg.Content = &pb.Message_EcGroupElement{ecge}

	err := c.send(openMsg)
	if err != nil {
		return nil, err
	}

	resp, err := c.recieve()
	if err != nil {
		return nil, err
	}

	ecge = resp.GetEcGroupElement()
	commitment := common.ToECGroupElement(ecge)
	return commitment, nil
}

func proofRandomDataEC(c *Client, isFirstMsg bool, a *common.ECGroupElement, secret *big.Int) (*pb.PedersenDecommitment, error) {
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
		return nil, err
	}

	resp, err := c.recieve()
	if err != nil {
		return nil, err
	}

	pedersenDecommitment := resp.GetPedersenDecommitment()
	return pedersenDecommitment, nil
}

func proofDataEC(c *Client, challenge *big.Int) (bool, error) {
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
		return false, err
	}

	resp, err := c.recieve()
	if err != nil {
		return false, err
	}

	return resp.GetStatus().Success, nil
}
