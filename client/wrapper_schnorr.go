package main

import (
	"errors"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

func (c *Client) Schnorr(protocolType common.ProtocolType, dlog *dlog.ZpDLog, secret big.Int) error {

	prover := dlogproofs.NewSchnorrProver(dlog, protocolType)
	(c.handler).schnorrProver = prover

	initMsg := c.getInitialMsg()

	if protocolType != common.Sigma {
		commitment, err := open(c, initMsg) // sends pedersen's h=g^trapdoor
		if err != nil {
			return err
		}

		(c.handler).schnorrProver.PedersenReceiver.SetCommitment(commitment)
		pedersenDecommitment, err := proofRandomData(c, false, dlog.G, &secret)
		if err != nil {
			return err
		}

		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		r := new(big.Int).SetBytes(pedersenDecommitment.R)

		success := (c.handler).schnorrProver.PedersenReceiver.CheckDecommitment(r, challenge)
		if success {
			proved, err := proofData(c, challenge)
			logger.Noticef("Decommit successful, proved: %v", proved)
			if err != nil {
				return err
			}
		} else {
			logger.Notice("Decommitment failed")
			return errors.New("Decommitment failed")
		}
	} else {
		pedersenDecommitment, err := proofRandomData(c, true, dlog.G, &secret)
		if err != nil {
			return err
		}
		challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
		proved, err := proofData(c, challenge)
		if err != nil {
			return err
		}
		logger.Noticef("Decommit successful, proved: %v", proved)
	}

	return nil
}

func open(c *Client, openMsg *pb.Message) (*big.Int, error) {
	h := (c.handler).schnorrProver.GetOpeningMsg()

	openMsg.Content = &pb.Message_PedersenFirst{
		&pb.PedersenFirst{H: h.Bytes()},
	}

	err := c.send(openMsg)
	if err != nil {
		return nil, err
	}

	resp, err := c.recieve()
	if err != nil {
		return nil, err
	}

	bigint := resp.GetBigint()
	commitment := new(big.Int).SetBytes(bigint.X1)
	return commitment, nil
}

func proofRandomData(c *Client, isFirstMsg bool, a, secret *big.Int) (*pb.PedersenDecommitment, error) {

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
		return nil, err
	}

	resp, err := c.recieve()
	if err != nil {
		return nil, err
	}

	pedersenDecommitment := resp.GetPedersenDecommitment()
	return pedersenDecommitment, nil
}

func proofData(c *Client, challenge *big.Int) (bool, error) {
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
		return false, err
	}

	resp, err := c.recieve()
	if err != nil {
		return false, err
	}

	return resp.GetStatus().Success, nil
}
