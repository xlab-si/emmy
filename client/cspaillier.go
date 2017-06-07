package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/encryption"
	"math/big"
)

func (c *Client) CSPaillier(pubKeyPath string, m, label *big.Int) (bool, error) {
	encryptor, err := encryption.NewCSPaillierFromPubKeyFile(pubKeyPath)
	if err != nil {
		return false, err
	}

	c.handler.paillierEncryptor = encryptor
	u, e, v, _ := c.handler.paillierEncryptor.Encrypt(m, label)

	if err = c.openCSPaillier(m, u, e, v, label); err != nil {
		return false, err
	}

	challenge, err := c.cspaillierProveRandomData(u, e, label)
	if err != nil {
		return false, err
	}

	proved, err := c.cspaillierProveData(challenge)
	if err != nil {
		return false, err
	}

	return proved, nil
}

func (c *Client) openCSPaillier(m, u, e, v, label *big.Int) error {
	l, delta := c.handler.paillierEncryptor.GetOpeningMsg(m)

	opening := pb.CSPaillierOpening{
		U:     u.Bytes(),
		E:     e.Bytes(),
		V:     v.Bytes(),
		Delta: delta.Bytes(),
		Label: label.Bytes(),
		L:     l.Bytes(),
	}

	openMsg := c.getInitialMsg()
	openMsg.Content = &pb.Message_CsPaillierOpening{&opening}

	if err := c.send(openMsg); err != nil {
		return err
	}

	if _, err := c.receive(); err != nil {
		return err
	}

	return nil
}

func (c *Client) cspaillierProveRandomData(u, e, label *big.Int) (*big.Int, error) {
	u1, e1, v1, delta1, l1, err := c.handler.paillierEncryptor.GetProofRandomData(u, e, label)
	if err != nil {
		return nil, err
	}

	data := pb.CSPaillierProofRandomData{
		U1:     u1.Bytes(),
		E1:     e1.Bytes(),
		V1:     v1.Bytes(),
		Delta1: delta1.Bytes(),
		L1:     l1.Bytes(),
	}
	msg := &pb.Message{
		Content: &pb.Message_CsPaillierProofRandomData{&data},
	}

	if err = c.send(msg); err != nil {
		return nil, err
	}

	resp, err := c.receive()
	if err != nil {
		return nil, err
	}

	bigint := resp.GetBigint()
	return new(big.Int).SetBytes(bigint.X1), nil
}

func (c *Client) cspaillierProveData(challenge *big.Int) (bool, error) {
	rTilde, sTilde, mTilde := c.handler.paillierEncryptor.GetProofData(challenge)

	data := pb.CSPaillierProofData{
		RTilde:      rTilde.Bytes(),
		RTildeIsNeg: rTilde.Cmp(big.NewInt(0)) < 0,
		STilde:      sTilde.Bytes(),
		STildeIsNeg: sTilde.Cmp(big.NewInt(0)) < 0,
		MTilde:      mTilde.Bytes(),
		MTildeIsNeg: mTilde.Cmp(big.NewInt(0)) < 0,
	}
	msg := &pb.Message{
		Content: &pb.Message_CsPaillierProofData{&data},
	}

	if err := c.send(msg); err != nil {
		return false, err
	}

	resp, err := c.receive()
	if err != nil {
		return false, err
	}
	status := resp.GetStatus()
	return status.Success, nil
}
