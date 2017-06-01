package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/encryption"
	"math/big"
)

func (c *Client) Paillier(pubKeyPath string, m, label big.Int) (bool, error) {

	encryptor, err := encryption.NewCSPaillierFromPubKeyFile(pubKeyPath)
	if err != nil {
		return false, err
	}

	(c.handler).paillierEncryptor = encryptor
	u, e, v, _ := (c.handler).paillierEncryptor.Encrypt(&m, &label)

	err = openCSPaillier(c, &m, u, e, v, &label)
	if err != nil {
		return false, err
	}

	challenge, err := cspaillierProveRandomData(c, u, e, &label)
	if err != nil {
		return false, err
	}

	proved, err := cspaillierProveData(c, challenge)
	if err != nil {
		return false, err
	}

	return proved, nil
}

func openCSPaillier(c *Client, m, u, e, v, label *big.Int) error {
	l, delta := (c.handler).paillierEncryptor.GetOpeningMsg(m)

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

	err := c.send(openMsg)
	if err != nil {
		return err
	}

	_, err = c.recieve()
	if err != nil {
		return err
	}

	return nil
}

func cspaillierProveRandomData(c *Client, u, e, label *big.Int) (*big.Int, error) {

	u1, e1, v1, delta1, l1, err := (c.handler).paillierEncryptor.GetProofRandomData(u, e, label)
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

	err = c.send(msg)
	if err != nil {
		return nil, err
	}

	resp, err := c.recieve()
	if err != nil {
		return nil, err
	}

	bigint := resp.GetBigint()
	challenge := new(big.Int).SetBytes(bigint.X1)
	return challenge, nil

}

func cspaillierProveData(c *Client, challenge *big.Int) (bool, error) {
	rTilde, sTilde, mTilde := (c.handler).paillierEncryptor.GetProofData(challenge)

	rTildeIsNeg, sTildeIsNeg, mTildeIsNeg := false, false, false

	if rTilde.Cmp(big.NewInt(0)) < 0 {
		rTildeIsNeg = true
	}
	if sTilde.Cmp(big.NewInt(0)) < 0 {
		sTildeIsNeg = true
	}
	if mTilde.Cmp(big.NewInt(0)) < 0 {
		mTildeIsNeg = true
	}

	data := pb.CSPaillierProofData{
		RTilde:      rTilde.Bytes(),
		RTildeIsNeg: rTildeIsNeg,
		STilde:      sTilde.Bytes(),
		STildeIsNeg: sTildeIsNeg,
		MTilde:      mTilde.Bytes(),
		MTildeIsNeg: mTildeIsNeg,
	}
	msg := &pb.Message{
		Content: &pb.Message_CsPaillierProofData{&data},
	}

	err := c.send(msg)
	if err != nil {
		return false, err
	}

	resp, err := c.recieve()
	if err != nil {
		return false, err
	}

	status := resp.GetStatus()
	return status.Success, nil
}
