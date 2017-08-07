package client

import (
	"errors"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/pseudonymsys"
	"google.golang.org/grpc"
	"math/big"
)

type PseudonymsysClient struct {
	genericClient
	conn *grpc.ClientConn
	dlog *dlog.ZpDLog
}

func NewPseudonymsysClient(conn *grpc.ClientConn) (*PseudonymsysClient, error) {
	dlog := config.LoadDLog("pseudonymsys")

	return &PseudonymsysClient{
		conn: conn,
		dlog: dlog,
	}, nil
}

// GenerateNym generates a nym and registers it to the organization. Do not use
// the same CACertificate for different organizations - use it only once!
func (c *PseudonymsysClient) GenerateNym(userSecret *big.Int,
	caCertificate *pseudonymsys.CACertificate) (
	*pseudonymsys.Pseudonym, error) {
	// new client needs to be created in each method to implicitly call server Run method:
	genericClient, err := newGenericClient(c.conn)
	if err != nil {
		return nil, err
	}
	c.genericClient = *genericClient

	prover := dlogproofs.NewDLogEqualityProver(c.dlog)

	// Differently as in Pseudonym Systems paper a user here generates a nym (if master
	// key pair is (g, g^s), a generated nym is (g^gamma, g^(gamma * s)),
	// however a user needs to prove that log_nymA(nymB) = log_blindedA(blindedB).

	// Note that as there is very little logic needed (besides what is in DLog equality
	// prover), everything is implemented here (no pseudoynymsys nym gen client).
	gamma := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	nymA, _ := c.dlog.ExponentiateBaseG(gamma)
	nymB, _ := c.dlog.Exponentiate(nymA, userSecret)

	// Prove now that log_nymA(nymB) = log_blindedA(blindedB):
	// g1 = nymA, g2 = blindedA
	x1, x2 := prover.GetProofRandomData(userSecret, nymA, caCertificate.BlindedA)
	pRandomData := pb.PseudonymsysNymGenProofRandomData{
		X1: x1.Bytes(),
		A1: nymA.Bytes(),
		B1: nymB.Bytes(),
		X2: x2.Bytes(),
		A2: caCertificate.BlindedA.Bytes(),
		B2: caCertificate.BlindedB.Bytes(),
		R:  caCertificate.R.Bytes(),
		S:  caCertificate.S.Bytes(),
	}

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_PSEUDONYMSYS_NYM_GEN,
		SchemaVariant: pb.SchemaVariant_SIGMA,
		Content: &pb.Message_PseudonymsysNymGenProofRandomData{
			&pRandomData,
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	pedersenDecommitment, err := resp.GetPedersenDecommitment(), nil
	if err != nil {
		return nil, err
	}
	challenge := new(big.Int).SetBytes(pedersenDecommitment.X)

	z := prover.GetProofData(challenge)

	msg := &pb.Message{
		Content: &pb.Message_SchnorrProofData{
			&pb.SchnorrProofData{
				Z: z.Bytes(),
				//Trapdoor: trapdoor.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}
	verified := resp.GetStatus().Success
	if verified {
		// todo: store in some DB: (orgName, nymA, nymB)
		return pseudonymsys.NewPseudonym(nymA, nymB), nil
	} else {
		err := errors.New("The proof for nym registration failed.")
		return nil, err
	}
}

// ObtainCredential returns anonymous credential.
func (c *PseudonymsysClient) ObtainCredential(userSecret *big.Int,
	nym *pseudonymsys.Pseudonym, orgPubKeys *pseudonymsys.OrgPubKeys) (
	*pseudonymsys.Credential, error) {
	// new client needs to be created in each method to implicitly call server Run method:
	genericClient, err := newGenericClient(c.conn)
	if err != nil {
		return nil, err
	}
	c.genericClient = *genericClient

	gamma := common.GetRandomInt(c.dlog.GetOrderOfSubgroup())
	equalityVerifier1 := dlogproofs.NewDLogEqualityBTranscriptVerifier(c.dlog, gamma)
	equalityVerifier2 := dlogproofs.NewDLogEqualityBTranscriptVerifier(c.dlog, gamma)

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. Authentication is done via Schnorr.
	schnorrProver := dlogproofs.NewSchnorrProver(c.dlog, common.Sigma)
	x := schnorrProver.GetProofRandomData(userSecret, nym.A)

	pRandomData := pb.SchnorrProofRandomData{
		X: x.Bytes(),
		A: nym.A.Bytes(),
		B: nym.B.Bytes(),
	}

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_PSEUDONYMSYS_ISSUE_CREDENTIAL,
		SchemaVariant: pb.SchemaVariant_SIGMA,
		Content: &pb.Message_SchnorrProofRandomData{
			&pRandomData,
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	ch := resp.GetBigint()
	challenge := new(big.Int).SetBytes(ch.X1)

	z, _ := schnorrProver.GetProofData(challenge)
	msg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: z.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	randomData := resp.GetPseudonymsysIssueProofRandomData()
	// Now the organization needs to prove that it knows log_b(A), log_g(h2) and log_b(A) = log_g(h2).
	// And to prove that it knows log_aA(B), log_g(h1) and log_aA(B) = log_g(h1).
	// g1 = dlog.G, g2 = nym.B, t1 = A, t2 = orgPubKeys.H2

	x11 := new(big.Int).SetBytes(randomData.X11)
	x12 := new(big.Int).SetBytes(randomData.X12)
	x21 := new(big.Int).SetBytes(randomData.X21)
	x22 := new(big.Int).SetBytes(randomData.X22)
	A := new(big.Int).SetBytes(randomData.A)
	B := new(big.Int).SetBytes(randomData.B)

	challenge1 := equalityVerifier1.GetChallenge(c.dlog.G, nym.B, orgPubKeys.H2, A, x11, x12)
	aA, _ := c.dlog.Multiply(nym.A, A)
	challenge2 := equalityVerifier2.GetChallenge(c.dlog.G, aA, orgPubKeys.H1, B, x21, x22)

	msg = &pb.Message{
		Content: &pb.Message_DoubleBigint{
			&pb.DoubleBigInt{
				X1: challenge1.Bytes(),
				X2: challenge2.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	proofData := resp.GetDoubleBigint()
	z1 := new(big.Int).SetBytes(proofData.X1)
	z2 := new(big.Int).SetBytes(proofData.X2)

	verified1, transcript1, bToGamma, AToGamma := equalityVerifier1.Verify(z1)
	verified2, transcript2, aAToGamma, BToGamma := equalityVerifier2.Verify(z2)

	aToGamma, _ := c.dlog.Exponentiate(nym.A, gamma)
	if verified1 && verified2 {
		valid1 := dlogproofs.VerifyBlindedTranscript(transcript1, c.dlog, c.dlog.G, orgPubKeys.H2,
			bToGamma, AToGamma)
		valid2 := dlogproofs.VerifyBlindedTranscript(transcript2, c.dlog, c.dlog.G, orgPubKeys.H1,
			aAToGamma, BToGamma)
		if valid1 && valid2 {
			credential := pseudonymsys.NewCredential(aToGamma, bToGamma, AToGamma, BToGamma,
				transcript1, transcript2)
			return credential, nil
		}
	}

	err = errors.New("Organization failed to prove that a credential is valid.")
	return nil, err
}

// TransferCredential transfers orgName's credential to organization where the
// authentication should happen (the organization takes credential issued by
// another organization).
func (c *PseudonymsysClient) TransferCredential(orgName string, userSecret *big.Int,
	nym *pseudonymsys.Pseudonym, credential *pseudonymsys.Credential) (bool, error) {
	genericClient, err := newGenericClient(c.conn)
	if err != nil {
		return false, err
	}
	c.genericClient = *genericClient

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. But we need also to prove that dlog_a(b) = dlog_a2(b2), where
	// a2, b2 are a1, b1 exponentiated to gamma, and (a1, b1) is a nym for organization that
	// issued a credential. So we can do both proofs at the same time using DLogEqualityProver.
	equalityProver := dlogproofs.NewDLogEqualityProver(c.dlog)
	x1, x2 := equalityProver.GetProofRandomData(userSecret, nym.A, credential.SmallAToGamma)

	transcript1 := &pb.PseudonymsysTranscript{
		A:      credential.T1[0].Bytes(),
		B:      credential.T1[1].Bytes(),
		Hash:   credential.T1[2].Bytes(),
		ZAlpha: credential.T1[3].Bytes(),
	}
	transcript2 := &pb.PseudonymsysTranscript{
		A:      credential.T2[0].Bytes(),
		B:      credential.T2[1].Bytes(),
		Hash:   credential.T2[2].Bytes(),
		ZAlpha: credential.T2[3].Bytes(),
	}
	pbCredential := &pb.PseudonymsysCredential{
		SmallAToGamma: credential.SmallAToGamma.Bytes(),
		SmallBToGamma: credential.SmallBToGamma.Bytes(),
		AToGamma:      credential.AToGamma.Bytes(),
		BToGamma:      credential.BToGamma.Bytes(),
		T1:            transcript1,
		T2:            transcript2,
	}
	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_PSEUDONYMSYS_TRANSFER_CREDENTIAL,
		SchemaVariant: pb.SchemaVariant_SIGMA,
		Content: &pb.Message_PseudonymsysTransferCredentialData{
			&pb.PseudonymsysTransferCredentialData{
				OrgName:    orgName,
				X1:         x1.Bytes(),
				X2:         x2.Bytes(),
				NymA:       nym.A.Bytes(),
				NymB:       nym.B.Bytes(),
				Credential: pbCredential,
			},
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return false, err
	}

	ch := resp.GetBigint()
	challenge := new(big.Int).SetBytes(ch.X1)

	z := equalityProver.GetProofData(challenge)
	msg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: z.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return false, err
	}

	status := resp.GetStatus()
	return status.Success, nil
}
