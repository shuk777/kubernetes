package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"

	pb "git.basebit.me/xss/tpm/tpm_attest/attestation"

	"github.com/google/go-attestation/attest"
)

//Verify take the address of the attestor,uid of this session and certificate of rootCA as input, output the verify result and possible errors
func AttestAK(client pb.AttestationClient, ctx context.Context, uid *string, rootCA string) ([]byte, error) {
	// Setting up a connection to attestor
	// conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	// if err != nil {
	// 	log.Fatalf("Cannot connect to attestor: %v", err)
	// 	return nil, err
	// }
	// defer conn.Close()
	// client := pb.NewAttestationClient(conn)
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	// defer cancel()

	//Send certificates request and verify them
	respCerts, err := client.GetCerts(ctx, &pb.GetCertsRequest{Uid: *uid})
	if err != nil {
		log.Fatalf("Cannot get certificates from attestor: %v", err)
		return nil, err
	}

	//Platform certificate verification
	platformCert, err := x509.ParseCertificate(respCerts.GetPlatformCert())
	if err != nil {
		log.Fatalf("Platform Certificate invalid: %v", err)
		return nil, err
	}

	rootCAFile, err := ioutil.ReadFile(rootCA)
	if err != nil {
		log.Fatalf("Do not have root CA certificate: %v", err)
		return nil, err
	}

	rootCABlock, _ := pem.Decode(rootCAFile)
	rootCACert, err := x509.ParseCertificate(rootCABlock.Bytes)
	if err != nil {
		log.Fatalf("Unvalid CA certificate: %v", err)
		return nil, err
	}

	if err := platformCert.CheckSignatureFrom(rootCACert); err != nil {
		log.Fatalf("Platform Certificate is not issued by root CA: %v", err)
		return nil, err
	}

	//EK certificate verification
	ekCert, err := x509.ParseCertificate(respCerts.GetEkCert())
	if err != nil {
		log.Fatalf("EK Certificate invalid: %v", err)
		return nil, err
	}

	if err := platformCert.CheckSignature(ekCert.SignatureAlgorithm, ekCert.RawTBSCertificate, ekCert.Signature); err != nil {
		log.Fatalf("EK certificate is not issued by platform: %v", err)
		return nil, err
	}

	//Happened after EK certificateis verified
	log.Printf("EK Certificate is verified!")

	//Send Attestation Key request and then generate a challenge using the AK.
	respAK, err := client.GetAK(ctx, &pb.GetAKRequest{Uid: *uid})
	if err != nil {
		log.Fatalf("Cannot get AK from attestor: %v", err)
		return nil, err
	}
	ekpub, err := x509.ParsePKIXPublicKey(respAK.GetEkPub())
	if err != nil {
		log.Fatalf("Cannot parse EK public key: %v", err)
		return nil, err
	}

	// Generate a challenge from AK and send back to the attestor
	params := attest.ActivationParameters{
		TPMVersion: 2,
		EK:         ekpub,
		AK: attest.AttestationParameters{
			Public:                  respAK.GetAk().GetAkPub(),
			UseTCSDActivationFormat: respAK.GetAk().GetTcsd(),
			CreateData:              respAK.GetAk().GetCreateData(),
			CreateAttestation:       respAK.GetAk().GetCreateAttestation(),
			CreateSignature:         respAK.GetAk().GetCreateSignature(),
		},
	}

	//encryptedCredentials are sent back to attestor, secret is kept locally for verification
	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		log.Fatalf("Invalid EK or AK,cannot generate challenge: %v", err)
		return nil, err
	}
	respChallenge, err := client.Challenge(ctx, &pb.ChallengeRequest{
		Uid:        *uid,
		Credential: encryptedCredentials.Credential,
		Secret:     encryptedCredentials.Secret,
	})
	if err != nil {
		log.Fatalf("Cannot challenge the attestor: %v", err)
		return nil, err
	}

	//This secret can be used as a secret session key
	secretHash := sha256.Sum256(secret)
	if bytes.Equal(secretHash[:], respChallenge.GetSecret()) {
		log.Println("Attestor solved the challenge, now can be trusted.Meanwhile, the secret key is exchanged and verified")
		return respAK.GetAk().GetAkPub(), nil
	} else {
		return nil, errors.New("attestor cannot solve the challenge")
	}
}

// To-DO: Generate AK certificate or locally store the AK pub?
func VerifyQuote(akPub []byte, client pb.AttestationClient, ctx context.Context, uid *string) (bool, error) {
	//Generate nonce and send a Quote request
	nonce := make([]byte, 5)
	rand.Read(nonce)
	respQuote, err := client.GetQuote(ctx, &pb.GetQuoteRequest{
		Uid:   *uid,
		Nonce: nonce,
	})
	if err != nil {
		log.Fatalf("Cannot request for quote: %v", err)
		return false, err
	}

	//Regenerate Quotes and PCRs from response
	quoteLen := len(respQuote.Quotes)
	quotes := make([]attest.Quote, 0)
	for i := 0; i < quoteLen; i++ {
		quote := attest.Quote{
			Version:   2,
			Quote:     respQuote.Quotes[i].Quote,
			Signature: respQuote.Quotes[i].Signature,
		}
		quotes = append(quotes, quote)
	}

	pcrLen := len(respQuote.Pcrs)
	pcrs := make([]attest.PCR, 0)
	for i := 0; i < pcrLen; i++ {
		pcr := attest.PCR{
			Index:     int(respQuote.Pcrs[i].Index),
			Digest:    respQuote.Pcrs[i].GetDigest(),
			DigestAlg: crypto.Hash(respQuote.Pcrs[i].GetDigestAlg()),
		}
		pcrs = append(pcrs, pcr)
	}

	if !bytes.Equal(akPub, respQuote.Public) {
		return false, errors.New("the ak used for quote is not verified")
	}

	pub, err := attest.ParseAKPublic(2, respQuote.Public)
	if err != nil {
		log.Fatalf("Failed to parse AK public: %v", err)
		return false, err
	}

	platformParam := attest.PlatformParameters{
		TPMVersion: 2,
		Public:     akPub,
		Quotes:     quotes,
		PCRs:       pcrs,
		EventLog:   respQuote.EventLog,
	}

	if err := pub.VerifyAll(platformParam.Quotes, platformParam.PCRs, nonce); err != nil {
		log.Fatalf("quote verification failed: %v", err)
		return false, err
	}

	//For now we store PCR hash values locally for verification
	//To-Do: Deploy a central node for verification
	// digestCollection := make([]byte, 0)
	// for i := 0; i < len(platformParam.PCRs); i++ {
	// 	for j := 0; j < len(platformParam.PCRs[i].Digest); j++ {
	// 		digestCollection = append(digestCollection, platformParam.PCRs[i].Digest[j])
	// 	}
	// }
	// localPCRValue, err := ioutil.ReadFile("test.txt")
	// if err != nil {
	// 	panic(err)
	// }
	// for i := 0; i < len(digestCollection); i++ {
	// 	if digestCollection[i] != localPCRValue[i] {
	// 		log.Printf("Index%v doesn't match", i)
	// 	}
	// }
	return true, nil
}
