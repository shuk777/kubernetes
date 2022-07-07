package attestor

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"

	pb "git.basebit.me/xss/tpm/tpm_attest/attestation"
	"git.basebit.me/xss/tpm/tpm_attest/tpm"

	"github.com/google/go-attestation/attest"
)

var (
	// 	ek            attest.EK
	// 	ak            *attest.AK
	// 	tpm           *attest.TPM
	// 	attestParams  attest.AttestationParameters
	platform_cert = flag.String("platformcert", "platform.crt", "platform certificate")
	tpm_cert      = flag.String("tpmcert", "tpm.crt", "TPM(EK) certificate")

	// platform_cert = flag.String("platform_cert", "certs/platform_cert.der", "Platform Certificate File")
)

// const (
// 	tpm_device = "/dev/tpm0"
// 	port       = ":50051"
// )

type Server struct {
	pb.UnimplementedAttestationServer
}

// func init() {

// 	var err error

// 	// Open TPM and get EK,AK for attestation
// 	config := &attest.OpenConfig{}
// 	tpm, err = attest.OpenTPM(config)
// 	if err != nil {
// 		log.Fatalf("Cannot open TPM:%v", err)
// 	}

// 	eks, err := tpm.EKs()
// 	if err != nil {
// 		log.Fatalf("Cannot get EKs:%v", err)
// 	}
// 	ek = eks[0]

// 	akConfig := &attest.AKConfig{}
// 	ak, err = tpm.NewAK(akConfig)
// 	if err != nil {
// 		log.Fatalf("Cannot generate AK:%v", err)
// 	}
// }

func (s *Server) GetCerts(ctx context.Context, in *pb.GetCertsRequest) (*pb.GetCertsResponse, error) {
	log.Println("=== Getting platform and EK certs ===")
	log.Printf("Verifier side uid: %s", in.Uid)
	//Here I use pre-generated certificates as platform and EK certificates
	//To-Do: How to fetch certificates from real TPMs
	platformFile, err := ioutil.ReadFile(*platform_cert)
	if err != nil {
		log.Fatalf("Cannot read platform certificate file:%v", err)
		return &pb.GetCertsResponse{}, err
	}
	platformBlock, _ := pem.Decode(platformFile)
	platformCertificate, err := x509.ParseCertificate(platformBlock.Bytes)
	if err != nil {
		log.Fatalf("Unvalid certificate:%v", err)
		return &pb.GetCertsResponse{}, err
	}
	//Successfully read platform certificate
	log.Printf("Certificate info:%v", platformCertificate.Issuer)

	tpmFile, err := ioutil.ReadFile(*tpm_cert)
	if err != nil {
		log.Fatalf("Cannot read platform certificate file:%v", err)
		return &pb.GetCertsResponse{}, err
	}
	tpmBlock, _ := pem.Decode(tpmFile)
	if err != nil {
		log.Fatalf("Unvalid certificate:%v", err)
		return &pb.GetCertsResponse{}, err
	}

	//Note!!!:The EK certificate and EK public key does not match because I use openssl to generate fake
	//certificates, have to change to real EK certificate in the future.
	ekBytes, err := x509.MarshalPKIXPublicKey(tpm.EK().Public)
	if err != nil {
		log.Fatalf("Cannot generate EK bytes:%v", err)
		return &pb.GetCertsResponse{}, err
	}
	return &pb.GetCertsResponse{
		Uid:          in.Uid,
		PlatformCert: platformBlock.Bytes,
		EkCert:       tpmBlock.Bytes,
		EkPub:        ekBytes,
	}, nil
}

func (s *Server) GetAK(ctx context.Context, in *pb.GetAKRequest) (*pb.GetAKResponse, error) {
	log.Println("=== Getting AK ===")
	log.Printf("Verifier side uid: %s", in.Uid)
	attestParams := tpm.AK().AttestationParameters()
	ekBytes, err := x509.MarshalPKIXPublicKey(tpm.EK().Public)
	if err != nil {
		log.Fatalf("Cannot generate EK bytes:%v", err)
		return &pb.GetAKResponse{}, err
	}
	return &pb.GetAKResponse{
		Uid:   in.Uid,
		EkPub: ekBytes,
		Ak: &pb.AK{
			AkPub:             attestParams.Public,
			Tcsd:              attestParams.UseTCSDActivationFormat,
			CreateData:        attestParams.CreateData,
			CreateAttestation: attestParams.CreateAttestation,
			CreateSignature:   attestParams.CreateSignature,
		},
	}, nil
}

func (s *Server) Challenge(ctx context.Context, in *pb.ChallengeRequest) (*pb.ChallengeResponse, error) {
	log.Println("=== Receive challenge from verifier ===")
	log.Printf("Verifier side uid: %s", in.Uid)

	secret, err := tpm.AK().ActivateCredential(tpm.Device(), attest.EncryptedCredential{in.Credential, in.Secret})
	if err != nil {
		log.Fatalf("Cannot solve the challenge:%v", err)
		return &pb.ChallengeResponse{}, err
	}
	secretHash := sha256.Sum256(secret)
	return &pb.ChallengeResponse{
		Uid:    in.Uid,
		Secret: secretHash[:],
	}, nil

}

func (s *Server) GetQuote(ctx context.Context, in *pb.GetQuoteRequest) (*pb.GetQuoteResponse, error) {
	log.Println("=== Receive quote request from verifier ===")
	log.Printf("Verifier side uid: %s", in.Uid)
	nonce := in.GetNonce()
	att, err := tpm.Device().AttestPlatform(tpm.AK(), nonce, &attest.PlatformAttestConfig{
		EventLog: []byte{0},
	})
	if err != nil {
		log.Fatalf("Failed to attest the platform state: %v", err)
	}

	// Get pb.quote and pb.pcrs
	quoteLen := len(att.Quotes)
	quotes := make([]*pb.Quote, 0)
	for i := 0; i < quoteLen; i++ {
		quote := pb.Quote{
			TpmVersion: 2,
			Quote:      att.Quotes[i].Quote,
			Signature:  att.Quotes[i].Signature,
		}
		quotes = append(quotes, &quote)
	}

	pcrLen := len(att.PCRs)
	pcrs := make([]*pb.PCR, 0)
	for i := 0; i < pcrLen; i++ {
		pcr := pb.PCR{
			Index:     int32(att.PCRs[i].Index),
			Digest:    att.PCRs[i].Digest,
			DigestAlg: uint32(att.PCRs[i].DigestAlg),
		}
		pcrs = append(pcrs, &pcr)
	}

	return &pb.GetQuoteResponse{
		Uid:        in.GetUid(),
		TpmVersion: 2,
		Public:     att.Public,
		Quotes:     quotes,
		Pcrs:       pcrs,
		EventLog:   att.EventLog,
	}, nil

}

// func main() {
// 	lis, err := net.Listen("tcp", port)
// 	if err != nil {
// 		log.Fatalf("failed to listen: %v", err)
// 	}
// 	s := grpc.NewServer()
// 	pb.RegisterAttestationServer(s, &server{})
// 	log.Printf("gRPC server is listening at %v", lis.Addr())
// 	if err := s.Serve(lis); err != nil {
// 		log.Fatalf("Failed to server: %v", err)
// 	}

// }
