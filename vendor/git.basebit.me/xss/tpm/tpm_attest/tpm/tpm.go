package tpm

import (
	"log"

	"github.com/google/go-attestation/attest"
)

var (
	ek     attest.EK
	ak     *attest.AK
	device *attest.TPM
)

func InitTPM() {
	var err error

	// Open TPM and get EK,AK for attestation
	config := &attest.OpenConfig{}
	device, err = attest.OpenTPM(config)
	if err != nil {
		log.Fatalf("Cannot open TPM:%v", err)
	}

	eks, err := device.EKs()
	if err != nil {
		log.Fatalf("Cannot get EKs:%v", err)
	}
	ek = eks[0]

	akConfig := &attest.AKConfig{}
	ak, err = device.NewAK(akConfig)
	if err != nil {
		log.Fatalf("Cannot generate AK:%v", err)
	}
}

func CLoseTPM() {
	device.Close()
}
func Device() *attest.TPM {
	return device
}
func EK() attest.EK {
	return ek
}

func AK() *attest.AK {
	return ak
}
