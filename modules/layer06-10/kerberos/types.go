package kerberos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"
)

type TicketEncoding int

const (
	EncodingDER    TicketEncoding = iota
	EncodingASN1
	EncodingRaw
)

type EncryptionType int

const (
	EncRC4HMAC   EncryptionType = 23
	EncAES128    EncryptionType = 17
	EncAES256    EncryptionType = 18
	EncDES_CRC   EncryptionType = 1
	EncDES_MD4   EncryptionType = 3
	EncDES_MD5   EncryptionType = 4
)

type MessageType int

const (
	MSGASREQ     MessageType = 10
	MSGASREP     MessageType = 11
	MSGTGSREQ    MessageType = 12
	MSGTGSREP    MessageType = 13
	MSGAPREQ     MessageType = 14
	MSGAPREP     MessageType = 15
)

type KerberosConfig struct {
	Domain       string
	DomainController string
	KDCPort      int
	KerberosPort int
	Realm        string
	Timeout      time.Duration
	EncType      EncryptionType
	RoastFormat  string
}

func DefaultKerberosConfig() *KerberosConfig {
	return &KerberosConfig{
		Domain:       "CORP.LOCAL",
		DomainController: "dc01.corp.local",
		KDCPort:      88,
		KerberosPort: 88,
		Realm:        "CORP.LOCAL",
		Timeout:      30 * time.Second,
		EncType:      EncRC4HMAC,
		RoastFormat:  "hashcat",
	}
}

type Ticket struct {
	MsgType       MessageType
	TicketVNO     int
	Realm         string
	SName         []string
	EncPart       *EncryptedPart
	DecPart       *TicketDecPart
	RawTicket     []byte
	SessionKey    []byte
	RawEncPart    []byte
	Flags         TicketFlags
	AuthTime      time.Time
	StartTime     time.Time
	EndTime       time.Time
	RenewTill     time.Time
	CName         []string
	CAData        []byte
}

type EncryptedPart struct {
	EType  EncryptionType
	KVNO   int
	Cipher []byte
}

type TicketDecPart struct {
	Flags        TicketFlags
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	SName        []string
	Realm        string
	CName        []string
	Transited    *TransitedEncoding
	EncEText     []byte
	EncEType2    EncryptionType
	HostAddresses []HostAddress
	PACData      *PACData
}

type TicketFlags uint32

const (
	TicketFlagInitial     TicketFlags = 0x40000000
	TicketFlagInvalid     TicketFlags = 0x20000000
	TicketFlagMayPostDate TicketFlags = 0x10000000
	TicketFlagPostDated   TicketFlags = 0x08000000
	TicketFlagRenewable   TicketFlags = 0x04000000
	TicketFlagForwardable TicketFlags = 0x02000000
	TicketFlagForwarded   TicketFlags = 0x01000000
	TicketFlagProxiable   TicketFlags = 0x00800000
	TicketFlagProxy       TicketFlags = 0x00400000
	TicketFlagOptHardware TicketFlags = 0x00200000
	TicketFlagHWAUTH      TicketFlags = 0x00100000
	TicketFlagPreAuth     TicketFlags = 0x00080000
	TicketFlagMandatoryPost TicketFlags = 0x00040000
)

type TransitedEncoding struct {
	EncType EncryptionType
	Contents []byte
}

type HostAddress struct {
	AddrType int
	Contents []byte
}

type PACData struct {
	InfoBuffer        []PACInfoBuffer
	SignatureKDC      []byte
	SignatureServer    []byte
	SignatureKDCR     []byte
	SignatureServerR  []byte
	PacType           int
}

type PACInfoBuffer struct {
	Type   int
	Length int
	Offset int
	Data   []byte
}

type KerberoastResult struct {
	Username   string
	SPN        string
	TicketData []byte
	Hash       string
	EncType    EncryptionType
	Timestamp  time.Time
	WordCount  int
}

type ASREPResult struct {
	Username    string
	TicketData  []byte
	Hash        string
	EncType     EncryptionType
	Timestamp   time.Time
	NTLMHash   string
	Certificate string
}

type CertResult struct {
	Success    bool
	CertPEM    []byte
	KeyPEM     []byte
	CACert     []byte
	Template   string
	CA         string
	Serial     string
	Error      string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	DNSNames   []string
	UPN        string
}

type DomainInfo struct {
	Name          string
	DNSName       string
	DomainSID     string
	DCIP          string
	DCName        string
	Forest        string
	FunctionalLevel string
	OSVersion     string
	Timestamp     time.Time
}

type UserInfo struct {
	Username    string
	DN          string
	SID         string
	Enabled     bool
	AdminCount  bool
	LastLogon   time.Time
	PasswordSet time.Time
	MemberOf    []string
	SPNs        []string
	UACFlags    int
	DisplayName string
	Email       string
	Description string
}

type GroupInfo struct {
	Name     string
	DN       string
	SID      string
	Members  []string
	Type     int
	WellKnown bool
}

type SPNInfo struct {
	ServiceAccount string
	SPN            string
	DN             string
	AdminCount     bool
	Enabled        bool
	LastLogon      time.Time
	PasswordAge    time.Duration
}

type GPOInfo struct {
	Name       string
	GUID       string
	DN         string
	Path       string
	Version    int
	FileSysPath string
	Timestamp  time.Time
}

type DCSyncResult struct {
	Success      bool
	DomainName   string
	DomainSID    string
	NTLMHash     string
	AES256Key    string
	AES128Key    string
	KRBTGT       string
	MachineAcct  string
	DCNames      []string
	Timestamp    time.Time
	Error        string
}

func ComputeMD5(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

func ComputeRC4HMAC(key, data []byte) ([]byte, error) {
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

func ComputeHMACSHA1(key, data []byte) []byte {
	h := sha1.New()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}

func EncodeTicketFlags(flags TicketFlags) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(flags))
	return buf
}

func DecodeTicketFlags(data []byte) TicketFlags {
	if len(data) < 4 {
		return 0
	}
	return TicketFlags(binary.LittleEndian.Uint32(data))
}

func (t *Ticket) ToASN1() ([]byte, error) {
	return t.RawTicket, nil
}

func (t *Ticket) Validate() error {
	if t.TicketVNO != 5 {
		return fmt.Errorf("invalid ticket version: %d", t.TicketVNO)
	}
	if len(t.Realm) == 0 {
		return fmt.Errorf("empty realm")
	}
	if len(t.SName) == 0 {
		return fmt.Errorf("empty sname")
	}
	if t.EncPart == nil {
		return fmt.Errorf("nil encrypted part")
	}
	return nil
}

func (t *TicketFlags) HasFlag(flag TicketFlags) bool {
	return *t&flag != 0
}

func (t *TicketFlags) SetFlag(flag TicketFlags) {
	*t |= flag
}

func (t *TicketFlags) ClearFlag(flag TicketFlags) {
	*t &^= flag
}
