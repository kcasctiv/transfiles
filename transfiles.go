package transfiles

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/cheggaaa/pb.v1"

	"github.com/sigurn/crc8"

	"github.com/sirupsen/logrus"
)

const preamble = "FUU"

// Send sends file with fileName to the rw
//
// Format of first packet (for version 0x01):
// - preamble (FUU)
// - version (8bit)
// - length of packet (32bit)
// - length of file name (16bit)
// - length of file (64bit)
// - file name in utf-8
// - md5 of file
// - crc8
func Send(fileName string, rw io.ReadWriter) {
	file, err := os.Open(fileName)
	if err != nil {
		logrus.WithError(err).Error("could not open file")
		return
	}
	defer file.Close()
	name := filepath.Base(fileName)
	logrus.WithField("name", name).Info("file opened")

	hash, err := calcHash(file)
	if err != nil {
		logrus.WithError(err).Error("could not calc file hash")
		return
	}
	logrus.WithField("hash", hex.EncodeToString(hash)).Info("hash calculated")
	if _, err := file.Seek(0, 0); err != nil {
		logrus.WithError(err).Error("could not prepare file to transfer")
		return
	}

	stat, err := file.Stat()
	if err != nil {
		logrus.WithError(err).Error("could not get file stat")
	}

	// size of file name + size of file + file name + md5 + crc8
	hs := newHandshake(name, uint64(stat.Size()), hash)
	if _, err := rw.Write(hs); err != nil {
		logrus.WithError(err).Error("could not send handshake")
		return
	}
	logrus.Info("handshake sended")

	hsab := make([]byte, 15)
	if _, err := rw.Read(hsab); err != nil {
		logrus.WithError(err).Error("could not read handshake answer")
		return
	}
	var hsa handshakeAnswer
	hsa.HandshakeSize = binary.LittleEndian.Uint32(hsab)
	hsa.FileNameSize = binary.LittleEndian.Uint16(hsab[4:])
	hsa.FileSize = binary.LittleEndian.Uint64(hsab[6:])
	hsa.CRC = hsab[14]
	logrus.Info("handshake answer received")
	if hsa.HandshakeSize != hs.HandshakeSize() ||
		hsa.FileNameSize != hs.FileNameSize() ||
		hsa.FileSize != hs.FileSize() ||
		crc8.Checksum(hsab[:14], crc8.MakeTable(crc8.CRC8)) != hsa.CRC {
		logrus.Error("answer is not valid")
		return
	}

	bar := pb.New(int(stat.Size())).SetUnits(pb.U_BYTES)
	bar.Start()

	reader := bar.NewProxyReader(file)
	_, err = io.Copy(rw, reader)
	bar.Finish()
	if err != nil {
		logrus.WithError(err).Error("could not send file data")
		return
	}

	logrus.Info("file sended successfully")
}

// Receive receives file from rw
func Receive(rw io.ReadWriter) {
	b := make([]byte, 18)
	if _, err := rw.Read(b); err != nil {
		logrus.WithError(err).Error("could not read handshake")
		return
	}
	if string(b[:3]) != preamble {
		logrus.Error("preamble is not valid")
		return
	}
	if b[3] != 0x01 {
		logrus.Error("version is not supported")
		return
	}

	hsize := binary.LittleEndian.Uint32(b[4:])
	fnsize := binary.LittleEndian.Uint16(b[8:])
	fsize := binary.LittleEndian.Uint64(b[10:])

	if hsize-18-uint32(fnsize)-1 <= 0 {
		logrus.Error("handshake size is not valid")
		return
	}

	b1 := make([]byte, int(hsize-18))
	n, err := rw.Read(b1)
	if err != nil {
		logrus.WithError(err).Error("could not read handshake")
		return
	}
	if n != len(b1) {
		logrus.Error("could not read handshake")
		return
	}

	name := string(b1[:int(fnsize)])
	md5 := b1[int(fnsize) : len(b1)-1]
	crc := b1[len(b1)-1]

	b = append(b, b1...)
	if crc8.Checksum(b[:len(b)-1], crc8.MakeTable(crc8.CRC8)) != crc {
		logrus.Error("crc is not valid")
		return
	}

	hsa := make([]byte, 15)
	binary.LittleEndian.PutUint32(hsa, hsize)
	binary.LittleEndian.PutUint16(hsa[4:], fnsize)
	binary.LittleEndian.PutUint64(hsa[6:], fsize)
	hsa[14] = crc8.Checksum(hsa[:14], crc8.MakeTable(crc8.CRC8))
	logrus.Info("handshake answer sended")
	if _, err := rw.Write(hsa); err != nil {
		logrus.WithError(err).Error("could not send handshake answer")
		return
	}

	file, err := os.Create(name)
	if err != nil {
		logrus.WithError(err).Error("could not create file")
		return
	}
	defer file.Close()

	cp, err := io.Copy(file, rw)
	if err != nil {
		logrus.WithError(err).Error("could not receive file data")
		return
	}

	if uint64(cp) != fsize {
		logrus.Error("received file size is not valid")
		return
	}

	if _, err := file.Seek(0, 0); err != nil {
		logrus.WithError(err).Error("could not prepare file to calculate hash")
		return
	}

	hash, err := calcHash(file)
	if err != nil {
		logrus.WithError(err).Error("could not calculate hash")
		return
	}

	if !bytes.Equal(md5, hash) {
		logrus.Error("hash sum is not valid")
		return
	}

	logrus.WithField("name", name).Info("file received successfully")
}

type handshake []byte

func (h handshake) Preamble() string {
	return string(h[:3])
}

func (h handshake) Version() byte {
	return h[3]
}

func (h handshake) HandshakeSize() uint32 {
	return binary.LittleEndian.Uint32(h[4:])
}

func (h handshake) FileNameSize() uint16 {
	return binary.LittleEndian.Uint16(h[8:])
}

func (h handshake) FileSize() uint64 {
	return binary.LittleEndian.Uint64(h[10:])
}

func (h handshake) FileName() string {
	return string(h[18 : 18+h.FileNameSize()])
}

func (h handshake) MD5() []byte {
	return h[18+h.FileNameSize() : len(h)-1]
}

func (h handshake) CRC() byte {
	return h[len(h)-1]
}

func newHandshake(name string, size uint64, md5 []byte) handshake {
	b := make([]byte, 3+1+4+2+8+len(name)+len(md5)+1)

	copy(b, preamble)
	b[3] = 0x01
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[8:], uint16(len(name)))
	binary.LittleEndian.PutUint64(b[10:], size)
	copy(b[18:], name)
	copy(b[18+len(name):], md5)
	b[len(b)-1] = crc8.Checksum(b[:len(b)-1], crc8.MakeTable(crc8.CRC8))

	return b
}

type handshakeAnswer struct {
	HandshakeSize uint32
	FileNameSize  uint16
	FileSize      uint64
	CRC           uint8
}

func calcHash(file *os.File) ([]byte, error) {
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
