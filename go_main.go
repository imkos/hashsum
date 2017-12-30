//go_main
package main

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"os"
	"time"
	//
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

const (
	MAJOR_VER = "1.0.1"
)

var (
	Built_dtime string
	//
	s_hashfile *string
	s_hashstr  *string
	b_md5      *bool
	b_sha1     *bool
	b_sha256   *bool
	b_sha512   *bool
	b_crc32    *bool
	b_crc64    *bool
)

type hashsum struct {
	h_name string
	h_hash hash.Hash
	b_r    []byte
}

func (h hashsum) String() string {
	return h.h_name + ":\t" + hex.EncodeToString(h.b_r)
}

//判断文件或文件夹是否存在
func Exist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil || os.IsExist(err)
}

func hashsumfile(s_file string, hss []*hashsum) error {
	if len(hss) == 0 {
		return errors.New("hss is nil")
	}
	b_file, e1 := os.Open(s_file)
	if e1 != nil {
		return e1
	}
	defer b_file.Close()
	br := bufio.NewReader(b_file)
	buf_line := make([]byte, 1024)
	for {
		n, err := br.Read(buf_line)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		for _, hs := range hss {
			hs.h_hash.Write(buf_line[:n])
		}
	}
	for _, hs := range hss {
		hs.b_r = hs.h_hash.Sum(nil)
	}
	return nil
}

func hashsumstr(b_str []byte, hss []*hashsum) error {
	if len(hss) == 0 {
		return errors.New("hss is nil")
	}
	for _, hs := range hss {
		hs.h_hash.Write(b_str)
		hs.b_r = hs.h_hash.Sum(nil)
	}
	return nil
}

func init() {
	flag.Usage = func() {
		var s_build_datetime string
		if Built_dtime != "" {
			//(built: 2017/04/18 16:04:40)
			s_build_datetime = "(built: " + Built_dtime + ")"
		}
		fmt.Fprintf(os.Stderr, "Usage of %s, Version: %s %s\n", os.Args[0], MAJOR_VER, s_build_datetime)
		fmt.Println("hash sum file/string by K.o.s[vbz276@gmail.com]!")
		flag.PrintDefaults()
	}
	//other *var
	s_hashfile = flag.String("f", "", "to Hash file")
	s_hashstr = flag.String("s", "", "to Hash string")
	//
	b_md5 = flag.Bool("md5", false, "use MD5 hash")
	b_sha1 = flag.Bool("sha1", false, "use SHA1 hash")
	b_sha256 = flag.Bool("sha256", false, "use SHA256 hash")
	b_sha512 = flag.Bool("sha512", false, "use SHA512 hash")
	b_crc32 = flag.Bool("crc32", false, "use CRC32 hash")
	b_crc64 = flag.Bool("crc64", false, "use CRC64 hash")
}

func main() {
	flag.Parse()
	hss := make([]*hashsum, 0)
	if *b_md5 {
		hss = append(hss, &hashsum{h_name: "MD5", h_hash: crypto.MD5.New()})
	}
	if *b_sha1 {
		hss = append(hss, &hashsum{h_name: "SHA1", h_hash: crypto.SHA1.New()})
	}
	if *b_sha256 {
		hss = append(hss, &hashsum{h_name: "SHA256", h_hash: crypto.SHA256.New()})
	}
	if *b_sha512 {
		hss = append(hss, &hashsum{h_name: "SHA512", h_hash: crypto.SHA512.New()})
	}
	if *b_crc32 {
		hss = append(hss, &hashsum{h_name: "CRC32", h_hash: crc32.New(crc32.IEEETable)})
	}
	if *b_crc64 {
		hss = append(hss, &hashsum{h_name: "CRC64", h_hash: crc64.New(crc64.MakeTable(crc64.ISO))})
	}
	//file
	if *s_hashfile != "" && Exist(*s_hashfile) {
		t1 := time.Now().UnixNano()
		if err := hashsumfile(*s_hashfile, hss); err != nil {
			fmt.Printf("hashsumfile error: %+v\n", err)
			return
		}
		t2 := time.Now().UnixNano()
		for _, hs := range hss {
			fmt.Println(hs)
		}
		fmt.Printf("total elapsed time: %d ms.\n", (t2-t1)/1000000)
		return
	}
	//string
	if err := hashsumstr([]byte(*s_hashstr), hss); err != nil {
		fmt.Printf("hashsumstr error: %+v\n", err)
		return
	}
	for _, hs := range hss {
		fmt.Println(hs)
	}
}
