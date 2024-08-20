package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Downloader tracks the region and Session and only recreates the Session
// if the region has changed
type Downloader struct {
	region string
	sess   *session.Session
}

func NewDownloader() *Downloader {
	d := &Downloader{}
	return d
}

// getValue parses a string and returns the value assigned to a key
func (d *Downloader) getValue(line string) string {
	splitLine := strings.Split(line, " = ")
	return (splitLine[len(splitLine)-1])
}

// credentialsFromFile loads AWS credentials from a non-standard path
func (d *Downloader) credentialsFromFile(fileName string) (string, string, string, error) {
	var accessKey, secretKey, token string

	file, err := os.Open(fileName)
	if err != nil {
		return "", "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		switch {
		case strings.Contains(scanner.Text(), "aws_access_key_id"):
			accessKey = d.getValue(scanner.Text())
		case strings.Contains(scanner.Text(), "aws_secret_access_key"):
			secretKey = d.getValue(scanner.Text())
		case strings.Contains(scanner.Text(), "aws_session_token"):
			token = d.getValue(scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	return accessKey, secretKey, token, nil
}

// loadCredentials sets up a Session using credentials found in /etc/apt/s3creds
// or using the default configuration supported by AWS if /etc/apt/s3creds does
// not exist
func (d *Downloader) loadCredentials(g *os.File, region string) (*session.Session, error) {
	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.loadCredentials, starting, region: %s\n", os.Getpid(), region))
	var config aws.Config
	var sess *session.Session

	if _, err := os.Stat("/etc/apt/s3creds"); err == nil {
		g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.loadCredentials, s3creds exists in etc/apt\n", os.Getpid()))
		accessKey, secretKey, token, err := d.credentialsFromFile("/etc/apt/s3creds")
		if err != nil {
			return nil, err
		}
		config = aws.Config{
			Region:      aws.String(region),
			Credentials: credentials.NewStaticCredentials(accessKey, secretKey, token),
		}
	} else if os.IsNotExist(err) {
		g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.loadCredentials, s3creds does not exist in etc/apt\n", os.Getpid()))
		b := true
		config = aws.Config{Region: aws.String(region), CredentialsChainVerboseErrors: &b}
	}
	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.loadCredentials, before new session, config: %+v\n", os.Getpid(), config))
	sess, err := session.NewSession(&config)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.loadCredentials, after new session, err: %s, sess: %+v\n", os.Getpid(), err, sess))

	return sess, err
}

// parseUri takes an S3 URI s3://<bucket>.s3-<region>.amazonaws.com/key/file
// and returns the bucket, region, key, and filename
func (d *Downloader) parseURI(keyString string) (string, string, string, string) {
	var region string
	ss := strings.Split(keyString, "/")
	bucketSs := strings.Split(ss[2], ".")
	bucket := bucketSs[0]
	regionSs := strings.Split(bucketSs[1], "-")
	// Default to us-east-1 if just <bucket>.s3.amazonaws.com is passed
	if len(regionSs) == 1 {
		region = "us-east-1"
	} else {
		region = strings.Join(regionSs[1:], "-")
	}
	key := strings.Join(ss[3:], "/")
	filename := ss[len(ss)-1]
	return bucket, region, key, filename
}

// GetFileAttributes queries the object in S3 and returns the timestamp and
// size in the format expected by apt
func (d *Downloader) GetFileAttributes(g *os.File, s3Uri string) (string, int64, error) {
	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.GetFileAttributes, starting...\n", os.Getpid()))
	var err error
	bucket, region, key, eee := d.parseURI(s3Uri)

	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.GetFileAttributes, parsed uri, bucket: %s, region: %s, key: %s, eee: %s\n", os.Getpid(), bucket, region, key, eee))

	if d.region != region {
		g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.GetFileAttributes, d region doesn't equal region, d.region: %s\n", os.Getpid(), d.region))
		d.region = region
		d.sess, err = d.loadCredentials(g, region)
		g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.GetFileAttributes, d region doesn't equal region, loadCredentials, err: %s\n", os.Getpid(), err))
		if err != nil {
			return "", -1, err
		}
	}

	svc := s3.New(d.sess)

	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.GetFileAttributes, about to get object...\n", os.Getpid()))

	result, err := svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	g.WriteString(fmt.Sprintf("apt-s3, %d, Downloader.GetFileAttributes, get obj err: %s\n", os.Getpid(), err))
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return "", -1, errors.New(strings.Join(strings.Split(aerr.Error(), "\n"), " "))
		}
	}

	return result.LastModified.Format("2006-01-02T15:04:05+00:00"), *result.ContentLength, nil
}

// DownloadFile pulls the file from an S3 bucket and writes it to the specified
// path
func (d *Downloader) DownloadFile(g *os.File, s3Uri string, path string) (string, error) {
	var err error
	bucket, region, key, filename := d.parseURI(s3Uri)
	if path != "" {
		filename = path
	}

	if d.region != region {
		d.region = region
		d.sess, err = d.loadCredentials(g, region)
		if err != nil {
			return "", err
		}
	}
	downloader := s3manager.NewDownloader(d.sess)

	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}

	if _, err := downloader.Download(f, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err != nil {
		os.Remove(filename)
		return "", err
	}
	return filename, nil
}

type Method struct {
	Downloader *Downloader
}

func NewMethod() *Method {
	m := &Method{
		Downloader: NewDownloader(),
	}
	return m
}

// calculateHash calculates and returns a single hash. Used by calculateHashes
func (m *Method) calculateHash(h hash.Hash, f []byte) (string, error) {
	if _, err := io.Copy(h, bytes.NewReader(f)); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// calculateHashes returns md5, sha1, sha256, and sha512 hashes of the downloaded file
func (m *Method) calculateHashes(filename string) (string, string, string, string, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", "", "", "", err
	}

	md5h, err := m.calculateHash(md5.New(), f)
	if err != nil {
		return "", "", "", "", err
	}
	sha1h, err := m.calculateHash(sha1.New(), f)
	if err != nil {
		return "", "", "", "", err
	}
	sha256h, err := m.calculateHash(sha256.New(), f)
	if err != nil {
		return "", "", "", "", err
	}
	sha512h, err := m.calculateHash(sha512.New(), f)
	if err != nil {
		return "", "", "", "", err
	}

	return md5h, sha1h, sha256h, sha512h, nil
}

// sendCapabilities tells apt what this method is capable of
func (m *Method) sendCapabilities() {
	fmt.Printf("100 Capabilities\nSend-Config: true\nPipeline: true\nSingle-Instance: yes\n\n")
}

// findLine finds the line that starts with key: and returns the value
func (m *Method) findLine(key string, lines []string) string {
	for i := 0; i < len(lines); i++ {
		linesSs := strings.Split(lines[i], ": ")
		if linesSs[0] == key {
			return linesSs[1]
		}
	}

	return ""
}

// UriStart downloads a file from S3 and tells apt about when the download
// starts and is finished
func (m *Method) UriStart(g *os.File, lines []string) error {
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, starting...\n", os.Getpid()))
	uri := m.findLine("URI", lines)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, found uri: %s\n", os.Getpid(), uri))
	path := m.findLine("Filename", lines)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, found path: %s\n", os.Getpid(), path))

	lastModified, size, err := m.Downloader.GetFileAttributes(g, uri)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, file attributes, last modified: %s, size: %d, err: %s\n", os.Getpid(), lastModified, size, err))
	if err != nil {
		m.handleError(g, uri, err)
	}

	fmt.Printf("200 URI Start\nLast-Modified: %s\nSize: %d\nURI: %s\n\n", lastModified, size, uri)

	filename, err := m.Downloader.DownloadFile(g, uri, path)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, download file, filename: %s, err: %s\n", os.Getpid(), filename, err))
	if err != nil {
		m.handleError(g, uri, err)
	}
	md5Hash, sha1Hash, sha256Hash, sha512Hash, err := m.calculateHashes(filename)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, calculate hashes, err: %s\n", os.Getpid(), err))
	if err != nil {
		return err
	}
	fmt.Printf("201 URI Done\nFilename: %s\nLast-Modified: %s\n", filename, lastModified)
	fmt.Printf("MD5-Hash: %s\nMD5Sum-Hash: %s\nSHA1-Hash: %s\n", md5Hash, md5Hash, sha1Hash)
	fmt.Printf("SHA256-Hash: %s\nSHA512-Hash: %s\n", sha256Hash, sha512Hash)
	fmt.Printf("Size: %d\nURI: %s\n\n", size, uri)
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.UriStart, end.\n", os.Getpid()))

	return nil
}

// handleError sends an error message to os.Stdout in a format which apt
// understands
func (m *Method) handleError(g *os.File, uri string, err error) {
	g.WriteString(fmt.Sprintf("apt-s3, %d, handleError, uri: %s, err: %s\n", os.Getpid(), uri, err))
	fmt.Printf("400 URI Failure\nMessage: %s\nURI: %s\n\n", strings.TrimRight(fmt.Sprintln(err), "\n"), uri)
	os.Exit(1)
}

// Start watches os.Stdin for a "600 URI Acquire" message from apt which
// triggers UriStart
func (m *Method) Start(g *os.File) {
	g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, starting...\n", os.Getpid()))
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	m.sendCapabilities()

	for scanner.Scan() {
		t := scanner.Text()
		g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, in scanner, got line: %s\n", os.Getpid(), t))
		if t != "" {
			g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, in scanner, line not empty, so just appending it\n", os.Getpid()))
			lines = append(lines, t)
		} else {
			g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, in scanner, line empty, len(lines) == %d\n", os.Getpid(), len(lines)))
			if len(lines) > 0 {
				g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, in scanner, line empty, len(lines) gt zero, first line: %s\n", os.Getpid(), lines[0]))
				if lines[0] == "600 URI Acquire" {
					g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, in scanner, line empty, len(lines) gt zero, first line is uri aquire message\n", os.Getpid()))
					if err := m.UriStart(g, lines); err != nil {
						g.WriteString(fmt.Sprintf("apt-s3, %d, Method.Start, in scanner, line empty, len(lines) gt zero, first line is uri aquire message, but got error handling it, err: %s\n", os.Getpid(), err))
						m.handleError(g, strings.Split(lines[1], ": ")[1], err)
					}
				}
				lines = make([]string, 0)
			}
		}
	}
}

var (
	downloadUri  = flag.String("download", "", "S3 URI for downloading a single file")
	downloadPath = flag.String("path", "", "Path to download file to")
	versionFlag  = flag.Bool("version", false, "Show version")
	Version      = "master"
)

func main() {
	g, err := os.OpenFile("/tmp/filefilefile", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()
	g.WriteString(fmt.Sprintf("apt-s3, %d, main(), starting...\n", os.Getpid()))

	m := NewMethod()
	programName := os.Args[0]


	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s %s (Go version: %s)\n", programName, Version, runtime.Version())
		os.Exit(0)
		// Called outside of apt to download a file
	} else if *downloadUri != "" {
		if match, _ := regexp.MatchString("s3://.*\\.s3.*\\.amazonaws\\.com/.*", *downloadUri); !match {
			log.Fatalf("Incorrect bucket format.\nExpected: s3://<bucket>.s3-<region>.amazonaws.com/path/to/file\n")
		} else {
			filename, err := m.Downloader.DownloadFile(g, *downloadUri, *downloadPath)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Downloaded %s\n", filename)
			os.Exit(0)
		}
	} else {
		m.Start(g)
	}

	g.WriteString(fmt.Sprintf("apt-s3, %d, main(), ended.\n", os.Getpid()))
}
