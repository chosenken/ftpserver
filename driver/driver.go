package driver

import (
	"crypto/rand"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	"bytes"

	"fmt"

	"sync/atomic"

	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"path/filepath"

	"os"

	"github.com/Sirupsen/logrus"
	"github.com/chosenken/ftpserver/db"
	"github.com/chosenken/ftpserver/server"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

type MainDriver struct {
	BaseDir    string
	logger     *logrus.Entry
	tlsConfig  *tls.Config
	nbClients  int32
	settings   *server.Settings
	maxClients int32
	db         *db.Client
}

type ClientDriver struct {
	BaseDir string
	Logger  *logrus.Entry
}

func NewDriver(logger *logrus.Logger, db *db.Client) *MainDriver {
	return &MainDriver{
		logger: logger.WithField("package", "driver"),
		db:     db,
	}
}

func (driver *MainDriver) GetSettings() (*server.Settings, error) {

	eIP, _ := externalIP()

	viper.SetDefault("listen_host", "0.0.0.0")
	viper.SetDefault("listen_port", "22")
	viper.SetDefault("public_host", eIP)
	viper.SetDefault("idle_timeout", 900)
	viper.SetDefault("data_port_range_start", 2200)
	viper.SetDefault("data_port_range_end", 2299)
	viper.SetDefault("max_clients", 20)
	viper.SetDefault("base_dir", "/mnt/ftp")

	driver.settings = &server.Settings{
		DataPortRange: &server.PortRange{
			Start: viper.GetInt("data_port_range_start"),
			End:   viper.GetInt("data_port_range_end"),
		},
		IdleTimeout: viper.GetInt("idle_timeout"),
		ListenAddr:  fmt.Sprintf("%s:%s", viper.GetString("listen_host"), viper.GetString("listen_port")),
		PublicHost:  viper.GetString("public_host"),
		DisableMLSD: false,
		DisableMLST: false,
	}
	driver.maxClients = int32(viper.GetInt("max_clients"))
	driver.BaseDir = viper.GetString("base_dir")

	return driver.settings, nil
}

// GetTLSConfig returns a TLS Certificate to use
func (driver *MainDriver) GetTLSConfig() (*tls.Config, error) {
	driver.logger.Debug("Getting TLS")

	if driver.tlsConfig == nil {
		if cert, err := driver.getCertificate(); err == nil {
			driver.tlsConfig = &tls.Config{
				NextProtos:   []string{"ftp"},
				Certificates: []tls.Certificate{*cert},
			}
		} else {
			return nil, err
		}
	}
	return driver.tlsConfig, nil
}

func (driver *MainDriver) getCertificate() (*tls.Certificate, error) {
	logger := driver.logger.WithField("function", "GetTLSConfig")
	logger.Info("Creating certificate")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		logger.WithField("error", err).Error("Could not generate key")
		return nil, err
	}

	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"FTPServer"},
		},
		DNSNames:              []string{"localhost"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour * 24 * 7),
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	if err != nil {
		logger.WithField("error", err).Error("Could not create cert")
		return nil, err
	}

	var certPem, keyPem bytes.Buffer
	if err := pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}
	if err := pem.Encode(&keyPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	return &c, err
}

func (driver *MainDriver) WelcomeUser(cc server.ClientContext) (string, error) {
	//cc.SetDebug(true)
	nbClients := atomic.AddInt32(&driver.nbClients, 1)
	if nbClients > driver.maxClients {
		return "Cannot accept any additional client", fmt.Errorf("too many clients: %d > % d", driver.nbClients, driver.maxClients)
	}

	return fmt.Sprintf(
			"Welcome to NavistoneFTPs, your ID is %d, your IP:port is %s, we currently have %d clients connected",
			cc.ID(),
			cc.RemoteAddr(),
			nbClients),
		nil
}

func (driver *MainDriver) AuthUser(cc server.ClientContext, userName, pass string) (server.ClientHandlingDriver, error) {
	logger := driver.logger.WithFields(logrus.Fields{"function": "AuthUser", "UserName": userName})
	logger.Info("Authenticating user")
	user, err := driver.db.GetUser(userName)
	if err != nil {
		logger.WithField("error", err).Error("Error getting user")
	}
	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(pass)); err != nil {
		return nil, fmt.Errorf("could not authenticate you")
	}
	baseDir := filepath.Join(driver.BaseDir, user.Dir)
	os.MkdirAll(baseDir, 0766)
	return &ClientDriver{BaseDir: baseDir, Logger: driver.logger}, nil
}

// UserLeft is called when the user disconnects, even if he never authenticated
func (driver *MainDriver) UserLeft(cc server.ClientContext) {
	atomic.AddInt32(&driver.nbClients, -1)
}

// ChangeDirectory changes the current working directory
func (driver *ClientDriver) ChangeDirectory(cc server.ClientContext, directory string) error {
	driver.Logger.WithField("directory", directory).Debug("Changing Directory")
	_, err := os.Stat(driver.BaseDir + directory)
	return err
}

// MakeDirectory creates a directory
func (driver *ClientDriver) MakeDirectory(cc server.ClientContext, directory string) error {
	return os.Mkdir(driver.BaseDir+directory, 0777)
}

// ListFiles lists the files of a directory
func (driver *ClientDriver) ListFiles(cc server.ClientContext) ([]os.FileInfo, error) {
	path := driver.BaseDir + cc.Path()
	driver.Logger.WithField("path", path).Debug("List Files")
	files, err := ioutil.ReadDir(path)
	if err != nil {
		driver.Logger.Error(err)
	}
	return files, err
}

// OpenFile opens a file in 3 possible modes: read, write, appending write (use appropriate flags)
func (driver *ClientDriver) OpenFile(cc server.ClientContext, path string, flag int) (server.FileStream, error) {

	path = driver.BaseDir + path
	driver.Logger.WithField("path", path).Debug("Open File")
	// If we are writing and we are not in append mode, we should remove the file
	if (flag & os.O_WRONLY) != 0 {
		flag |= os.O_CREATE
		if (flag & os.O_APPEND) == 0 {
			os.Remove(path)
		}
	}

	return os.OpenFile(path, flag, 0666)
}

// GetFileInfo gets some info around a file or a directory
func (driver *ClientDriver) GetFileInfo(cc server.ClientContext, path string) (os.FileInfo, error) {
	path = driver.BaseDir + path
	driver.Logger.WithField("path", path).Debug("Get File Info")
	return os.Stat(path)
}

// CanAllocate gives the approval to allocate some data
func (driver *ClientDriver) CanAllocate(cc server.ClientContext, size int) (bool, error) {
	// The root dir SHOULD be in an s3fs, so we should have inf storage space
	return true, nil
}

// ChmodFile changes the attributes of the file
func (driver *ClientDriver) ChmodFile(cc server.ClientContext, path string, mode os.FileMode) error {
	path = driver.BaseDir + path

	return os.Chmod(path, mode)
}

// DeleteFile deletes a file or a directory
func (driver *ClientDriver) DeleteFile(cc server.ClientContext, path string) error {
	path = driver.BaseDir + path

	return os.Remove(path)
}

// RenameFile renames a file or a directory
func (driver *ClientDriver) RenameFile(cc server.ClientContext, from, to string) error {
	from = driver.BaseDir + from
	to = driver.BaseDir + to

	return os.Rename(from, to)
}

func externalIP() (string, error) {
	// If you need to take a bet, amazon is about as reliable & sustainable a service as you can get
	rsp, err := http.Get("http://checkip.amazonaws.com")
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()

	buf, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return "", err
	}

	return string(bytes.TrimSpace(buf)), nil
}
