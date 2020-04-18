/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package store

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	apiv1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"

	"github.com/google/uuid"
	"k8s.io/ingress-nginx/internal/file"
	"k8s.io/ingress-nginx/internal/ingress"
	"k8s.io/ingress-nginx/internal/net/ssl"
)

// syncSecret synchronizes the content of a TLS Secret (certificate(s), secret
// key) with the filesystem. The resulting files can be used by NGINX.
func (s *k8sStore) syncSecret(key string) {
	s.syncSecretMu.Lock()
	defer s.syncSecretMu.Unlock()

	klog.V(3).Infof("Syncing Secret %q", key)

	cert, err := s.getPemCertificate(key)
	if err != nil {
		if !isErrSecretForAuth(err) {
			klog.Warningf("Error obtaining X.509 certificate: %v", err)
		}
		return
	}

	// create certificates and add or update the item in the store
	cur, err := s.GetLocalSSLCert(key)
	if err == nil {
		if cur.Equal(cert) {
			// no need to update
			return
		}
		klog.Infof("Updating Secret %q in the local store", key)
		s.sslStore.Update(key, cert)
		// this update must trigger an update
		// (like an update event from a change in Ingress)
		s.sendDummyEvent()
		return
	}

	klog.Infof("Adding Secret %q to the local store", key)
	s.sslStore.Add(key, cert)
	// this update must trigger an update
	// (like an update event from a change in Ingress)
	s.sendDummyEvent()
}

// getVaultCertificate returns the cert, key and ca from Vault using the
// provided path and the Vault's data from environment variables.
func getVaultCertificate(secretPath string) ([]byte, []byte, []byte, error) {

	var cert, key, ca []byte

	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultPathDelimIndex := strings.LastIndex(secretPath, "/")
	vaultPath := secretPath[:vaultPathDelimIndex]
	vaultKey := secretPath[vaultPathDelimIndex+1:]
	vaultAddress := "https://" + os.Getenv("VAULT_HOSTS") + ":" + os.Getenv("VAULT_PORT") + "/v1" + vaultPath
	klog.Warningf("[DEBUG] backend_ssl getVaultCertificate - vaultAddress: %s", vaultAddress)

	// Prepare client
	req, err := http.NewRequest("GET", vaultAddress, nil)
	if err != nil {
		return cert, key, ca, fmt.Errorf("[ERROR] Error reading request: %v ", err)
	}

	req.Header.Set("X-Vault-Token", vaultToken)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return cert, key, ca, fmt.Errorf("[ERROR] Error reading response: %v ", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return cert, key, ca, fmt.Errorf("[ERROR] Error reading body: %v ", err)
	}

	type Response struct {
		Data interface{}
	}
	var certData Response

	if err := json.Unmarshal(body, &certData); err != nil {
		return cert, key, ca, fmt.Errorf("[ERROR] Error reading vault response: %v ", err)
	}

	if certData.Data == nil {
		klog.Warning("[DEBUG] Cannot get data from Vault")
		return cert, key, ca, nil
	}

	// As pointed out here: https://eagain.net/articles/go-dynamic-json, I will regret this
	rawCert := certData.Data.(map[string]interface{})[vaultKey+"_crt"]
	if rawCert == nil {
		klog.Warning("[ERROR] backend_ssl getVaultCertificate - rawCert is nil")
		return cert, key, ca, nil
	}
	var reCert = regexp.MustCompile(`-----END CERTIFICATE-----.*`)
	formattedCert := strings.Replace(reCert.ReplaceAllString(rawCert.(string), "$1\n-----END CERTIFICATE-----$2"), "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n", -1)
	cert = []byte(formattedCert)

	rawKey := certData.Data.(map[string]interface{})[vaultKey+"_key"]
	if rawKey == nil {
		klog.Warning("[ERROR] backend_ssl getVaultCertificate - rawKey is nil")
		return cert, key, ca, nil
	}

	formattedKey := strings.Replace(strings.Replace(rawKey.(string), "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n", -1), "-----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----\n", -1)
	key = []byte(formattedKey)

	var reCA = regexp.MustCompile(`^(.*?)-----END CERTIFICATE-----(.*)$`)
	subFormattedCA := reCA.ReplaceAllString(rawCert.(string), "${1}-----END CERTIFICATE-----\n$2")
	reCA = regexp.MustCompile(`.*\n`)
	formattedCA := reCA.ReplaceAllString(subFormattedCA, "$1$2")
	ca = []byte(strings.Replace(strings.Replace(formattedCA, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n", -1), "-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----\n", -1))

	return cert, key, ca, nil
}

// getPemCertificate receives a secret, and creates a ingress.SSLCert as return.
// It parses the secret and verifies if it's a keypair, or a 'ca.crt' secret only.
func (s *k8sStore) getPemCertificate(secretName string) (*ingress.SSLCert, error) {
	var cert, key, ca, crl, auth []byte
	var okcert, okkey bool
	var uid, sslCertName, sslCertNamespace string

	// secret.UID

	secret, err := s.listers.Secret.ByKey(secretName)

	// If secret doesnt exist, we check if it is a vault path
	if err != nil {
		klog.Warningf("[DEBUG] Trying secretName as a Vault Path")
		okcert = true
		okkey = true

		crl = []byte("")
		auth = []byte("")
		uid = uuid.New().String()

		// sslCertName = secretName[:strings.IndexByte(secretName, '/')]
		sslCertName = secretName[strings.IndexByte(secretName, '/'):]
		sslCertNamespace = secretName[:strings.IndexByte(secretName, '/')]

		cert, key, ca, err = getVaultCertificate(sslCertName)

		if err != nil {
			return nil, fmt.Errorf("Missing certificates in Vault's Path %s", sslCertName)
		}

	} else {
		cert, okcert = secret.Data[apiv1.TLSCertKey]
		key, okkey = secret.Data[apiv1.TLSPrivateKeyKey]
		ca = secret.Data["ca.crt"]

		crl = secret.Data["ca.crl"]
		auth = secret.Data["auth"]

		uid = string(secret.UID)

		sslCertName = secret.Name
		sslCertNamespace = secret.Namespace

	}

	// namespace/secretName -> namespace-secretName
	nsSecName := strings.Replace(secretName, "/", "-", -1)

	var sslCert *ingress.SSLCert
	if okcert && okkey {
		if cert == nil {
			return nil, fmt.Errorf("key 'tls.crt' missing from Secret %q", secretName)
		}

		if key == nil {
			return nil, fmt.Errorf("key 'tls.key' missing from Secret %q", secretName)
		}

		// sslCert, err = ssl.CreateSSLCert(cert, key, string(secret.UID))
		sslCert, err = ssl.CreateSSLCert(cert, key, uid)
		if err != nil {
			return nil, fmt.Errorf("unexpected error creating SSL Cert: %v", err)
		}

		if len(ca) > 0 {
			caCert, err := ssl.CheckCACert(ca)
			if err != nil {
				return nil, fmt.Errorf("parsing CA certificate: %v", err)
			}

			path, err := ssl.StoreSSLCertOnDisk(nsSecName, sslCert)
			if err != nil {
				return nil, fmt.Errorf("error while storing certificate and key: %v", err)
			}

			sslCert.PemFileName = path
			sslCert.CACertificate = caCert
			sslCert.CAFileName = path
			sslCert.CASHA = file.SHA1(path)

			err = ssl.ConfigureCACertWithCertAndKey(nsSecName, ca, sslCert)
			if err != nil {
				return nil, fmt.Errorf("error configuring CA certificate: %v", err)
			}

			if len(crl) > 0 {
				err = ssl.ConfigureCRL(nsSecName, crl, sslCert)
				if err != nil {
					return nil, fmt.Errorf("error configuring CRL certificate: %v", err)
				}
			}
		}

		msg := fmt.Sprintf("Configuring Secret %q for TLS encryption (CN: %v)", secretName, sslCert.CN)
		if ca != nil {
			msg += " and authentication"
		}

		if crl != nil {
			msg += " and CRL"
		}

		klog.V(3).Info(msg)
	} else if len(ca) > 0 {
		sslCert, err = ssl.CreateCACert(ca)
		if err != nil {
			return nil, fmt.Errorf("unexpected error creating SSL Cert: %v", err)
		}

		err = ssl.ConfigureCACert(nsSecName, ca, sslCert)
		if err != nil {
			return nil, fmt.Errorf("error configuring CA certificate: %v", err)
		}

		if len(crl) > 0 {
			err = ssl.ConfigureCRL(nsSecName, crl, sslCert)
			if err != nil {
				return nil, err
			}
		}
		// makes this secret in 'syncSecret' to be used for Certificate Authentication
		// this does not enable Certificate Authentication
		klog.V(3).Infof("Configuring Secret %q for TLS authentication", secretName)
	} else {
		if auth != nil {
			return nil, ErrSecretForAuth
		}

		return nil, fmt.Errorf("secret %q contains no keypair or CA certificate", secretName)
	}

	// sslCert.Name = secret.Name
	sslCert.Name = sslCertName
	// sslCert.Namespace = secret.Namespace
	sslCert.Namespace = sslCertNamespace

	// the default SSL certificate needs to be present on disk
	if secretName == s.defaultSSLCertificate {
		path, err := ssl.StoreSSLCertOnDisk(nsSecName, sslCert)
		if err != nil {
			return nil, errors.Wrap(err, "storing default SSL Certificate")
		}

		sslCert.PemFileName = path
	}

	return sslCert, nil
}

// sendDummyEvent sends a dummy event to trigger an update
// This is used in when a secret change
func (s *k8sStore) sendDummyEvent() {
	s.updateCh.In() <- Event{
		Type: UpdateEvent,
		Obj: &networking.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy",
				Namespace: "dummy",
			},
		},
	}
}

// ErrSecretForAuth error to indicate a secret is used for authentication
var ErrSecretForAuth = fmt.Errorf("secret is used for authentication")

func isErrSecretForAuth(e error) bool {
	return e == ErrSecretForAuth
}
