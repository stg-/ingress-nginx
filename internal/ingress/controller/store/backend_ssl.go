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

	klog.Warning("[STG] backend_ssl syncSecret ")

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

	klog.Warningf("[STG] backend_ssl getVaultCertificate - secretPath: %s", secretPath)

	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultPathDelimIndex := strings.LastIndex(secretPath, "/")
	klog.Warningf("[STG] backend_ssl getVaultCertificate - vaultPathDelimIndex: %s", vaultPathDelimIndex)
	vaultPath := secretPath[:vaultPathDelimIndex]
	vaultKey := secretPath[vaultPathDelimIndex+1:]
	vaultAddress := "https://" + os.Getenv("VAULT_HOSTS") + ":" + os.Getenv("VAULT_PORT") + "/v1/" + vaultPath
	klog.Warningf("[STG] backend_ssl getVaultCertificate - vaultAddress: %s", vaultAddress)

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

	// body := []byte(`{
	// 	"request_id": "7e6068a8-12ab-c8c2-f873-a915a269d285",
	// 	"lease_id": "",
	// 	"renewable": false,
	// 	"lease_duration": 2764800,
	// 	"data": {
	// 	  "cicdcd-dev-jenkins_crt": "-----BEGIN CERTIFICATE-----MIIEzjCCAragAwIBAgIUczaS5UC+lW7p1AgPOkw9k+MBH48wDQYJKoZIhvcNAQELBQAwNjELMAkGA1UEBhMCRVMxEDAOBgNVBAoMB1N0cmF0aW8xFTATBgNVBAMMDExhYnMgdGVhbSBDQTAeFw0yMDAyMDYxMDI1MjBaFw0yMTAyMDUxMDI1NDlaMB0xGzAZBgNVBAMTEmNpY2RjZC1kZXYtamVua2luczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANX+B1OhY39pStsbf/uNMH8d2H1mcOvq5WisEws60Ab31IYp1uOEPl1x4DgE+PMnxx6KYqhO+DN3kxMnT19e/iJ4gHEHDrOwonYHcIyP4YNBHegkB9L7N+UzIMN1E1S9DUIEVihLVl8qMLI4nOniB1vXsxlvCnhR0Lf3fFct8hEJa6Dqsai/cfaLmiqKAG9hVMMLJjq+MJi49QexeqnDg27aHHFnGIuxMbZo07fx11X253tA4NSsj9mMsjTdQhyN2ZI1dryTmV59G3QOQpcln7i3+gJHzbyvACIbEQZ9IZjpIMIxr5E67W9LA8I3moe3SXmAWK9q3WbvV74MydMy2h0CAwEAAaOB7DCB6TAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRiBErRyIXPW505XtISa43i/lNDgTAfBgNVHSMEGDAWgBQJKT+GZuaidBa59eIk7bYUgq11UjB4BgNVHREEcTBvghJjaWNkY2QtZGV2LWplbmtpbnOCLGNpY2RjZC1kZXYtamVua2lucy5jaWNkY2QtZGV2Lm1hcmF0aG9uLm1lc29zgitqZW5raW5zLmNpY2RjZC1kZXYuZ29sZi5oZXR6bmVyLnN0cmF0aW8uY29tMA0GCSqGSIb3DQEBCwUAA4ICAQB4AbsMq1f5SBgzuzIHB2YN8LSCxKvwLj/38XUGLzJAJaT4DFIVSNvO4vYG6V2LCwDAZPjayekdZYlUlMyEVhfR6cmElw56fFmLv/xFfFmuV0UPKG5GykY9xUs5iYNfqUWC9mifSuB927VaI/TIfuKdeB3oieVBFdJXXg0SDCGhpT/+IsVFFVAStdov5zw37XSB+psuoyMFEow+DZd17xgx7KRVmZsFMiVOAdkaTTQ9O4F3HhFZ6MjGh6kHn30LZqtf5s1F2nWcpWrlZvhk8POVFxV0qBSQKwvr0Ze6uPgGyCQlGInDeMoKFCAkBCSBFTYyAHWeUMzU+1qH4ddq4gob1XFL5xYhPx3UQuWK3B5JQq3CnXU+owgQ73/4h/3e5p8AUWUXBCy/QznvloUihQCzmLZp1DFog2yZuQmVXLmYklqMsrcYKH1nXPLvlprEr04B0JKSVzSCFckMMkSRaSM2xZKIsH/T7SSKcDsGIfiT15TjwyN8I3vLKtA7fyiB8oG0FEGrAF17WkpZqpxiuxbAN0zUwb061OBHU2L+dQcFIE1dyzzxaZfHA3Wfhw/YiSbKQhdEgUJt7CjUFROK/zWrrvvTDHhSrmRtfW11B1HskzCZvygRO5P4cnGKBdNBIcA9WdSaUA4np9LXgxILbU+lzkqhucS0TBX6GLnTi0hNYg==-----END CERTIFICATE----------BEGIN CERTIFICATE-----MIIFOjCCAyKgAwIBAgIQdWSbQJ/CYk1/BERap1nTPTANBgkqhkiG9w0BAQsFADA4MQswCQYDVQQGEwJFUzEQMA4GA1UECgwHU3RyYXRpbzEXMBUGA1UEAwwOU3RyYXRpbyBJbmMgQ0EwHhcNMTYxMDIxMTUxNjEyWhcNMjYxMDE5MTUxNjEyWjA2MQswCQYDVQQGEwJFUzEQMA4GA1UECgwHU3RyYXRpbzEVMBMGA1UEAwwMTGFicyB0ZWFtIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtMw5w9bxjXur+T3A/sFEcDCKxvKWU1Um86puh36D3Zc55/aTpNzq8UqyEtTUbr9xuqpkriQWPZcS3CZEDW0wnEXmZ6/ukQ059T9wv6P+YGEXMqaVHn3qPGwiZ8WbClVrGfDwTl+9sfqvfR6keJq8rJkxE21ECW94ikI7Tk19s0Rz62xf+/FFRndQbTsech9Opi4TC2zMd9h9rPyRwfSmVHMKPmqm+nnAoDjBlUalxjt+n7Vs269ZBqfusn25Em+BIMwU4z13csHIuZuB/mvmqipxc2VHHrvhlCeoSgqWnNvmok4D8Ug+9sASAKYn1stdkSxCqwLLWb9PR/fUcqorvz1S8KNc07c7IIt2ip5sXGWSJKIazak4CHiJGEQ11jO4NOFsXp+tDaQgT/21Aq45zHJyf9ymT8c0ztwe9oQI1UYXHyopfyW1o9Ca5/MxQeXWcCPEFE1IMoA/e6vDWF09liDOZl94lSwZ2ev+zGGDN+WU4ZojCbjdLCv/tbuSdyiTd4jV6dCShObyWMc6l+TAfHvHFkxD29MDC165evoSXWMZtqriyt2h/9kWmqgblpz0oJ4kFPQ9RY5n34FHMSvabkSTWkjcV8m6/4YDaRWYTo7a+ObJ9a6sk0J8pfYYcpwn4QoFS+12IA95ea51TWN1bEoIFaVEqBDy5y3Qe7JSWNkCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFAkpP4Zm5qJ0Frn14iTtthSCrXVSMA0GCSqGSIb3DQEBCwUAA4ICAQA/Pnv9Lf/Ic/EeJYjFGZ84bICIZ/cFFNPcb4lWc7zJNOg2690t748MwqDUQYvCL4f5Dh+rvssLxK/FlMGDiw4UrZGHdHS5u3bTTUrbwG1NHQKRnthdz1xtx/TlBn4NvqVokcB7AkC5XVwpTvvVvcgpRp+ffYK3gd6arOb6oOOzRYDawFgPEZdZrbREh9p1k0NpbkUcmNiNMjQhV+DqVvGI+pYTOP4686Q4PvC7OGma5X3T0MWwUJ3iMPdo4qAGJB8GV4XbyPapMd7vqFzsf18yAKmT9Q2afr1U1KCQ/zourY1uqBeor5CzJzCDqLDxgXrBauVwB844Epa24x98RQGfZuIULZGPn0Sf8sF4L2bwmBBQM29yAWO4DLEZU0yqQTUHV7oJmNN+i0iE4wNSlC/Gz/wV3LCG+tseQkgvRziN8hwoTGg6n9EvT2NdD0QpzJ2D7PQeJIytKEYzJKVRCZkn3Xcoy1SzIKiG0xDLME22rjFuvWFyw1r/OnErIM7RL4GLZ3gAm00CRq4e2GarcEeLAq1d7rcSxV5/84pOIX9mH7PNJTg5js6pOn9hrZWmmwRKYYVTPFqkAlTurrO0NjOT/kmDdHT0Xnaq0LRg0bKa79iDJcylT5C08PAJX5S9esPXhNwS6rxMwk1ApmdE5USs/hn3geDAebJ0aRwIwnX5+g==-----END CERTIFICATE----------BEGIN CERTIFICATE-----MIIFPDCCAySgAwIBAgIQdWSbQJ/CYk1/BERap1nTNjANBgkqhkiG9w0BAQsFADA4MQswCQYDVQQGEwJFUzEQMA4GA1UECgwHU3RyYXRpbzEXMBUGA1UEAwwOU3RyYXRpbyBJbmMgQ0EwHhcNMTYwMjE5MTEzODI2WhcNMjYwMjE2MTEzODI2WjA4MQswCQYDVQQGEwJFUzEQMA4GA1UECgwHU3RyYXRpbzEXMBUGA1UEAwwOU3RyYXRpbyBJbmMgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2boA0hxlI9cDcSrt956lPnNuQ0ek/NnuWw6dsGXZeC1RHBR5m3/0jGnKRMpW2PpmTp7eG2ngOCbZMd5tGhZHoposlCHSjRrJvhXWPRDP52WvtSgsckcJtKw1uoo3lqZGBPAHpvg3ExxcWY8Q/b7H3Rc0zY2nM/whiayJPwO4+wE3gGiQwFrvsaekFjX/bNwBnZRiSAHm6iYeL0qfwvSUwBcs0Wzh2yCKOuNqnuk+xFy3iaj5ADWGDxhm4Qf4q5UKJCriYZnWWSn0CDIHlZPc05sXERO52OCyzAG5Bm8qCGeCBtgpFQtHf72gbJFfSqJKs0VQ7U8N9ucI3NAEpvt0NDXALF+4EoyV+0vCrq4U5f7geUSKPSEZWI2lpyz+NCZ95BrTFSHLDuNsTXJLnmJjOYCymAm5luKA6DQw3HyNXIndgKV2e5BfhSWx3HP4J0DxO7kB2F1APUSijNZAe2x6x+SO85CR6dT46pEvoGypD8EiRRoDHbQ8Vw1ulVh8nXoJzCs8v3exQUt1ZG7G1Pcmp/S4xPF0Y6/HP0IIe2pxJ4uzOYaaARki3AI8pwHfD6OON6tRC0wjnPB4qYPtanVJo4Nr/UWmq8vpgLKrI2kE3ceiPkNgb7/cXepyseTDBQidvCwV/ZyixmafwDgDi02zN/FI4yS3aMtpyXtrTkKlLXwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU1T68/Oa44A7bgn6wxN1deQVukKQwDQYJKoZIhvcNAQELBQADggIBAEGTbgPUdRcWCgLclrbIOJ9wNC/T0LhmAuMyPtXJVfojaH1XlWWGZw9CTAD0/d/W1cE0QwLi7MI0IWV6Lb4VjaogXIga7ND5uLzZ5iJb7SK8+gjK0d8hpGUKrwLzS6jUuL4vieM9DF7/VPi4EJm4EL35QfNpnb4Y17yOY1FZwZjtwlPZWGrG0plRTi70/Mgic4a3KtC1I33RUUruF3nk+Fm+VEJJzmoOi01JwDwuM1hT6lI4USNLp2vy4l1iJSdBSlwwNEthv1C/eHqC2XkH8Kr6kufW8s2Cnqu1tHJ/U+ns/m5dDcrP22i/toDKVwOdquFdB4bg42PWyKeQi85UlHVSPwlTiB7gXZi97vtIDlIfYZ6V3zy4fSUudaBXEm4IOY7IoRFB1zoqSj86KtufjOLAfqAcUFqYJGKEIfjbGistagDKh5VRTtmgWnCSp252h27UHrYMWSv9/oi6H7m9dv5ZBuUgeYnxsgZYDgic4xA80POOWAiMwYdoIQwQghdGLRDuXT8krg8/ery42xmIvqW0xpJzROAVzWgtEUFFtFfMnrFjf2b4o6Mw8A6AflbL1zeRuum/Uz+sFVVSUS1uzWrIRSTN6M2tRpu6EuRuNCJkNXxqQ5v3iBCpoKsXEBqDeymnT4WEFqv+Rq2ZHbticZ+vXbu8039fau7bdmVS9Bjj-----END CERTIFICATE-----",
	// 	  "cicdcd-dev-jenkins_key": "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA1f4HU6Fjf2lK2xt/+40wfx3YfWZw6+rlaKwTCzrQBvfUhinW44Q+XXHgOAT48yfHHopiqE74M3eTEydPX17+IniAcQcOs7CidgdwjI/hg0Ed6CQH0vs35TMgw3UTVL0NQgRWKEtWXyowsjic6eIHW9ezGW8KeFHQt/d8Vy3yEQlroOqxqL9x9ouaKooAb2FUwwsmOr4wmLj1B7F6qcODbtoccWcYi7ExtmjTt/HXVfbne0Dg1KyP2YyyNN1CHI3ZkjV2vJOZXn0bdA5ClyWfuLf6AkfNvK8AIhsRBn0hmOkgwjGvkTrtb0sDwjeah7dJeYBYr2rdZu9XvgzJ0zLaHQIDAQABAoIBAHOaA8M+EE4oR3QOaxktsOE68lTsHlyUTNI7Ax6x6ueYwoqn15qZOkeo2QPqS8Kv3nW1NI7P+m1zT1Sti8dtvcRJbLmiomKYLWutoTOOFrmdV9asgD2N0ShUcoKkoIjKiHr9dL3X1RUb6aqdwsbmgCsxX2OCBRnyuNppLBa8j2R7wVtxvf8pHXpFIQ2HTaiqhHpska/Z0GCbF1bjxZWhw2rxgKHaCmWnPnsS8qy4OnWS7zaqrXKtp62KwoF+7lQ6jLveVnPDh6Dec2diV+O66aQPn5d83sT5HVat0KBhzdwbhj569u2ewb66xh/OXJ+7R63M3KgTu7xiO6VsNRFu19ECgYEA8GcwpaNdUpjgF8aSOeyewaqFnkdXqmYcE74VTa8NSZPKQ4V1TuqatWGkQTbVy0P3au7HHRQUKJbLZiCk65s6KVD5VNKLuZscvZBly4+h3uOi9wp6OifXph5Yk3U2wgJFw2EIaSkJevIIP+ktaEa/TGtdN3GMr7GlfvAFY9KYIAMCgYEA4+Avz+lzJ1ppZUZC1lUAjIX9GV/AL0tuzj3fpnnVmaT/ZKA0OPxx0w4n4dfjKTZB+beWKp9l23r23N36gE4vJsPUipnth4PuwQ3Qyg2Y4uHqNSgDypSGHkoi3i8tr4TA6EiYvDUS0nIt7yCXr5eYOk6TC5JDYenxizwregjKU18CgYEAqc0ZDUWwWvDkB6cYDZXWJJCfREa74v2wgzlVrsMgLYIX8U1IqG8Iy2imLfHfXG0rSvpQ5XcTLgAktoQEOO4xTJGHKqR0UKsAx9xAKmHPQbGjn75kysLtjMYOZkj6XlpgkDnvSOfVbGOb9BhtHCQsZnvHIawwZMCjVl+OTw2mqaUCgYEAxU/6tnGy5zFvL2UePI5Psl3WoSD6vTj40hZbUMAQB0EKb2wUq/9S4+hO+kxAAxBbIkon+fIZdWlM1kRTQsPwKgXJRNYyCXRgyMMYtcv+RP5PGQXz+naOhy20cWSyj1dI3hj2P4lJKfX59iPnlACUrHAa/RsBw4eZQfGwx7NS1csCgYAPqUtbOCZPguqv2iozyqmRxDTKsul+kUEcG7E8dyxtQruEw2nL6riIq3X12X2MUlBQQNs0/SAJBNS04HHrO98syzU8i4mYj4HmyIjkbbtpHAy304ttotxFRhrbQ4qHo9WkR/NuW0mhINN76ISSRRZC3mM+kwNPebwiymqruWQnQQ==-----END RSA PRIVATE KEY-----"
	// 	},
	// 	"wrap_info": null,
	// 	"warnings": null,
	// 	"auth": null
	//   }`)

	type Response struct {
		Data interface{}
	}
	var certData Response

	if err := json.Unmarshal(body, &certData); err != nil {
		return cert, key, ca, fmt.Errorf("[ERROR] Error reading vault response: %v ", err)
	}
	
	klog.Warningf("[STG] backend_ssl getVaultCertificate - Data: %v", certData.Data)

	if certData.Data == nil {
		klog.Warning("[STG] backend_ssl getVaultCertificate - No Vault Data found")
		return cert, key, ca, nil
	}

	// As pointed out here: https://eagain.net/articles/go-dynamic-json, I will regret this
	rawCert := certData.Data.(map[string]interface{})[vaultKey + "_crt"]
	if rawCert == nil {
		klog.Warning("[STG] backend_ssl getVaultCertificate - rawCert is nil")
		return cert, key, ca, nil
	}
	var reCert = regexp.MustCompile(`-----END CERTIFICATE-----.*`)
	formattedCert := strings.Replace(reCert.ReplaceAllString(rawCert.(string), "$1\n-----END CERTIFICATE-----$2"), "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n", -1)
	cert = []byte(formattedCert)

	rawKey := certData.Data.(map[string]interface{})[vaultKey + "_key"]
	if rawKey == nil {
		klog.Warning("[STG] backend_ssl getVaultCertificate - rawKey is nil")
		return cert, key, ca, nil
	}

	formattedKey := strings.Replace(strings.Replace(rawKey.(string), "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n", -1), "-----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----\n", -1)
	key = []byte(formattedKey)

	var reCA = regexp.MustCompile(`^(.*?)-----END CERTIFICATE-----(.*)$`)
	subFormattedCA := reCA.ReplaceAllString(rawCert.(string), "${1}-----END CERTIFICATE-----\n$2")
	reCA = regexp.MustCompile(`.*\n`)
	formattedCA := reCA.ReplaceAllString(subFormattedCA, "$1$2")
	ca = []byte(strings.Replace(strings.Replace(formattedCA, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n", -1), "-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----\n", -1))

	klog.Warningf("[STG] backend_ssl getVaultCertificate - formattedCert: %s", formattedCert)
	klog.Warningf("[STG] backend_ssl getVaultCertificate - formattedKey: %s", formattedKey)
	klog.Warningf("[STG] backend_ssl getVaultCertificate - formattedCA: %s", formattedCA)
	klog.Warningf("[STG] backend_ssl getVaultCertificate - cert: %s", cert)
	klog.Warningf("[STG] backend_ssl getVaultCertificate - key: %s", key)
	klog.Warningf("[STG] backend_ssl getVaultCertificate - ca: %s", ca)

	return cert, key, ca, nil
}

// getPemCertificate receives a secret, and creates a ingress.SSLCert as return.
// It parses the secret and verifies if it's a keypair, or a 'ca.crt' secret only.
func (s *k8sStore) getPemCertificate(secretName string) (*ingress.SSLCert, error) {

	klog.Warningf("[STG] backend_ssl getPemCertificate - secretName: %s", secretName)

	var cert, key, ca, crl, auth []byte
	var okcert, okkey bool
	var uid, sslCertName, sslCertNamespace string

	// secret.UID

	secret, err := s.listers.Secret.ByKey(secretName)

	// If secret doesnt exist, we check if it is a vault path
	if err != nil {
		klog.Warningf("[STG] backend_ssl getPemCertificate - secretName is Vault Path")
		okcert = true
		okkey = true

		crl = []byte("")
		auth = []byte("")
		uid = uuid.New().String()

		// sslCertName = secretName[:strings.IndexByte(secretName, '/')]
		sslCertName = secretName[strings.IndexByte(secretName, '/'):]
		sslCertNamespace = secretName[:strings.IndexByte(secretName, '/')]
		
		klog.Warningf("[STG] backend_ssl getPemCertificate - sslCertName: %s", sslCertName)

		cert, key, ca, err = getVaultCertificate(sslCertName)

		if err != nil {
			return nil, fmt.Errorf("Missing certificates in Vault's Path %s", sslCertName)
		}

	} else {
		klog.Warningf("[STG] backend_ssl getPemCertificate - secret.name: %s", secret.Name)

		cert, okcert = secret.Data[apiv1.TLSCertKey]
		key, okkey = secret.Data[apiv1.TLSPrivateKeyKey]
		ca = secret.Data["ca.crt"]

		crl = secret.Data["ca.crl"]
		auth = secret.Data["auth"]

		uid = string(secret.UID)

		sslCertName = secret.Name
		sslCertNamespace = secret.Namespace

	}

	klog.Warningf("[STG] backend_ssl getPemCertificate - cert: %s", cert)
	klog.Warningf("[STG] backend_ssl getPemCertificate - key: %s", key)
	klog.Warningf("[STG] backend_ssl getPemCertificate - ca: %s", ca)

	klog.Warningf("[STG] backend_ssl getPemCertificate - crl: %s", crl)
	klog.Warningf("[STG] backend_ssl getPemCertificate - auth: %s", auth)

	// namespace/secretName -> namespace-secretName
	nsSecName := strings.Replace(secretName, "/", "-", -1)

	klog.Warningf("[STG] backend_ssl getPemCertificate - nsSecName: %s", nsSecName)

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
		// klog.Warningf("[STG] backend_ssl getPemCertificate - path: %s", string(secret.UID))

		if len(ca) > 0 {
			caCert, err := ssl.CheckCACert(ca)
			if err != nil {
				return nil, fmt.Errorf("parsing CA certificate: %v", err)
			}

			path, err := ssl.StoreSSLCertOnDisk(nsSecName, sslCert)
			if err != nil {
				return nil, fmt.Errorf("error while storing certificate and key: %v", err)
			}

			klog.Warningf("[STG] backend_ssl getPemCertificate - path: %s", path)

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

		klog.Warningf("[STG] backend_ssl getPemCertificate - default path: %s", path)

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
