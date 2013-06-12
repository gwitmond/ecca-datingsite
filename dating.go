// Eccentric Authentication Dating Site Example
//
// Show the cryptographic message signing and encryption to provide anonymous
// but secure and private communication.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

package main

import (
	"log"
	"net/http"
	"net/url"
	"crypto/tls"
	"html/template"
	"flag"

	"github.com/gwitmond/eccentric-authentication" // package eccentric

	// These are for the data storage
	//"github.com/coopernurse/gorp"
	//"database/sql"
	//_ "github.com/mattn/go-sqlite3"
)

// The things to set before running.
var certDir = flag.String("config", "cert", "Directory where the certificates and keys are found.") 
var fpcaCert = flag.String("fpcaCert", "applicationFPCA.cert.pem", "File with the Certificate of the First Party Certificate Authority that we accept for our clients.")
var fpcaURL = flag.String("fpcaURL", "https://register-application.example.nl", "URL of the First Party Certificate Authority where clients can get their certificate.")
var hostname = flag.String("hostname", "application.example.nl", "Hostname of the application. Determines which cert.pem and key.pem are used for the TLS-connection.")
var bindAddress = flag.String("bind", "[::]:443", "Address and port number where to bind the listening socket.") 

// global state
var ecca = eccentric.Authentication{}
 
var templates = template.Must(template.ParseFiles(
	"templates/homepage.template",
	"templates/editProfile.template",
	"templates/aliens.template",
	"templates/showAlien.template",	
	"templates/readMessage.template",
	"templates/sendMessage.template",
	"templates/needToRegister.template",
	"templates/menu.template",
	"templates/tracking.template")) 


func init() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/aliens", showAliens)
	http.HandleFunc("/show", showProfile)
	
	http.Handle("/profile", ecca.LoggedInHandler(editProfile, "needToRegister.template"))

	http.Handle("/read-messages", ecca.LoggedInHandler(readMessages, "needToRegister.template"))
	http.Handle("/send-message", ecca.LoggedInHandler(sendMessage, "needToRegister.template"))

	http.Handle("/static/", http.FileServer(http.Dir(".")))
}


func main() {
	flag.Parse()
	ecca = eccentric.Authentication{
		RegisterURL:  *fpcaURL, // "https://register-dating.wtmnd.nl:10444/register-pubkey",
		Templates: templates,   //Just copy the templates variable
	}

	// This CA-pool specifies which client certificates can log in to our site.
	pool := eccentric.ReadCert( *certDir + "/" + *fpcaCert) // "datingLocalCA.cert.pem"
	
	log.Printf("Started at %s. Go to https://%s/ + port", *bindAddress, *hostname)
	
	server := &http.Server{Addr: *bindAddress,
		TLSConfig: &tls.Config{
			ClientCAs: pool,
			ClientAuth: tls.VerifyClientCertIfGiven},
	}
	// Set  the server certificate to encrypt the connection with TLS
	ssl_certificate := *certDir + "/" + *hostname + ".cert.pem"
	ssl_cert_key   := *certDir + "/" + *hostname + ".key.pem"
	
	check(server.ListenAndServeTLS(ssl_certificate, ssl_cert_key))
}


func homePage(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/" {
		check(templates.ExecuteTemplate(w, "homepage.template",  nil))
		return;
	}
	http.NotFound(w, req)
}


// editProfile lets the user fill in his/her profile data to lure the aliens into the hive.
func editProfile(w http.ResponseWriter, req *http.Request) {
	// LoggedInHander made sure our user is logged in with a correct certificate
	cn := req.TLS.PeerCertificates[0].Subject.CommonName
	switch req.Method {
	case "GET": 
		alien := getAlien(cn)  // alien or nil
		check(templates.ExecuteTemplate(w, "editProfile.template", map[string]interface{}{
			"CN": cn,
			"alien": alien,
			"races": races,
			"occupations": occupations,
		}))

	case "POST":
		req.ParseForm()
		saveAlien(Alien{
			CN: cn,
			Race: req.Form.Get("race"),
			Occupation: req.Form.Get("occupation"),
		})
		//TODO: make a nice template with a menu and a redirect-link.
		w.Write([]byte(`<html><p>Thank you for your entry. <a href="/aliens">Show all aliens.</a></p></html>`))

	default: 
		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
	}
}


// Checked sets the checked attribute.
// To be called from within templates.
func (alien *Alien) Checked(data string) string {
 	if alien == nil { return "" } // no data, nothing selected
 	if alien.Race == data { return "checked"} // if the data is in the Alien.Race -> true
 	if alien.Occupation == data { return "checked" } // or if the data is in the Occup. -> true
 	return ""
}


// Show all aliens, no authentication required
func showAliens (w http.ResponseWriter, req *http.Request) {
	aliens := getAliens()
	check(templates.ExecuteTemplate(w, "aliens.template", map[string]interface{}{
		"aliens": aliens,
		"races": races,
		"occupations": occupations,
	}))
}

// Show all aliens, no authentication required
func showProfile (w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	cn := req.Form.Get("alien")
	alien := getAlien(cn)
	if alien == nil {
		http.NotFound(w, req)
		return
	}
	check(templates.ExecuteTemplate(w, "showAlien.template", map[string]interface{}{
		"alien": alien	}))
}

// readMessages shows you the messages other aliens have sent you.
func readMessages (w http.ResponseWriter, req *http.Request) {
	// User is logged in
	cn := req.TLS.PeerCertificates[0].Subject.CommonName
	switch req.Method {
	case "GET": 
		// set this header to signal the user's Agent to perform data decryption.
		w.Header().Set("Eccentric-Authentication", "decryption=\"required\"")
		w.Header().Set("Content-Type", "text/html, charset=utf8")
		messages := getMessages(cn)
		check(templates.ExecuteTemplate(w, "readMessage.template", map[string]interface{}{
			"CN": cn,
			"messages": messages,
		}))
		
	default:
 		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )

	}
}


// sendMessage takes an encrypted message and delivers it at the message box of the recipient
// Right now, that's our own dating site. It could perform a MitM.
// See: http://eccentric-authentication.org/eccentric-authentication/private_messaging.html
func sendMessage(w http.ResponseWriter, req *http.Request) {
	cn := req.TLS.PeerCertificates[0].Subject.CommonName
	switch req.Method {
	case "GET": 
		req.ParseForm()
		toCN := req.Form.Get("addressee")

		// idURL 
		// We do provide a path to the CA to let the user retrieve the public key of the recipient.
		// User is free to obtain in other ways... :-)
		idURL, err := url.Parse(*fpcaURL)
		idURL.Path = "/get-certificate"
		check(err)
		q := idURL.Query()
		q.Set("nickname", toCN)
		idURL.RawQuery = q.Encode()

 		check(templates.ExecuteTemplate(w, "sendMessage.template", map[string]interface{}{
			"CN": cn,            // from us
			"ToCN": toCN,   // to recipient
			"IdURL": idURL, // where to find the certificate with public key
		}))

	case "POST":
		req.ParseForm()
		ciphertext := req.Form.Get("ciphertext")
		if ciphertext == "" {
			w.Write([]byte(`<html><p>Your message was not encrypted. We won't accept it. Please use the ecca-proxy.</p></html>`))
			return
		}
		saveMessage(Message{
			FromCN: cn,
			ToCN: req.Form.Get("addressee"),
			Ciphertext: ciphertext,
		})
		w.Write([]byte(`<html><p>Thank you, your message will be delivered at galactic speed.</p></html>`))

	default:
 		http.Error(w, "Unexpected method", http.StatusMethodNotAllowed )
	}

}



	
func check(err error) {
	if err != nil {
		panic(err)
	}
}


// Example data

var races = map[string]string{
	"a-mars": "Man from Mars",
	"b-venus": "Vamp from Venus",
	"c-creature": "A small furry creature from Alpha Centauri",
}

var occupations = map[string]string{
	"a-captain": "Captain of a Death Star",
	"b-barkeeper": "Barkeeper at a deep space station",
	"c-redshirt": "Redshirt at an away mission",
}


// Marshalling

type Alien struct {
	CN string
	Race string
	Occupation string
}

// get full description for race-id
func (alien Alien) GetRace() (string) {
	return races[alien.Race]
}

// get full description for occupation-id
func (alien Alien) GetOccupation() (string) {
	return occupations[alien.Occupation]
}

// Message struct is used to display received messages
type Message struct {
	ToCN string
	FromCN string
	Ciphertext string // []byte  // don't convert to utf-8 string and back
}


