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

	"database/sql"
	_ "github.com/gwenn/gosqlite"
)


// The things to set before running.
var certDir = flag.String("cert", "cert", "Directory where the certificates and keys are found.") 
var fpcaCert = flag.String("fpcaCert", "applicationFPCA.cert.pem", "File with the Certificate of the First Party Certificate Authority that we accept for our clients.")
var fpcaURL = flag.String("fpcaUrl", "https://register-application.example.nl", "URL of the First Party Certificate Authority where clients can get their certificate.")
var hostname = flag.String("hostname", "application.example.nl", "Hostname of the application. Determines which cert.pem and key.pem are used for the TLS-connection.")
var bindAddress = flag.String("bind", "[::]:443", "Address and port number where to bind the listening socket.") 
//var namespace = flag.String("namespace", "", "Name space that we are signing. I.E. <cn>@@example.com. Specifiy the part after the @@.")

var ecca= eccentric.Authentication{
	RegisterURL:  *fpcaURL, // "https://register-dating.wtmnd.nl:10444/register-pubkey",
	Templates: templates,   //Just copy the templates variable
}

var templates = template.Must(template.ParseFiles(
	"templates/homepage.template",
	"templates/editProfile.template",
	"templates/aliens.template",
	"templates/readMessage.template",
	"templates/sendMessage.template",
	"templates/needToRegister.template",
	"templates/menu.template",
	"templates/tracking.template")) 


func init() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/aliens", showProfiles)

	http.Handle("/profile", ecca.LoggedInHandler(editProfile, "needToRegister.template"))

	http.Handle("/read-messages", ecca.LoggedInHandler(readMessages, "needToRegister.template"))
	http.Handle("/send-message", ecca.LoggedInHandler(sendMessage, "needToRegister.template"))

	http.Handle("/static/", http.FileServer(http.Dir(".")))
}


func main() {
	flag.Parse()
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
	}
	http.NotFound(w, req)
}


// editProfile lets the user fill in his/her profile data to lure the aliens into the hive.
func editProfile(w http.ResponseWriter, req *http.Request) {
	// LoggedInHander made sure our user is logged in.
	// If not, this will give a nice 500 Internal Server Error.
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


// Show profiles, no authentication required
func showProfiles (w http.ResponseWriter, req *http.Request) {
	aliens := getAliens()
	check(templates.ExecuteTemplate(w, "aliens.template", map[string]interface{}{
		"aliens": aliens,
		"races": races,
		"occupations": occupations,
	}))
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
		toURL, err := url.Parse("https://register-dating.wtmnd.nl:10444/get-certificate")
		check(err)
		q := toURL.Query()
		q.Set("nickname", toCN)
		toURL.RawQuery = q.Encode()
 		check(templates.ExecuteTemplate(w, "sendMessage.template", map[string]interface{}{
			"CN": cn,
			"ToCN": toCN,
			"ToURL": toURL,
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

// Database connection

var dbFile = "datingdb.db"
var db *sql.DB
	
func init() {
	var err error
	db, err = sql.Open("sqlite3", dbFile)
	check(err)	
	
	_, err = db.Exec("CREATE TABLE aliens (cn TEXT, race TEXT, occupation TEXT)")
	// check(err) // ignore

	_, err = db.Exec("CREATE TABLE messages (toCN TEXT, fromCN, ciphertext BLOB)")
	// check(err) // ignore
}

// saveAlien inserts or updates an Alien record
func saveAlien(alien Alien) {
	existing := getAlien(alien.CN)
	var result sql.Result
	var err error
	if existing == nil {
		insert, err := db.Prepare("INSERT INTO aliens (cn, race, occupation) values (?, ?, ?)")
		check(err)
		defer insert.Close()
		
		result, err = insert.Exec(alien.CN, alien.Race, alien.Occupation)
		check(err)
	} else {
		update, err := db.Prepare("UPDATE aliens SET race = ?, occupation = ? WHERE cn = ?")
		check(err)
		defer update.Close()

		result, err = update.Exec(alien.Race, alien.Occupation, alien.CN)
		check(err)
	}
	count, err := result.RowsAffected()
	check(err)
	log.Printf("Inserted %d rows", count)
}

func getAliens() (aliens []Alien) {
	rows, err := db.Query("SELECT cn, race, occupation FROM aliens")
	check(err)
	defer rows.Close()
	for rows.Next() {
		var alien Alien
		rows.Scan(&alien.CN, &alien.Race, &alien.Occupation)
		aliens = append(aliens, alien)
	}
	return
}

// getAlien gets one alien
func getAlien(cn string) (*Alien) {
	rows, err := db.Query("SELECT cn, race, occupation FROM aliens WHERE cn = ?", cn)
	check(err)
	defer rows.Close()
	if rows.Next() {
		var alien Alien
		rows.Scan(&alien.CN, &alien.Race, &alien.Occupation)
		return &alien
	}
	return nil
}



func saveMessage(message Message) {
	insert, err := db.Prepare("INSERT INTO messages (toCN, fromCN, ciphertext) values (?, ?, ?)")
	check(err)
	defer insert.Close()

	result, err := insert.Exec(message.ToCN, message.FromCN, message.Ciphertext)
	check(err)
	count, err := result.RowsAffected()
	check(err)
	log.Printf("Inserted %d rows", count)
}

func getMessages(toCN string) (messages []Message) {
	rows, err := db.Query("SELECT toCN, fromCN, ciphertext FROM messages WHERE toCN = ?", toCN)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var message Message
		rows.Scan(&message.ToCN, &message.FromCN, &message.Ciphertext)
		messages = append(messages, message)
	}
	return
}
