// Ecca Authentication Dating Site Example
//
// Show the cryptographic message signing and encryption to provide anonymous
// but secure and private communication.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under GPL v3 or later.

package main

import (
	"log"
	"net/http"
	"crypto/x509"
	"crypto/tls"
	"io/ioutil"
	"html/template"
	"database/sql"
	_ "github.com/gwenn/gosqlite"
)

var homePageTemplate = template.Must(template.ParseFiles("homepage.template", "menu.template")) 

func homePage(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/" {
		err := homePageTemplate.Execute(w, nil) 
		check(err)
		return
	}
	http.NotFound(w, req)
}


var editProfileTemplate = template.Must(template.ParseFiles("editProfile.template", "menu.template"))

func editProfile(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		sendToLogin(w, req)
		return
	}

	// User is logged in
	cn := req.TLS.PeerCertificates[0].Subject.CommonName
	switch req.Method {
	case "GET": 
		alien := getAlien(cn)  // alien or nil
		log.Printf("Alien is %#v\n", alien)
		err := editProfileTemplate.Execute(w, map[string]interface{}{
			"CN": cn,
			"alien": alien,
			"races": races,
			"occupations": occupations,
		}) 
		check(err)
		return
	case "POST":
		req.ParseForm()
		saveAlien(Alien{
			CN: cn,
			Race: req.Form.Get("race"),
			Occupation: req.Form.Get("occupation"),
		})
		//TODO: make a nice page with a menu and a redirect-link.
		w.Write([]byte(`<html><p>Thank you for your entry. <a href="/aliens">Show all aliens.</a></p></html>`))
		return
	// TODO: change panic to 400-error.
	default: panic("Unexpected method")
	}
	return
}


// Checked sets the checked attribute.
func (alien *Alien) Checked(data string) string {
 	if alien == nil { return "" } // no data, nothing selected
 	if alien.Race == data { return "checked"} // if the data is in the Alien.Race -> true
 	if alien.Occupation == data { return "checked" } // or if the data is in the Occup. -> true
 	return ""
}



var aliensTemplate = template.Must(template.ParseFiles("aliens.template", "menu.template"))

// Show profiles, no authentication required
func showProfiles (w http.ResponseWriter, req *http.Request) {
	log.Printf("TLS connection %s, state: %#v\n", req.URL.Host, req.TLS)
	aliens := getAliens()
	err := aliensTemplate.Execute(w, map[string]interface{}{
		"aliens": aliens,
		"races": races,
		"occupations": occupations,
	}) 
	check(err)
	return
}


var readMessageTemplate = template.Must(template.ParseFiles("readMessage.template", "menu.template"))

// readMessages shows you the messages other aliens have sent.
func readMessages (w http.ResponseWriter, req *http.Request) {
	log.Printf("TLS connection %s, state: %#v\n", req.URL.Host, req.TLS)
	// check to see if logged in
	if len(req.TLS.PeerCertificates) == 0 {
		// Not logged in. Send to register-site.
		sendToLogin(w, req)
		return
	}

	// User is logged in
	cn := req.TLS.PeerCertificates[0].Subject.CommonName
	switch req.Method {
	case "GET": 
		// set this header to signal the user agent to perform data decryption.
		w.Header().Set("Eccentric-Authentication", "decryption=\"required\"")
		w.Header().Set("Content-Type", "text/html, charset=utf8")
		messages := getMessages(cn)
		err := readMessageTemplate.Execute(w, map[string]interface{}{
			"CN": cn,
			"messages": messages,
		}) 
		check(err)
		return
	default: panic("Unexpected method")
	}
	return
}


var sendMessageTemplate = template.Must(template.ParseFiles("sendMessage.template", "menu.template"))

func sendMessage(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		sendToLogin(w, req)
		return
	}

	// User is logged in
	cn := req.TLS.PeerCertificates[0].Subject.CommonName
	switch req.Method {
	case "GET": 
		req.ParseForm()
		toCN := req.Form.Get("addressee")
 		err := sendMessageTemplate.Execute(w, map[string]interface{}{
			"CN": cn,
			"ToCN": toCN,
			"ToURL": "https://register-dating.wtmnd.nl:10444/get-certificate?nickname=" + toCN,
		})
		check(err)
		return
	case "POST":
		req.ParseForm()
		saveMessage(Message{
			FromCN: cn,
			ToCN: req.Form.Get("addressee"),
			Ciphertext: req.Form.Get("ciphertext"),
		})
		w.Write([]byte(`<html><p>Thank you, your message will be delivered at galactic speed.</p></html>`))
		return
	default: panic("Unexpected method")
	}
	return
}


func sendToLogin (w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("WWW-Authenticate", "Ecca realm=\"dating.wtmnd.nl\" type=\"public-key\" register=\"https://register-dating.wtmnd.nl:10444/register-pubkey\"")
	w.WriteHeader(401)
	w.Write([]byte("You need to register.\n"))
}	


func main() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/profile", editProfile)
	http.HandleFunc("/aliens", showProfiles)
	http.HandleFunc("/read-messages", readMessages)
	http.HandleFunc("/send-message", sendMessage)
	http.Handle("/static/", http.FileServer(http.Dir(".")))

	// This CA-pool specifies which client certificates can log in to our site.
	pool := readCert("datingLocalCA.cert.pem")
	
	log.Printf("About to listen on 10443. Go to https://dating.wtmnd.nl:10443/")
	server := &http.Server{Addr: "[2001:980:71b2:1::443]:10443",
	                       TLSConfig: &tls.Config{
			            ClientCAs: pool,
			ClientAuth: tls.VerifyClientCertIfGiven},
	}
	
	err := server.ListenAndServeTLS("dating.wtmnd.nl.cert.pem", "dating.wtmnd.nl.key.pem")
	check(err)
}


// read certificate file or panic
func readCert(certFile string) (*x509.CertPool) {
	pool := x509.NewCertPool()

	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		panic("Cannot read certificate file " + certFile)
	}
	ok := pool.AppendCertsFromPEM(certPEMBlock)
	if !ok  {
		panic("Cannot parse certificate file " + certFile)
	}
	return pool
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
