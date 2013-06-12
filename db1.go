// Database connection

package main

import (
	"database/sql"
	_ "github.com/gwenn/gosqlite"

	// utils
	"log"
)

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
	query := "SELECT toCN, fromCN, ciphertext FROM messages WHERE toCN = ?"
	log.Printf("query is: %s  with %s\n", query, toCN)
	rows, err := db.Query(query, toCN)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var message Message
		rows.Scan(&message.ToCN, &message.FromCN, &message.Ciphertext)
		messages = append(messages, message)
	}
	return
}