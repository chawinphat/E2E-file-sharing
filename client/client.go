package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type UserContainer struct {
	UserStruct []byte
	UserMAC []byte
}

type User struct {
	Username string
	Salt []byte
	PassHash []byte
	RSASK userlib.PKEDecKey
	SigSK userlib.DSSignKey
	
	password string
	encKey []byte
	macKey []byte
	fileEnckey []byte //key for current file, set in getfile()
	fileMacKey []byte //key for current file mac, set in getfile()
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

var currentUser User

type FileContainer struct {
	FileStruct []byte
	FileMAC []byte
	UserTreeUUID uuid.UUID
}

type File struct {
	FileName []byte
	UpdateListHead uuid.UUID
	UpdateListTail uuid.UUID
}

type UserTree struct {
	Username string
	FileSourceKey []byte
}


type UpdateListContainer struct {
	ListStruct []byte
	ListMAC []byte
}

type UpdateList struct {
	Contents []byte
	NextUUID uuid.UUID
}

type InvitationPtr struct {
	InvitStruct Invitation
	Sig []byte
}

type Invitation struct {
	FileContainer uuid.UUID
	FilePK userlib.PKEEncKey
}

func GetUserID(username string) (userUUID uuid.UUID, err error) {
	userUUID, err = uuid.FromBytes([]byte(userlib.Hash([]byte(username)))[0:16]) // can you open a shared terminal pls
	if err != nil {
		return uuid.Nil, err
	}
	return userUUID, nil
}

func VerifyUser(username string, password string, userCont UserContainer) (equal bool, err error) {
	macKey, err := GetLocalKey(username, password, "mac")
	if err != nil {
		return false, err
	}

	currMAC, err := userlib.HMACEval(macKey, userCont.UserStruct)
	if err != nil {
		return false, err
	}
	equal = userlib.HMACEqual(currMAC, userCont.UserMAC)
	return equal, nil
}

func GetLocalKey(username string, password string, purpose string) (key []byte, err error) {
	srcKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	key, err = userlib.HashKDF(srcKey, []byte(purpose))
	key = key[0:16]
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GetFile(filename string) (filedataptr *File, err error) { //returns file, returns false if errors
	ok := false
	byteFilename := []byte(filename)
	if err != nil {
		return nil, err
	}
	fileMapUUID, err := uuid.FromBytes([]byte(userlib.Hash(byteFilename))[0:17]) //key:value where value points to file
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot get uuid from bytes"))
	}
	
	//get file container uuid
	EncfileContainerUUID, ok := userlib.DatastoreGet(fileMapUUID)
	if ok == false {
		return nil, errors.New(strings.ToTitle("EncfileContainerUUID not found"))
	}
	fileContainerUUIDMarshal := userlib.SymDec(currentUser.encKey, EncfileContainerUUID)
	var fileContainerUUID uuid.UUID
	err = json.Unmarshal(fileContainerUUIDMarshal, &fileContainerUUID)
	//get file container
	fileContBytes, ok := userlib.DatastoreGet(fileContainerUUID)
	if ok == false {
		return nil, errors.New(strings.ToTitle("fileContainerUUID not found"))
	}
	var fileContainer FileContainer;
	err = json.Unmarshal(fileContBytes, &fileContainer)
	if err != nil {
		return nil, errors.New(strings.ToTitle("File Container not found"))
	}
	//get user tree, an array of users
	userTreeArr, ok := userlib.DatastoreGet(fileContainer.UserTreeUUID)
	if ok == false {
		return nil, errors.New(strings.ToTitle("userTree not found"))
	}
	
	var userList []UserTree //temp user tree
	err = json.Unmarshal(userTreeArr, &userList)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshall userTreeArr"))
	}

	found := false
	var fileSourceKey []byte
	for i := 0; i < len(userList); i++ {
		if currentUser.Username == userList[i].Username {
			found = true
			// user is acquiring file's symetric key here
			fileSourceKey, err = userlib.PKEDec(currentUser.RSASK, userList[i].FileSourceKey)
			if err != nil {
				return nil, err
			}
			break
		}		
	}
	if found != true {
		return nil, errors.New(strings.ToTitle("user not found in user tree"))
	}

	currentUser.fileEnckey, err = userlib.HashKDF(fileSourceKey, []byte("encryption"))
	currentUser.fileMacKey, err = userlib.HashKDF(fileSourceKey, []byte("mac"))
	
	//decrypt file container using file symmetric key
	marshalFileStruct := userlib.SymDec(currentUser.fileEnckey, fileContainer.FileStruct)
	//verify file HMAC
	HMACnew, err := userlib.HMACEval(currentUser.fileMacKey, marshalFileStruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot compute HMAC of filestruct"))
	}
	equals := userlib.HMACEqual(fileContainer.FileMAC, HMACnew)
	if equals != true {
		return nil, errors.New(strings.ToTitle("HMAC verify failed for file"))
	}
	var filestruct File
	err = json.Unmarshal(marshalFileStruct, &filestruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshall filestruct"))
	}
	
	filedataptr = &filestruct
	return filedataptr, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check if valid username
	if username == "" {
		return nil, errors.New(strings.ToTitle("username is empty"))
	}

	userUUID, err := GetUserID(username)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New(strings.ToTitle("username already exists"))
	}

	// Create user struct
	userdataptr = &User {
		Username: username,
		Salt: userlib.RandomBytes(512),
		password: password,
	}

	userdataptr.PassHash = userlib.Argon2Key([]byte(password), userdataptr.Salt, 512)

	rsaPK, rsaSK, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdataptr.RSASK = rsaSK
	err = userlib.KeystoreSet(username + "_RSA", rsaPK)
	if err != nil {
		return nil, err
	}

	sigSK, sigPK, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdataptr.SigSK = sigSK
	err = userlib.KeystoreSet(username + "_Sig", sigPK)
	if err != nil {
		return nil, err
	}

	encKey, err := GetLocalKey(username, password, "encryption")
	if err != nil {
		return nil, err
	}
	userdataptr.encKey = encKey

	macKey, err := GetLocalKey(username, password, "mac")
	if err != nil {
		return nil, err
	}
	userdataptr.macKey = macKey

	// Create user container and place on datastore
	userBytes, err := json.Marshal(*userdataptr)
	if err != nil {
		return nil, err
	}
	userCont := UserContainer {
		UserStruct: userlib.SymEnc(userdataptr.encKey, userlib.RandomBytes(16), userBytes),
	}
	mac, err := userlib.HMACEval(userdataptr.macKey, userCont.UserStruct)
	if err != nil {
		return nil, err
	}
	userCont.UserMAC = mac
	
	userContBytes, err := json.Marshal(userCont)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userUUID, userContBytes)

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	userUUID, err := GetUserID(username)
	if err != nil {
		return nil, err
	}
	
	userContBytes, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, err
	}

	var userCont UserContainer
	err = json.Unmarshal(userContBytes, &userCont)
	if err != nil {
		return nil, err
	}

	equal, err := VerifyUser(username, password, userCont)
	if err != nil {
		return nil, err
	} else if !equal {
		return nil, errors.New(strings.ToTitle("user struct has been compromised"))
	}

	decKey, err := GetLocalKey(username, password, "encryption")
	if err != nil {
		return nil, err
	}
	
	userBytes := userlib.SymDec(decKey, userCont.UserStruct)
	var userStruct User
	err = json.Unmarshal(userBytes, &userStruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshal user struct"))
	}

	// Check password
	givenHash := userlib.Argon2Key([]byte(password), userStruct.Salt, 512)
	if !userlib.HMACEqual(givenHash, userStruct.PassHash) {
		return nil, errors.New(strings.ToTitle("incorrect password"))
	}

	var userdata User
	userdataptr = &userdata
	currentUser = userdata //sets system's current user to userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
