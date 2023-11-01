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
	UserMAC    []byte
}

type User struct {
	Username string
	Salt     []byte
	PassHash []byte
	RSASK    userlib.PKEDecKey
	SigSK    userlib.DSSignKey

	password   string
	encKey     []byte
	macKey     []byte
	fileEncKey []byte //key for current file, set in getfile()
	fileMacKey []byte //key for current file mac, set in getfile()
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type FileContainer struct {
	FileStruct   []byte
	FileMAC      []byte
	UserTreeUUID uuid.UUID
}

type File struct {
	FileName       []byte
	UpdateListHead uuid.UUID
	UpdateListTail uuid.UUID
}

type FilePointer struct {
	FileContUUID []byte // Encrpyt using local key, "encryption"
	UUIDMAC      []byte // MAC using local key, "mac"
}

type UserTree struct {
	Username   string
	FileEncKey []byte // RSA encrypted
	FileMacKey []byte // RSA encrypted
}

type UpdateListContainer struct {
	UpdateList []byte
	ListMAC    []byte
}

type UpdateList struct {
	Contents []byte
	NextUUID uuid.UUID
}

type InvitationContainer struct {
	InvitStruct []byte
	Sig         []byte
}

type Invitation struct {
	FileContainer uuid.UUID
	FilePK        []byte
}

// Returns UUID of a UserContainer
func GetUserID(username string) (userUUID uuid.UUID, err error) {
	userInput := userlib.Hash([]byte(username))
	userUUID, err = uuid.FromBytes(userInput[0:16])
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot get UUID from username bytes"))
	}
	return userUUID, nil
}

// Returns UUID of a file pointer that points to OG file container
func GetFilePtrID(username string, filename string) (fileUUID uuid.UUID, err error) {
	fileInput := userlib.Hash([]byte(username + "/" + filename))
	fileUUID, err = uuid.FromBytes(fileInput[0:16])
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot get UUID from username/filename bytes"))
	}
	return fileUUID, nil
}

// Create local keys for users
func GetLocalKey(username string, password string, purpose string) (key []byte, err error) {
	srcKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
	key, err = userlib.HashKDF(srcKey, []byte(purpose))
	key = key[0:16]
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Checks that current HMAC of user struct matches saved HMAC
func VerifyUserMAC(username string, password string, userCont UserContainer) (err error) {
	macKey, err := GetLocalKey(username, password, "mac")
	if err != nil {
		return err
	}
	currMAC, err := userlib.HMACEval(macKey, userCont.UserStruct)
	if err != nil {
		return err
	}
	equal := userlib.HMACEqual(currMAC, userCont.UserMAC)
	if !equal {
		return errors.New(strings.ToTitle("user struct has been compromised"))
	}
	return nil
}

// Checks integrity of user struct and returns a UserContainer
func GetUserContainer(username string, password string) (userCont *UserContainer, err error) {
	// Get user container
	userContUUID, err := GetUserID(username)
	if err != nil {
		return nil, err
	}
	userContBytes, ok := userlib.DatastoreGet(userContUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("user container not found in datastore"))
	}

	// Unmarshal user container
	err = json.Unmarshal(userContBytes, &userCont)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshal user container bytes"))
	}

	// Check stored and computed MACs
	err = VerifyUserMAC(username, password, *userCont)
	if err != nil {
		return nil, err
	}
	return userCont, nil
}

// Returns FilePointer if it exists
func GetFilePtr(userdata *User, filename string) (filePtr *FilePointer, err error) {
	filePtrUUID, err := GetFilePtrID(userdata.Username, filename)
	if err != nil {
		return nil, err
	}
	filePtrBytes, ok := userlib.DatastoreGet(filePtrUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("filename does not exist in caller's namespace"))
	}

	// Unmarshal file pointer
	err = json.Unmarshal(filePtrBytes, &filePtr)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshal file pointer bytes"))
	}

	return filePtr, nil
}

// Checks integrity of file pointer struct and returns UUID of FileContainer
func GetFileContUUID(userdata *User, filename string) (fileCont uuid.UUID, err error) {
	filePtr, err := GetFilePtr(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Check MAC of file container's UUID
	currMAC, err := userlib.HMACEval(userdata.macKey, filePtr.FileContUUID)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot compute HMAC of file pointer"))
	}
	equal := userlib.HMACEqual(currMAC, filePtr.UUIDMAC)
	if !equal {
		return uuid.Nil, errors.New(strings.ToTitle("file pointer has been compromised"))
	}

	// Get file container's UUID
	UUIDBytes := userlib.SymDec(userdata.encKey, filePtr.FileContUUID)
	var contUUID uuid.UUID
	err = json.Unmarshal(UUIDBytes, &contUUID)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot unmarshal UUID of file container"))
	}

	return contUUID, nil
}

// Returns file, returns false if errors
func GetFile(userdata *User, filename string) (filedataptr *File, err error) {
	fileMapUUID, err := GetFileContUUID(userdata, filename)

	//get file container uuid
	fmt.Print(fileMapUUID)
	EncfileContainerUUID, ok := userlib.DatastoreGet(fileMapUUID)
	if ok == false {
		return nil, errors.New(strings.ToTitle("EncfileContainerUUID not found"))
	}
	fileContainerUUIDMarshal := userlib.SymDec(userdata.encKey, EncfileContainerUUID)
	var fileContainerUUID uuid.UUID
	err = json.Unmarshal(fileContainerUUIDMarshal, &fileContainerUUID)
	//get file container
	fileContBytes, ok := userlib.DatastoreGet(fileContainerUUID)
	if ok == false {
		return nil, errors.New(strings.ToTitle("fileContainerUUID not found"))
	}
	var fileContainer FileContainer
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
	var fileEncKey []byte
	var fileMacKey []byte
	for i := 0; i < len(userList); i++ {
		if userdata.Username == userList[i].Username {
			found = true
			// user is acquiring file's symetric key here
			fileEncKey, err = userlib.PKEDec(userdata.RSASK, userList[i].FileEncKey)
			fileMacKey, err = userlib.PKEDec(userdata.RSASK, userList[i].FileMacKey)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if found != true {
		return nil, errors.New(strings.ToTitle("user not found in user tree"))
	}

	userdata.fileEncKey = fileEncKey
	userdata.fileMacKey = fileMacKey

	//decrypt file container using file symmetric key
	marshalFileStruct := userlib.SymDec(userdata.fileEncKey, fileContainer.FileStruct)
	//verify file HMAC
	HMACnew, err := userlib.HMACEval(userdata.fileMacKey, marshalFileStruct)
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
	userdataptr = &User{
		Username: username,
		Salt:     userlib.RandomBytes(512),
		password: password,
	}

	userdataptr.PassHash = userlib.Argon2Key([]byte(password), userdataptr.Salt, 512)

	rsaPK, rsaSK, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdataptr.RSASK = rsaSK
	err = userlib.KeystoreSet(username+"_RSA", rsaPK)
	if err != nil {
		return nil, err
	}

	sigSK, sigPK, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdataptr.SigSK = sigSK
	err = userlib.KeystoreSet(username+"_Sig", sigPK)
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
	userCont := UserContainer{
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
	// Verify validiity and integrity of user struct
	userCont, err := GetUserContainer(username, password)
	if err != nil {
		return nil, err
	}

	// Decrypt user struct
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

	// Set system's current user to userdata
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//call verify user
	//check if hash(filename) exists already
	fileExist := true
	containerUUID, err := GetFileContUUID(userdata, filename) //CHANGE
	if err != nil {                                               //file does not exist
		fileExist = false
		containerUUID = uuid.New()
	}
	var fileStruct File
	if fileExist == false {
		//create new file struct
		fileStruct = File{FileName: []byte(filename)}
		//create new user file enc and file mac keys
		userdata.fileEncKey = userlib.RandomBytes(16)
		userdata.fileMacKey = userlib.RandomBytes(16)
	}
	//if file exists
	if fileExist == true {
		fileStruct, err := GetFile(userdata, filename)
		if err != nil {
			return err
		}
		//iterate through and delete everything
		curr := fileStruct.UpdateListHead
		nodeUUIDs := make([]uuid.UUID, 0) //dynamic length array using append
		for curr != fileStruct.UpdateListTail {
			nodeUUIDs = append(nodeUUIDs, curr)
			updateContainerMarshal, ok := userlib.DatastoreGet(curr)
			var updateContainer UpdateListContainer
			json.Unmarshal(updateContainerMarshal, &updateContainer)
			if ok == false {
				return errors.New(strings.ToTitle("not Ok when trying to get curr"))
			}
			//verify node hmac
			nodeHMACNew, err := userlib.HMACEval(userdata.fileMacKey, updateContainer.UpdateList)
			if err != nil {
				return err
			}
			result := userlib.HMACEqual(nodeHMACNew, updateContainer.ListMAC)
			if result == false {
				return errors.New(strings.ToTitle("result does not match hmac"))
			}
			var newUpdateNode UpdateList
			newUpdateNodeMarshal := userlib.SymDec(userdata.fileEncKey, updateContainer.UpdateList)
			err = json.Unmarshal(newUpdateNodeMarshal, &newUpdateNode)
			if err != nil {
				return err
			}
			curr = newUpdateNode.NextUUID
		}
		//iterate to delete all nodes in updatelist
		for i := 0; i < len(nodeUUIDs); i++ {
			userlib.DatastoreDelete(nodeUUIDs[i])
		}
	}

	//generate new UUID
	newHeadUUID := uuid.New()
	newTailUUID := uuid.New()
	fileStruct.UpdateListHead = newHeadUUID
	fileStruct.UpdateListTail = newTailUUID

	//create new Update List for file
	newListNode := UpdateList{Contents: content, NextUUID: newTailUUID}
	newListNodeMarshal, err := json.Marshal(newListNode)
	if err != nil {
		return err
	}
	//compute node hmac and encrypt
	encryptedNewListNode := userlib.SymEnc(userdata.fileEncKey, userlib.RandomBytes(16), newListNodeMarshal)
	newListNodeHMAC, err := userlib.HMACEval(userdata.fileMacKey, encryptedNewListNode)
	if err != nil {
		return err
	}
	newListContainer := UpdateListContainer{UpdateList: encryptedNewListNode, ListMAC: newListNodeHMAC}
	newListContainerMarshal, err := json.Marshal(newListContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(newHeadUUID, newListContainerMarshal)

	//update and store file struct + file container struct
	fileStructMarshal, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	fileStructEnc := userlib.SymEnc(userdata.fileEncKey, userlib.RandomBytes(16), fileStructMarshal)
	//compute new filestruct hmac
	fileStructHMAC, err := userlib.HMACEval(userdata.fileMacKey, fileStructEnc)
	if err != nil {
		return err
	}
	//create new file container or use prexisting
	var fileContainer FileContainer
	if fileExist == true {
		//get preexisting file container
		fileContainerMarshal, ok := userlib.DatastoreGet(containerUUID)
		if ok == false {
			return errors.New(strings.ToTitle("datastore get container uuid not ok"))
		}
		json.Unmarshal(fileContainerMarshal, &fileContainer)
	}
	//create new fileContainer
	if fileExist == false {
		fileContainer = FileContainer{}
	}
	//set values of file container
	fileContainer.FileStruct = fileStructEnc
	fileContainer.FileMAC = fileStructHMAC

	if fileExist == false {
		//encrypt filesymkey using user's rsa public key
		//create new array of user trees
		userRSAPublicKey, ok := userlib.KeystoreGet(userdata.Username + "_RSA")
		if ok == false {
			fmt.Print("dog " + userdata.Username)
			return errors.New(strings.ToTitle(" rsa public key not in keystore"))
		}
		rsaEncryptedFileEncKey, err := userlib.PKEEnc(userRSAPublicKey, userdata.fileEncKey)
		if err != nil {
			return err
		}
		rsaEncryptedFileMacKey, err := userlib.PKEEnc(userRSAPublicKey, userdata.fileMacKey)
		if err != nil {
			return err
		}

		userTreeArray := []UserTree{UserTree{Username: userdata.Username, FileEncKey: rsaEncryptedFileEncKey, FileMacKey: rsaEncryptedFileMacKey}}
		userTreeArrayMarshal, err := json.Marshal(userTreeArray)
		if err != nil {
			return err
		}
		userTreeEnc := userlib.SymEnc(userdata.fileEncKey, userlib.RandomBytes(16), userTreeArrayMarshal)
		userlib.DatastoreSet(containerUUID, userTreeEnc)
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	_, err = GetUserContainer(userdata.Username, userdata.password)
	if err != nil {
		return nil, err
	}
	var fileStruct File
	fileStructptr, err := GetFile(userdata, filename)
	if err != nil {
		return nil, err
	}
	fileStruct = *fileStructptr
	var fileContents []byte
	fileContents = []byte{}
	//iterates through file
	curr := fileStruct.UpdateListHead
	for curr != fileStruct.UpdateListTail {
		updateContainerMarshal, ok := userlib.DatastoreGet(curr)
		var updateContainer UpdateListContainer
		json.Unmarshal(updateContainerMarshal, &updateContainer)
		if ok == false {
			return nil, errors.New(strings.ToTitle("not Ok when trying to get curr"))
		}
		//verify hmac of container
		var updateList UpdateList
		updateListMarshal := userlib.SymDec(userdata.fileEncKey, updateContainer.UpdateList)
		err = json.Unmarshal(updateListMarshal, &updateList)
		if err != nil {
			return nil, err
		}
		fileContents = append(fileContents, updateList.Contents...)
	}
	content = []byte(fileContents)
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Check integrity of caller's user struct
	_, err = GetUserContainer(userdata.Username, userdata.password)
	if err != nil {
		return uuid.Nil, err
	}

	// Check if filename exists in caller's namespace and get file container UUID
	fileContUUID, err := GetFileContUUID(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Check if recipient exists
	recipUUID, err := GetUserID(recipientUsername)
	if err != nil {
		return uuid.Nil, err
	}
	_, ok := userlib.DatastoreGet(recipUUID)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipient username does not exist"))
	}

	// Create invitation
	_, err = GetFile(userdata, filename) // Used to set userdata.fileEnckey
	if err != nil {
		return uuid.Nil, err
	}

	invitation := Invitation{
		FileContainer: fileContUUID,
		FilePK:        userdata.fileEncKey,
	}

	// Encrypt invitation struct with recipient's RSA public key
	recipRSAPK, ok := userlib.KeystoreGet(recipientUsername + "_RSA")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipient RSA public key not found in keystore"))
	}
	invitBytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot marshal invitation bytes"))
	}
	encInvit, err := userlib.PKEEnc(recipRSAPK, invitBytes)

	// Create invitation container
	invitCont := InvitationContainer{
		InvitStruct: encInvit,
	}
	invitCont.Sig, err = userlib.DSSign(userdata.SigSK, invitCont.InvitStruct)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot sign encrypted invitation struct"))
	}

	// Save initation container on datastore
	invitationPtr = uuid.New()
	invitContBytes, err := json.Marshal(invitCont)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot marshal invitation container bytes"))
	}
	userlib.DatastoreSet(invitationPtr, invitContBytes)
	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	// Verify integrity of caller's user struct
	_, err = GetUserContainer(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	// Check if filename exists in caller's namespace
	filePtr, err := GetFilePtr(userdata, filename)
	if err != nil {
		return err
	} else if filePtr != nil {
		return errors.New(strings.ToTitle("filename already exists in caller's namespace"))
	}

	// Check if sender exists
	recipUUID, err := GetUserID(senderUsername)
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(recipUUID)
	if !ok {
		return errors.New(strings.ToTitle("recipient username does not exist"))
	}

	// Get invitation container
	invitContBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("invitation container bytes not found in datastore"))
	}
	var invitCont InvitationContainer
	err = json.Unmarshal(invitContBytes, &invitCont)
	if err != nil {
		return errors.New(strings.ToTitle("cannot unmarshal invitation container bytes"))
	}

	// Verify invitation signature
	verifyKey, ok := userlib.KeystoreGet(senderUsername + "_Sig")
	if !ok {
		return errors.New(strings.ToTitle("sender user's signature publi key not found in keystore"))
	}
	err = userlib.DSVerify(verifyKey, invitCont.InvitStruct, invitCont.Sig)
	if err != nil {
		return errors.New(strings.ToTitle("invitation signiture is invalid"))
	}

	// Create file pointer

	return
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	return nil
}
