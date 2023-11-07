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
	UserStruct []byte // Enc: Local enc key
	UserMAC    []byte // MAC: Local mac key
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

type FilePointerContainer struct {
	FilePtr         []byte
	FilePtrOwnerSig []byte // Signed by owner in RevokeAccess
	FilePtrUserSig  []byte // Signed by user in AcceptInvitation
	FileOwner       string
	FileOwnerSig    []byte // Signed by user in AcceptInvitation
}

type FilePointer struct {
	FileContUUID uuid.UUID
	FileEncKey   []byte // Enc: User's RSA PK
	FileMacKey   []byte // Enc: User's RSA PK
}

type FileContainer struct {
	FileStruct   []byte // Enc: File enc key
	FileMAC      []byte // MAC: File mac key
	UserTreeUUID uuid.UUID
	UserTreeMAC  []byte // MAC: File mac key
}

type File struct {
	FileName       []byte
	UpdateListHead uuid.UUID
	UpdateListTail uuid.UUID
}

type UserTreeContainer struct {
	UserTree    UserTree
	UserTreeMAC []byte // MAC: File mac key
}

type UserTree struct {
	Username string
	Children []UserTreeContainer
	ListAllUsers []string //array of usernames, of all people including those invited but not accepted
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
	FilePtrContainer FilePointerContainer
	Sig              []byte // Sig: Sender's Sig SK
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

// Returns UUID of a FilePtrContainer
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
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot HashKDF source key"))
	}
	key = key[0:16]
	return key, nil
}

// Checks integrity of user struct and returns a UserStruct
func GetUserStruct(username string, password string) (userStruct *User, err error) {
	// Get user container bytes
	userContUUID, err := GetUserID(username)
	if err != nil {
		return nil, err
	}
	userContBytes, ok := userlib.DatastoreGet(userContUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("user container not found in datastore"))
	}

	// Unmarshal user container
	var userCont UserContainer
	err = json.Unmarshal(userContBytes, &userCont)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshal user container bytes"))
	}

	// Check integrity of UserStruct
	macKey, err := GetLocalKey(username, password, "mac")
	if err != nil {
		return nil, err
	}
	currMAC, err := userlib.HMACEval(macKey, userCont.UserStruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot compute HMAC of user struct bytes"))
	}
	equal := userlib.HMACEqual(currMAC, userCont.UserMAC)
	if !equal {
		return nil, errors.New(strings.ToTitle("user struct has been compromised"))
	}

	// Decrypt and unmarshal UserStruct
	decKey, err := GetLocalKey(username, password, "encryption")
	if err != nil {
		return nil, err
	}
	userBytes := userlib.SymDec(decKey, userCont.UserStruct)
	err = json.Unmarshal(userBytes, &userStruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshal user struct"))
	}
	return userStruct, nil
}

// Checks if File exists in user namespace and returns FilePointerContainer bytes if it exists
func GetFilePtrContBytes(username string, filename string) (filePtrContBytes []byte, err error) {
	filePtrContUUID, err := GetFilePtrID(username, filename) //potentially bad since "usernam + efilename" could break it
	if err != nil {
		return nil, err
	}
	filePtrContBytes, ok := userlib.DatastoreGet(filePtrContUUID)
	if !ok {
		return nil, nil
	}
	return filePtrContBytes, nil
}

// Checks integrity of elements in FilePointerContainer and returns FilePointer
func GetFilePointer(userdata *User, filename string, username string) (filePointer *FilePointer, err error) {
	// Get FilePointerContainer
	filePointerContainerMarshal, err := GetFilePtrContBytes(username, filename)
	if err != nil {
		return nil, err
	}
	var filePointerContainer FilePointerContainer
	err = json.Unmarshal(filePointerContainerMarshal, &filePointerContainer)
	if err != nil {
		return nil, err //HERE3
	}

	// Check integrity of FileOwner
	sigUserPK, ok := userlib.KeystoreGet(username + "_Sig")
	if !ok {
		return nil, errors.New(strings.ToTitle("user sig public key not found on keystore"))
	}
	fileOwnerBytes, err := json.Marshal(filePointerContainer.FileOwner)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot marshal owner string"))
	}
	err = userlib.DSVerify(sigUserPK, fileOwnerBytes, filePointerContainer.FileOwnerSig)

	// Check integrity of FilePointer
	ownerVerify := false
	userVerify := false

	if filePointerContainer.FilePtrOwnerSig != nil {
		sigOwnerPK, ok := userlib.KeystoreGet(filePointerContainer.FileOwner + "_Sig")
		if !ok {
			return nil, errors.New(strings.ToTitle("owner sig public key not found on keystore"))
		}
		ownerErr := userlib.DSVerify(sigOwnerPK, filePointerContainer.FilePtr, filePointerContainer.FilePtrOwnerSig)
		if ownerErr == nil {
			ownerVerify = true
		}
	}
	if filePointerContainer.FilePtrUserSig != nil {
		sigUserPK, ok := userlib.KeystoreGet(username + "_Sig")
		if !ok {
			return nil, errors.New(strings.ToTitle("user sig public key not found on keystore"))
		}
		userErr := userlib.DSVerify(sigUserPK, filePointerContainer.FilePtr, filePointerContainer.FilePtrUserSig)
		if userErr == nil {
			userVerify = true
		}
	}
	if !ownerVerify && !userVerify {
		return nil, errors.New(strings.ToTitle("file pointer has been compromised"))
	}

	// Get FilePointer
	var filePointerStruct FilePointer
	err = json.Unmarshal(filePointerContainer.FilePtr, &filePointerStruct)
	if err != nil {
		return nil, err
	}
	filePointer = &filePointerStruct
	return filePointer, nil
}

// Returns UUID of FileContainer
func GetFileContUUID(userdata *User, filename string) (fileCont uuid.UUID, err error) {
	// Get FilePointer
	filePtr, err := GetFilePointer(userdata, filename, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	return filePtr.FileContUUID, nil
}

// Returns file
func GetFile(userdata *User, filename string) (filedataptr *File, err error) {
	//set user's file enc and mac keys
	filePointer, err := GetFilePointer(userdata, filename, userdata.Username)
	if err != nil {
		return nil, err //here2
	}
	userdata.fileEncKey, err = userlib.PKEDec(userdata.RSASK, filePointer.FileEncKey)
	if err != nil {
		return nil, errors.New("noFilePointerError")
	}
	userdata.fileMacKey, err = userlib.PKEDec(userdata.RSASK, filePointer.FileMacKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot decrypt file mac key"))
	}

	//get file container uuid
	fileContUUID := filePointer.FileContUUID

	//get file container
	fileContBytes, ok := userlib.DatastoreGet(fileContUUID)
	if ok == false {
		return nil, errors.New(strings.ToTitle("file container UUID not found"))
	}
	var fileContainer FileContainer
	err = json.Unmarshal(fileContBytes, &fileContainer)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshal file container"))
	}

	//verify file HMAC
	newMAC, err := userlib.HMACEval(userdata.fileMacKey, fileContainer.FileStruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot compute HMAC of filestruct"))
	}
	equals := userlib.HMACEqual(fileContainer.FileMAC, newMAC)
	if equals != true {
		return nil, errors.New(strings.ToTitle("HMAC verify failed for file1")) //HERE
	}

	//decrypt file struct using file symmetric key
	marshalFileStruct := userlib.SymDec(userdata.fileEncKey, fileContainer.FileStruct)
	var filestruct File
	err = json.Unmarshal(marshalFileStruct, &filestruct)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot unmarshall filestruct"))
	}

	filedataptr = &filestruct
	return filedataptr, nil
}

func GetUserTreeFromTreeContainer(userdata *User, treeContainer UserTreeContainer, filename string) (userTree *UserTree, err error) {
	userTreeBytes, err := json.Marshal(treeContainer.UserTree)
	if err != nil {
		return nil, errors.New(strings.ToTitle("unable to marshal tree struct bytes"))
	}

	// Get file mac key from file pointer
	filePtr, err := GetFilePointer(userdata, filename, userdata.Username)
	if err != nil {
		return nil, err
	}

	macKey, err := userlib.PKEDec(userdata.RSASK, filePtr.FileMacKey)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot decrypt file enc key2"))
	}

	// Check mac
	mac, err := userlib.HMACEval(macKey, userTreeBytes)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot compute HMAC of tree node"))
	}
	equal := userlib.HMACEqual(mac, treeContainer.UserTreeMAC)
	if !equal {
		return nil, errors.New(treeContainer.UserTree.Username)
	}

	return &treeContainer.UserTree, nil
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
	userdata := User{
		Username: username,
		Salt:     userlib.RandomBytes(512),
		password: password,
	}

	userdata.PassHash = userlib.Argon2Key([]byte(password), userdata.Salt, 512)

	rsaPK, rsaSK, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot generate RSA keys"))
	}
	userdata.RSASK = rsaSK
	err = userlib.KeystoreSet(username+"_RSA", rsaPK)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot store RSA public key in keystore"))
	}

	sigSK, sigPK, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot generate signature keys"))
	}
	userdata.SigSK = sigSK
	err = userlib.KeystoreSet(username+"_Sig", sigPK)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot store signature public key in keystore"))
	}

	encKey, err := GetLocalKey(username, password, "encryption")
	if err != nil {
		return nil, err
	}
	userdata.encKey = encKey

	macKey, err := GetLocalKey(username, password, "mac")
	if err != nil {
		return nil, err
	}
	userdata.macKey = macKey

	// Create user container
	userBytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot marshal user struct"))
	}
	encUserBytes := userlib.SymEnc(userdata.encKey, userlib.RandomBytes(16), userBytes)
	userMAC, err := userlib.HMACEval(userdata.macKey, encUserBytes)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot compute HMAC of user struct"))
	}
	userCont := UserContainer{
		UserStruct: encUserBytes,
		UserMAC:    userMAC,
	}

	// Place user container on datastore
	userContBytes, err := json.Marshal(userCont)
	if err != nil {
		return nil, errors.New(strings.ToTitle("cannot marshal user container struct"))
	}
	userlib.DatastoreSet(userUUID, userContBytes)

	userdataptr = &userdata
	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Verify integrity of user struct
	userStruct, err := GetUserStruct(username, password)
	if err != nil {
		return nil, err
	}

	// Check password
	givenHash := userlib.Argon2Key([]byte(password), userStruct.Salt, 512)
	if !userlib.HMACEqual(givenHash, userStruct.PassHash) {
		return nil, errors.New(strings.ToTitle("incorrect password"))
	}

	// Set password
	userStruct.password = password

	// Initialize local keys
	encKey, err := GetLocalKey(username, password, "encryption")
	if err != nil {
		return nil, err
	}
	userStruct.encKey = encKey

	macKey, err := GetLocalKey(username, password, "mac")
	if err != nil {
		return nil, err
	}
	userStruct.macKey = macKey

	// Set system's current user to userdata
	return userStruct, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//call verify user
	_, err = GetUserStruct(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	//check if hash(filename) exists already
	fileExist := true
	var containerUUID uuid.UUID

	filePtrBytes, err := GetFilePtrContBytes(userdata.Username, filename)
	if err != nil {
		return err
	} else if filePtrBytes == nil { // Filename does not exist in userspace
		fileExist = false
		containerUUID = uuid.New()
	} else {
		containerUUID, err = GetFileContUUID(userdata, filename)
		if err != nil {
			return err
		}
	}

	var fileStruct File
	if fileExist == false {
		//create new file struct
		fileStruct = File{FileName: []byte(filename)}
		//create new user file enc and filuserlib.RandomBytes(16)e mac keys
		userdata.fileEncKey = userlib.RandomBytes(16)
		userdata.fileMacKey = userlib.RandomBytes(16)

		//create new file pointer container
		//fp struct is encrypted w rsa key instead
		//set file pointer values

		userRSAPublicKey, ok := userlib.KeystoreGet(userdata.Username + "_RSA")
		if ok == false {
			return errors.New(strings.ToTitle("rsa public key not in keystore"))
		}

		encFileEncKey, err := userlib.PKEEnc(userRSAPublicKey, userdata.fileEncKey)
		if err != nil {
			return errors.New(strings.ToTitle("error 1"))
		}

		encFileMACKey, err := userlib.PKEEnc(userRSAPublicKey, userdata.fileMacKey)
		if err != nil {
			return errors.New(strings.ToTitle("error 2"))
		}

		var filePtrStruct = FilePointer{FileContUUID: containerUUID, FileEncKey: encFileEncKey, FileMacKey: encFileMACKey}

		fileptrStructMarshalStruct, err := json.Marshal(filePtrStruct)
		if err != nil {
			return err
		}

		//set file container fields
		filePtrOwnerSig, err := userlib.DSSign(userdata.SigSK, fileptrStructMarshalStruct)
		if err != nil {
			return err
		}
		fileOwner := userdata.Username
		fileOwnerMarshal, err := json.Marshal(fileOwner)
		if err != nil {
			return err
		}

		fileOwnerSig, err := userlib.DSSign(userdata.SigSK, fileOwnerMarshal)
		if err != nil {
			return err
		}

		var newFilePointerContainer = FilePointerContainer{
			FilePtr:         fileptrStructMarshalStruct,
			FileOwner:       fileOwner,
			FileOwnerSig:    fileOwnerSig,
			FilePtrOwnerSig: filePtrOwnerSig}

		newFilePtrUUID, err := GetFilePtrID(userdata.Username, filename)
		if err != nil {
			return err
		}

		//marshal and store file pointer container
		newFilePointerContainerMarshal, err := json.Marshal(newFilePointerContainer)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(newFilePtrUUID, newFilePointerContainerMarshal)

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
				return errors.New(strings.ToTitle("breaking here eGet(filePointerUUID)"))
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
		//create new user tree
		fileContainer.UserTreeUUID = uuid.New()

		//set user tree hmac
		var emptyChildArr []UserTreeContainer

		listAllUsers := []string{userdata.Username}
		var userTreeOwner = UserTree{Username: userdata.Username, Children: emptyChildArr,  ListAllUsers:listAllUsers}

		userTreeUUIDMarshal, err := json.Marshal(fileContainer.UserTreeUUID)
		if err != nil {
			return err
		}
		userTreeMAC, err := userlib.HMACEval(userdata.fileMacKey, userTreeUUIDMarshal)
		if err != nil {
			return err
		}
		fileContainer.UserTreeMAC = userTreeMAC

		userTreeOwnerMarshal, err := json.Marshal(userTreeOwner)
		if err != nil {
			return err
		}
		userTreeOwnerMAC, err := userlib.HMACEval(userdata.fileMacKey, userTreeOwnerMarshal)
		if err != nil {
			return err
		}

		var userTreeContainerOwner = UserTreeContainer{UserTree: userTreeOwner, UserTreeMAC: userTreeOwnerMAC}

		userTreeContainerOwnerMarshal, err := json.Marshal(userTreeContainerOwner)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileContainer.UserTreeUUID, userTreeContainerOwnerMarshal)
	}

	// Store FileContainer on datastore
	fileContainerMarshal, err := json.Marshal(fileContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(containerUUID, fileContainerMarshal)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	_, err := GetUserStruct(userdata.Username, userdata.password)
	if err != nil {
		return err
	}
	fileStruct, err := GetFile(userdata, filename)
	if err != nil {
		return err
	}
	//create new node
	newTailUUID := uuid.New()

	//create new Update List for file
	var newListNode UpdateList
	newListNode = UpdateList{Contents: content, NextUUID: newTailUUID}
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
	//create new list container
	var newListContainer UpdateListContainer
	newListContainer = UpdateListContainer{UpdateList: encryptedNewListNode, ListMAC: newListNodeHMAC}
	newListContainerMarshal, err := json.Marshal(newListContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStruct.UpdateListTail, newListContainerMarshal)
	fileStruct.UpdateListTail = newTailUUID

	//marshal encyrpt file struct
	fileStructMarshal, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	fileStructEnc := userlib.SymEnc(userdata.fileEncKey, userlib.RandomBytes(16), fileStructMarshal)
	fileStructHMAC, err := userlib.HMACEval(userdata.fileMacKey, fileStructEnc)
	if err != nil {
		return err
	}

	//update file container and put it back on datastore
	containerUUID, err := GetFileContUUID(userdata, filename)
	if err != nil {
		return err
	}
	var fileContainer FileContainer
	fileContainerMarshal, ok := userlib.DatastoreGet(containerUUID)
	if ok == false {
		return errors.New(strings.ToTitle("datastore get container uuid not ok"))
	}
	json.Unmarshal(fileContainerMarshal, &fileContainer)
	fileContainer.FileStruct = fileStructEnc
	fileContainer.FileMAC = fileStructHMAC

	fileContainerMarshal, err = json.Marshal(fileContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(containerUUID, fileContainerMarshal)

	fmt.Print(newTailUUID)
	fmt.Print("\n")
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	_, err = GetUserStruct(userdata.Username, userdata.password)
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
		if ok == false {
			return nil, errors.New(strings.ToTitle("not Ok when trying to get curr"))
		}

		var updateContainer UpdateListContainer
		err := json.Unmarshal(updateContainerMarshal, &updateContainer)
		if err != nil {
			return nil, errors.New(strings.ToTitle("filePointerdwadwadContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID)"))
		}
		//verify hmac of container
		nodeHMACNew, err := userlib.HMACEval(userdata.fileMacKey, updateContainer.UpdateList)
		if err != nil {
			return nil, err
		}
		result := userlib.HMACEqual(nodeHMACNew, updateContainer.ListMAC)
		if result == false {
			return nil, errors.New(strings.ToTitle("result does not match hmac"))
		}
		var updateList UpdateList
		updateListMarshal := userlib.SymDec(userdata.fileEncKey, updateContainer.UpdateList)
		err = json.Unmarshal(updateListMarshal, &updateList)
		if err != nil {
			return nil, errors.New(strings.ToTitle("fdwaddwet(filePointerUUID)"))
		}
		fileContents = append(fileContents, updateList.Contents...)
		curr = updateList.NextUUID
	}
	content = []byte(fileContents)
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Check integrity of caller's user struct
	_, err = GetUserStruct(userdata.Username, userdata.password)
	if err != nil {
		return uuid.Nil, err
	}

	// Get caller's file pointer
	ourFilePtr, err := GetFilePointer(userdata, filename, userdata.Username)
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

	// Used to set userdata.fileEnckey
	_, err = GetFile(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Decrypt file enc and mac keys
	fileEncKey, err := userlib.PKEDec(userdata.RSASK, ourFilePtr.FileEncKey)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot decrypt file enc key"))
	}
	fileMACKey, err := userlib.PKEDec(userdata.RSASK, ourFilePtr.FileMacKey)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot decrypt file enc key"))
	}

	// Encrypt file pointer elements with recipient's RSA public key
	recipRSAPK, ok := userlib.KeystoreGet(recipientUsername + "_RSA")
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipient RSA public key not found in keystore"))
	}
	fileEncKeyEnc, err := userlib.PKEEnc(recipRSAPK, fileEncKey)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot encrypt file enc key"))
	}
	fileMacKeyEnc, err := userlib.PKEEnc(recipRSAPK, fileMACKey)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot encrypt file mac key"))
	}

	// Create new file pointer for recipient
	filePtr := FilePointer{
		FileContUUID: ourFilePtr.FileContUUID,
		FileEncKey:   fileEncKeyEnc,
		FileMacKey:   fileMacKeyEnc,
	}
	filePtrBytes, err := json.Marshal(filePtr)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot marshal new file pointer"))
	}

	// Get your file pointer container
	ourFilePtrContUUID, err := GetFileContUUID(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}
	ourFilePtrContBytes, ok := userlib.DatastoreGet(ourFilePtrContUUID)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("our file pointer container not found in datastore"))
	}
	var ourFilePtrCont FilePointerContainer
	err = json.Unmarshal(ourFilePtrContBytes, &ourFilePtrCont)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot unmarshal our file pointer container bytes"))
	}

	// Create new file pointer container for recipient
	filePtrCont := FilePointerContainer{
		FilePtr:         filePtrBytes,
		FilePtrOwnerSig: nil,
		FilePtrUserSig:  nil,
		FileOwner:       ourFilePtrCont.FileOwner,
		FileOwnerSig:    nil,
	}

	// Sign invitation struct
	filePtrContBytes, err := json.Marshal(filePtrCont)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot marshal new file pointer container"))
	}
	invitSig, err := userlib.DSSign(userdata.SigSK, filePtrContBytes)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot sign encrypted invitation struct"))
	}

	// Create invitation container
	invitCont := InvitationContainer{
		FilePtrContainer: filePtrCont,
		Sig:              invitSig,
	}

	// Save initation container on datastore
	invitationPtr = uuid.New()
	invitContBytes, err := json.Marshal(invitCont)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot marshal invitation container bytes"))
	}
	userlib.DatastoreSet(invitationPtr, invitContBytes)


	//get usertree and add to list of invited users in owner's node
	fileContUUID, err := GetFileContUUID(userdata, filename)
	//get file container
	fileContBytes, ok := userlib.DatastoreGet(fileContUUID)
	if ok == false {
		return uuid.Nil, errors.New(strings.ToTitle("file container UUID not found"))
	}
	var fileContainer FileContainer
	err = json.Unmarshal(fileContBytes, &fileContainer)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot unmarshal file container"))
	}

	//verify file HMAC
	newMAC, err := userlib.HMACEval(userdata.fileMacKey, fileContainer.FileStruct)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot compute HMAC of filestruct"))
	}
	equals := userlib.HMACEqual(fileContainer.FileMAC, newMAC)
	if equals != true {
		return uuid.Nil, errors.New(strings.ToTitle("HMAC verify failed for file1")) //HERE
	}

	// Get user tree container
	userTreeContBytes, ok := userlib.DatastoreGet(fileContainer.UserTreeUUID)
	if !ok {
		return  uuid.Nil, errors.New(strings.ToTitle("user tree container not on datastore"))
	}
	var userTreeCont UserTreeContainer
	err = json.Unmarshal(userTreeContBytes, &userTreeCont)
	if err != nil {
		return  uuid.Nil, errors.New(strings.ToTitle("cannot unmarshal user tree container"))
	}
	var userTree = userTreeCont.UserTree
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("cannot compute HMAC of filestruct"))
	}

	var userTreeNew = UserTree{Username: userTree.Username, Children: userTree.Children,  ListAllUsers:userTree.ListAllUsers}
	//userTree.ListAllUsers = append(userTree.ListAllUsers, recipientUsername)
	userTreeCont.UserTree = userTreeNew
	userTreeOwnerMarshalNew, err := json.Marshal(userTreeNew)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("wewewewew"))
	}

	userTreeMacNew, err := userlib.HMACEval(fileMACKey, userTreeOwnerMarshalNew)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("wewewewew"))
	}

	userTreeCont.UserTreeMAC = userTreeMacNew
	userTreeContainerMarshal, err := json.Marshal(userTreeCont)
	if err != nil {
		return uuid.Nil, errors.New(strings.ToTitle("wewewewew"))
	}
	userlib.DatastoreSet(fileContainer.UserTreeUUID, userTreeContainerMarshal)



	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	// Verify integrity of caller's user struct
	_, err = GetUserStruct(userdata.Username, userdata.password)
	if err != nil {
		return err
	}

	// Check if filename exists in caller's namespace
	existingFilePtrBytes, err := GetFilePtrContBytes(userdata.Username, filename)
	if err != nil {
		return err
	} else if existingFilePtrBytes != nil {
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
		return errors.New(strings.ToTitle("sender user's signature public key not found in keystore"))
	}
	filePtrContBytes, err := json.Marshal(invitCont.FilePtrContainer)
	if err != nil {
		return errors.New(strings.ToTitle("cannot marshal file pointer container"))
	}
	err = userlib.DSVerify(verifyKey, filePtrContBytes, invitCont.Sig)
	if err != nil {
		return errors.New(strings.ToTitle("invitation signiture is invalid"))
	}

	// Get file pointer container
	filePtrCont := invitCont.FilePtrContainer

	// Sign elements in file pointer container
	fileSig, err := userlib.DSSign(userdata.SigSK, filePtrCont.FilePtr)
	if err != nil {
		return errors.New(strings.ToTitle("cannot sign file pointer"))
	}
	filePtrCont.FilePtrUserSig = fileSig

	ownerBytes, err := json.Marshal(filePtrCont.FileOwner)
	if err != nil {
		return errors.New(strings.ToTitle("cannot marshal file owner string"))
	}
	ownerSig, err := userlib.DSSign(userdata.SigSK, ownerBytes)
	if err != nil {
		return errors.New(strings.ToTitle("cannot sign file pointer"))
	}
	filePtrCont.FileOwnerSig = ownerSig

	// Store file pointer container on datastore
	filePtrContUUID, err := GetFilePtrID(userdata.Username, filename)
	if err != nil {
		return err
	}
	filePtrContBytes, err = json.Marshal(filePtrCont)
	if err != nil {
		return errors.New(strings.ToTitle("cannot marshal file pointer container"))
	}
	userlib.DatastoreSet(filePtrContUUID, filePtrContBytes)

	// Get file pointer
	filePtr, err := GetFilePointer(userdata, filename, userdata.Username)
	if err != nil {
		return err
	}

	// Get file container
	fileContBytes, ok := userlib.DatastoreGet(filePtr.FileContUUID)
	if !ok {
		return errors.New(strings.ToTitle("file container not found on datastore"))
	}
	var fileCont FileContainer
	err = json.Unmarshal(fileContBytes, &fileCont)
	if err != nil {
		return errors.New(strings.ToTitle("cannot unmarshal file container bytes"))
	}

	// Decrypt file mac key
	fileMACKey, err := userlib.PKEDec(userdata.RSASK, filePtr.FileMacKey)
	if err != nil {
		return errors.New(strings.ToTitle("cannot decrypt file mac key"))
	}

	// Verify integrity of user tree container UUID
	userTreeUUIDBytes, err := json.Marshal(fileCont.UserTreeUUID)
	if err != nil {
		return errors.New(strings.ToTitle("cannot marshal user tree UUID"))
	}
	idMAC, err := userlib.HMACEval(fileMACKey, userTreeUUIDBytes)
	if err != nil {
		return errors.New(strings.ToTitle("cannot compute HMAC of user tree UUID!"))
	}
	equal := userlib.HMACEqual(idMAC, fileCont.UserTreeMAC)
	if !equal {
		return errors.New(strings.ToTitle("user tree UUID has been compromised"))
	}

	// Get user tree container
	userTreeContBytes, ok := userlib.DatastoreGet(fileCont.UserTreeUUID)
	if !ok {
		return errors.New(strings.ToTitle("user tree container not on datastore"))
	}
	var userTreeCont UserTreeContainer
	err = json.Unmarshal(userTreeContBytes, &userTreeCont)
	if err != nil {
		return errors.New(strings.ToTitle("cannot unmarshal user tree container"))
	}

	// Get user tree
	userTree, err := GetUserTreeFromTreeContainer(userdata, userTreeCont, filename)
	if err != nil {
		return err
	}

	// Create user tree node
	var emptyChildArr []UserTreeContainer
	userNode := UserTree{
		Username: userdata.Username,
		Children: emptyChildArr,
	}

	// Create user tree node container
	userNodeBytes, err := json.Marshal(userNode)
	if err != nil {
		return errors.New(strings.ToTitle("cannot marshal user tree node struct"))
	}
	nodeMAC, err := userlib.HMACEval(fileMACKey, userNodeBytes)
	if err != nil {
		return errors.New(strings.ToTitle("cannot sign user tree node struct"))
	}

	userNodeContainer := UserTreeContainer{
		UserTree:    userNode,
		UserTreeMAC: nodeMAC,
	}

	// Add yourself to file's user tree
	if senderUsername == filePtrCont.FileOwner {
		userTree.Children = append(userTree.Children, userNodeContainer)
	} else {
		for i := 0; i < len(userTree.Children); i++ {
			isChild := false

			// Find parent in user tree
			currUserTree := userTree.Children[i].UserTree
			if err != nil {
				return err
			}
			if senderUsername == currUserTree.Username {
				isChild = true
			} else {
				for j := 0; j < len(currUserTree.Children); i++ {
					subUserTree := currUserTree.Children[j].UserTree
					if err != nil {
						return err
					}
					if senderUsername == subUserTree.Username {
						isChild = true
						break
					}
				}
			}

			if isChild {
				currUserTree.Children = append(currUserTree.Children, userNodeContainer)
				break
			}
		}
	}

	// Update user tree on datastore
	newTreeContBytes, err := json.Marshal(userTreeCont)
	if err != nil {
		return errors.New(strings.ToTitle("cannot marshal new user tree container"))
	}
	userlib.DatastoreSet(fileCont.UserTreeUUID, newTreeContBytes)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	// Verify integrity of caller's user struct
	_, err = GetUserStruct(userdata.Username, userdata.password)
	if err != nil {
		return err
	}
	//set user's file keys
	//get file struct
	fileStruct, err := GetFile(userdata, filename)
	if err != nil {
		return err
	}

	newFileEncKey := userlib.RandomBytes(16)
	newFileMacKey := userlib.RandomBytes(16)

	//iterate through file nodes to Re Mac and Re Encrypt everything
	curr := fileStruct.UpdateListHead
	for curr != fileStruct.UpdateListTail {
		// Get update list container
		updateContainerMarshal, ok := userlib.DatastoreGet(curr)
		if ok == false {
			return errors.New(strings.ToTitle("not Ok when trying to get curr"))
		}
		var updateContainer UpdateListContainer
		json.Unmarshal(updateContainerMarshal, &updateContainer)

		//reencrypt
		var updateList UpdateList
		updateListMarshal := userlib.SymDec(userdata.fileEncKey, updateContainer.UpdateList)
		err = json.Unmarshal(updateListMarshal, &updateList)
		if err != nil {
			return err //ERROR HERE
		}

		newNodeEnc := userlib.SymEnc(newFileEncKey, userlib.RandomBytes(16), updateListMarshal)

		//recompute mac
		nodeHMACNew, err := userlib.HMACEval(newFileMacKey, newNodeEnc)
		if err != nil {
			return err
		}

		//reinsert into updatelistcontainer
		updateContainer.UpdateList = newNodeEnc
		updateContainer.ListMAC = nodeHMACNew

		updateContainerMarshal, err = json.Marshal(updateContainer)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(curr, updateContainerMarshal)
		//reupload into datastore
		curr = updateList.NextUUID
	}

	// Remove recipient user and their children from user tree
	//get file container uuid
	fileContUUID, err := GetFileContUUID(userdata, filename)
	if err != nil {
		return err
	}
	//get file container
	fileContBytes, ok := userlib.DatastoreGet(fileContUUID)
	if ok == false {
		return errors.New(strings.ToTitle("file container UUID not found"))
	}

	var fileContainer FileContainer
	err = json.Unmarshal(fileContBytes, &fileContainer)
	if err != nil {
		return errors.New(strings.ToTitle("cannot unmarshal file container"))
	}

	//verify file HMAC
	HMACnew, err := userlib.HMACEval(userdata.fileMacKey, fileContainer.FileStruct)
	if err != nil {
		return errors.New(strings.ToTitle("cannot compute HMAC of filestruct"))
	}
	equals := userlib.HMACEqual(fileContainer.FileMAC, HMACnew)
	if equals != true {
		return errors.New(strings.ToTitle("HMAC verify failed for file2"))
	}

	UserTreeContainerMarshal, ok := userlib.DatastoreGet(fileContainer.UserTreeUUID)
	if ok == false {
		return errors.New(strings.ToTitle("cannot get usertree container"))
	}

	var userTreeContainer UserTreeContainer
	err = json.Unmarshal(UserTreeContainerMarshal, &userTreeContainer)
	if err != nil {
		return errors.New(strings.ToTitle("usertreecontainer not hmac"))
	}

	userTreeOwnerMarshal, err := json.Marshal(userTreeContainer.UserTree)
	if err != nil {
		return err
	}

	//check user tree HMAC
	userTreeHMACCompare, err := userlib.HMACEval(userdata.fileMacKey, userTreeOwnerMarshal)
	if err != nil {
		return err
	}

	equal := userlib.HMACEqual(userTreeHMACCompare, userTreeContainer.UserTreeMAC)
	if equal == false {
		return err
	}

	userTreeOwner, err := GetUserTreeFromTreeContainer(userdata, userTreeContainer, filename)
	if err != nil {
		return err
	}
	//remove from tree
	for i := 0; i < len(userTreeOwner.Children); i++ {
		userTreeUser:= userTreeOwner.Children[i].UserTree
		if err != nil {
			return err
		}
		if userTreeUser.Username == recipientUsername {
			userTreeOwner.Children = append(userTreeOwner.Children[:i], userTreeOwner.Children[i+1:]...)
		}
	}

	userTreeOwnerMarshalNew, err := json.Marshal(userTreeOwner)
	if err != nil {
		return err
	}

	userTreeMacNew, err := userlib.HMACEval(newFileMacKey, userTreeOwnerMarshalNew)
	if err != nil {
		return err
	}

	userTreeContainer.UserTreeMAC = userTreeMacNew
	userTreeContainerMarshal, err := json.Marshal(userTreeContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileContainer.UserTreeUUID, userTreeContainerMarshal)

	//disribute new keys

	//set the owner's file pointer
	ownerFilePointer, err := GetFilePointer(userdata, filename, userdata.Username)
	if err != nil {
		return err
	}
	ownerRSAPK, ok := userlib.KeystoreGet(userdata.Username + "_RSA")
	if ok == false {
		return errors.New(strings.ToTitle("keystore get fail 0"))
	}
	ownerFilePointer.FileEncKey, err = userlib.PKEEnc(ownerRSAPK, newFileEncKey)
	if err != nil {
		return errors.New(strings.ToTitle("error 4"))
	}
	ownerFilePointer.FileMacKey, err = userlib.PKEEnc(ownerRSAPK, newFileMacKey)
	if err != nil {
		return errors.New(strings.ToTitle("error 5"))
	}
	filePointerUUID, err := GetFilePtrID(userdata.Username, filename)
	if err != nil {
		return err
	}

	filePointerContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID)
	if ok == false {
		return errors.New(strings.ToTitle("filePointerContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID)"))
	}

	var filePointerContainer FilePointerContainer
	err = json.Unmarshal(filePointerContainerMarshal, &filePointerContainer)
	if err != nil {
		return errors.New(strings.ToTitle("dwadwdwointerUUID)"))
	}

	ownerFilePointerMarshal, err := json.Marshal(ownerFilePointer)
	if err != nil {
		return err
	}
	filePointerContainer.FilePtr = ownerFilePointerMarshal
	ownerSig, err := userlib.DSSign(userdata.SigSK, filePointerContainer.FilePtr)
	if err != nil {
		return err
	}
	filePointerContainer.FilePtrOwnerSig = ownerSig

	filePointerContainerMarshal, err = json.Marshal(filePointerContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(filePointerUUID, filePointerContainerMarshal)

	//set the second and third level users
	for i := 0; i < len(userTreeOwner.Children); i++ {
		userTreeUser:= userTreeOwner.Children[i].UserTree
		if err != nil {
			return err
		}
		filePointer, err := GetFilePointer(userdata, filename, userTreeUser.Username)

		if err != nil {
			return err
		}
		userRSAPK, ok := userlib.KeystoreGet(userTreeUser.Username + "_RSA")
		if ok == false {
			return errors.New(strings.ToTitle("keystore get fail 1"))
		}

		filePointer.FileEncKey, err = userlib.PKEEnc(userRSAPK, newFileEncKey)
		if err != nil {
			return errors.New(strings.ToTitle("error 6"))
		}
		filePointer.FileMacKey, err = userlib.PKEEnc(userRSAPK, newFileMacKey)
		if err != nil {
			return errors.New(strings.ToTitle("error 7"))
		}
		//add to datastore
		filePointerUUID, err := GetFilePtrID(userTreeUser.Username, filename)
		if err != nil {
			return err
		}

		filePointerContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID)
		if ok == false {
			return errors.New(strings.ToTitle("filePointerContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID) 2"))
		}

		var filePointerContainer FilePointerContainer
		err = json.Unmarshal(filePointerContainerMarshal, &filePointerContainer)
		if err != nil {
			return errors.New(strings.ToTitle("cannot get filePointerContainer from hmac"))
		}

		FilePointerMarshal, err := json.Marshal(filePointer)
		if err != nil {
			return err
		}

		filePointerContainer.FilePtr = FilePointerMarshal
		ownerSig, err := userlib.DSSign(userdata.SigSK, filePointerContainer.FilePtr)
		if err != nil {
			return err
		}
		filePointerContainer.FilePtrOwnerSig = ownerSig

		filePointerContainerMarshal, err = json.Marshal(filePointerContainer)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(filePointerUUID, filePointerContainerMarshal)

		for j := 0; j < len(userTreeUser.Children); j++ {
			userTree3 := userTreeUser.Children[j].UserTree
			if err != nil {
				return err
			}
			filePointer, err := GetFilePointer(userdata, filename, userTree3.Username)
			if err != nil {
				return err
			}
			userRSAPK, ok := userlib.KeystoreGet(userTree3.Username + "_RSA")
			if ok == false {
				return errors.New(strings.ToTitle("keystore get fail 3"))
			}
			filePointer.FileEncKey, err = userlib.PKEEnc(userRSAPK, newFileEncKey)
			if err != nil {
				return errors.New(strings.ToTitle("error 8"))
			}
			filePointer.FileMacKey, err = userlib.PKEEnc(userRSAPK, newFileMacKey)
			if err != nil {
				return errors.New(strings.ToTitle("error 9"))
			}

			//add to datastore
			filePointerUUID, err := GetFilePtrID(userTree3.Username, filename)
			if err != nil {
				return err
			}

			filePointerContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID)
			if ok == false {
				return errors.New(strings.ToTitle("filePointerContainerMarshal, ok := userlib.DatastoreGet(filePointerUUID) 2"))
			}

			var filePointerContainer FilePointerContainer
			err = json.Unmarshal(filePointerContainerMarshal, &filePointerContainer)
			if err != nil {
				return errors.New(strings.ToTitle("cannot unamrshal to filePointerContainer"))
			}

			FilePointerMarshal, err := json.Marshal(filePointer)
			if err != nil {
				return err
			}

			filePointerContainer.FilePtr = FilePointerMarshal
			ownerSig, err := userlib.DSSign(userdata.SigSK, filePointerContainer.FilePtr)
			if err != nil {
				return err
			}
			filePointerContainer.FilePtrOwnerSig = ownerSig

			filePointerContainerMarshal, err = json.Marshal(filePointerContainer)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(filePointerUUID, filePointerContainerMarshal)
		}

	}

	// rencrypt, and remac
	// file struct, each node,

	fileStructMarshal, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}

	fileStructEnc := userlib.SymEnc(newFileEncKey, userlib.RandomBytes(16), fileStructMarshal)
	fileStructMac, err := userlib.HMACEval(newFileMacKey, fileStructEnc)
	if err != nil {
		return errors.New(strings.ToTitle("cannot unmarshal file pointer container 2"))
	}

	fileContainerUUID, err := GetFileContUUID(userdata, filename)
	if err != nil {
		return err
	}

	fileContainerMarshal, ok := userlib.DatastoreGet(fileContainerUUID)
	if ok == false {
		return errors.New(strings.ToTitle("file container UUID not found"))
	}

	var newFileContainer FileContainer
	err = json.Unmarshal(fileContainerMarshal, &newFileContainer)
	if err != nil {
		return errors.New(strings.ToTitle("cannot unmarshal file pointer container 3"))
	}

	newFileContainer.FileStruct = fileStructEnc
	newFileContainer.FileMAC = fileStructMac

	newFileContainerMarshal, err := json.Marshal(newFileContainer)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileContUUID, newFileContainerMarshal)

	return nil
}
