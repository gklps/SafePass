package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gklps/SafePass/aesutils"
	_ "github.com/gklps/SafePass/docs" // Local Swagger docs import
	"github.com/gklps/SafePass/storage"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"            // SQLite driver
	swaggerFiles "github.com/swaggo/files"     // Swagger files
	ginSwagger "github.com/swaggo/gin-swagger" // Swagger UI handler
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/bcrypt" // bcrypt for hashing passwords
)

var db *sql.DB
var jwtSecret = []byte("your-secret-key")

// User struct for JSON response
type User struct {
	ID    int    `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	DID   string `json:"did"`
}

// LoginCredentials represents the request body structure for login
type LoginCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse represents the structure of the response containing the JWT token
type TokenResponse struct {
	Token string `json:"token"`
}

// ErrorResponse represents a generic error message
type ErrorResponse struct {
	Error string `json:"error"`
}

// CreateUserRequest represents the structure for creating a new user
type CreateUserRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Name       string `json:"name"`
	SecretKey  string `json:"secret_key"`
	WalletType string `json:"wallet_type"`
	PublicKey  string `json:"public_key"`
}

// did request
type DIDRequest struct {
	Port       int    `json:"port"`
	SecretKey  string `json:"secret_key"`
	WalletType string `json:"wallet_type"`
	PublicKey  string `json:"public_key"`
}

const (
	Custodial    = "self-custody"
	NonCustodial = "server-custody"
)

// sign request
type SignRequest struct {
	Data      SignReqData `json:"sign_data"`
	DID       string      `json:"did"`
	SecretKey string      `json:"secret_key"`
}

type SignReqData struct {
	ID          string `json:"id"`
	Mode        int    `json:"mode"`
	Hash        string `json:"hash"`
	OnlyPrivKey bool   `json:"only_priv_key"`
}

type SignRespData struct {
	ID        string       `json:"id"`
	Mode      int          `json:"mode"`
	Password  string       `json:"password"`
	Signature DIDSignature `json:"signature"`
}

type PassSignResponse struct {
	DID          string `json:"did"`
	SignRespData `json:"sign_response"`
}

type DIDSignature struct {
	Pixels    []byte
	Signature []byte
}

// transaction request
type TxnRequest struct {
	RubixNodePort string  `json:"port"`
	DID           string  `json:"did"`
	ReceiverDID   string  `json:"receiver"`
	RBTAmount     float64 `json:"rbt_amount"`
}

// request to rubix node
type ReqToRubixNode struct {
	RubixNodePort string `json:"port"`
	DID           string `json:"did"`
}

// generate test RBT request
type GenerateTestRBTRequest struct {
	// RubixNodePort string `json:"port"`
	DID        string `json:"did"`
	TokenCount int    `json:"number_of_tokens"`
}

// create FT request
type CreateFTRequest struct {
	DID        string `json:"did"`
	FTCount    int    `json:"ft_count"`
	FTName     string `json:"ft_name"`
	TokenCount int    `json:"token_count"`
}

// transfer FT request
type TransferFTReq struct {
	Receiver   string `json:"receiver"`
	Sender     string `json:"sender"`
	FTName     string `json:"ft_name"`
	FTCount    int    `json:"ft_count"`
	Comment    string `json:"comment"`
	QuorumType int    `json:"quorum_type"`
	Password   string `json:"password"`
	CreatorDID string `json:"creatorDID"`
}

// peer details struct
type DIDPeerMap struct {
	SelfDID string `json:"self_did"`
	PeerDID string `json:"DID"`
	DIDType int    `json:"DIDType"`
	PeerID  string `json:"PeerID"`
}

// create NFT request
type CreateNFTRequest struct {
	DID          string `json:"did"`
	MetadataPath string `json:"metadata"`
	ArtifactPath string `json:"artifact"`
}

// subscribe NFT request
type SubscribeNFTRequest struct {
	DID string `json:"did"`
	NFT string `json:"nft"`
}

// deploy NFT request
type DeployNFTRequest struct {
	DID        string `json:"did"`
	NFT        string `json:"nft"`
	QuorumType int    `json:"quorum_type"`
}

// execute NFT request
type ExecuteNFTRequest struct {
	DID        string  `json:"owner"`
	NFT        string  `json:"nft"`
	NFTData    string  `json:"nft_data"`
	NFTValue   float64 `json:"nft_value"`
	Receiver   string  `json:"receiver"`
	QuorumType int     `json:"quorum_type"`
	Comment    string  `json:"comment"`
}

type DeploySmartContractRequest struct {
	SmartContractToken string `json:"smartContractToken"`
	DeployerAddr       string `json:"deployerAddr"`
	RBTAmount          int    `json:"rbtAmount"`
	QuorumType         int    `json:"quorumType"`
	Comment            string `json:"comment"`
}

type GenerateSmartContractRequest struct {
	DID            string
	BinaryCodePath string
	RawCodePath    string
	SchemaFilePath string
}

type ExecuteSmartContractRequest struct {
	SmartContractToken string `json:"smartContractToken" binding:"required"`
	ExecutorAddr       string `json:"executorAddr" binding:"required"`
	QuorumType         int    `json:"quorumType" binding:"required"`
	Comment            string `json:"comment" binding:"required"`
	SmartContractData  string `json:"smartContractData" binding:"required"`
}

// subscribe SmartContract request
type SubscribeSmartContractRequest struct {
	DID                string `json:"did"`
	SmartContractToken string `json:"smartContractToken"`
}

// general response by all handlers
type BasicResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Result  interface{} `json:"result"`
}

// @title Wallet API Documentation
// @version 1.0
// @description API documentation for the Wallet application.
// @contact.name API Support
// @contact.email support@example.com
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

func main() {
	var err error
	// Initialize SQLite3 database
	db, err = storage.InitDatabase()
	if err != nil {
		log.Fatal(err)
	}

	InitJWT(db, []byte("RubixBIPWallet"))

	// Initialize JWT with database and secret
	r := gin.Default()
	// CORS middleware to allow Authorization header
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Requested-With"},
		AllowCredentials: true,
		AllowWildcard:    true,
	}))
	r.POST("/login", loginHandler)
	r.POST("/create", createUserHandler)
	r.GET("/profile", authenticate, profileHandler)

	// API endpoints
	//DID features
	r.POST("/create_wallet", createWalletHandler)
	r.POST("/register_did", registerDIDHandler)
	r.POST("/setup_quorum", authenticate, setupQuorumHandler)
	r.POST("/add_peer", addPeerHandler)
	//RBT features
	r.GET("/request_balance", requestBalanceHandler)
	r.POST("/testrbt/create", createTestRBTHandler)
	r.POST("/rbt/unpledge", unpledgeRBTHandler)
	//Txn features
	r.POST("/request_txn", requestTransactionHandler)
	r.GET("/txn/by_did", getTxnByDIDHandler)
	r.POST("/sign", signTransactionHandler)
	r.POST("/pass_signature", PassSignatureHandler)
	//FT features
	r.POST("/create_ft", createFTHandler)
	r.POST("/transfer_ft", transferFTHandler)
	r.GET("/get_all_ft", getAllFTHandler)
	r.GET("/get_ft_chain", getFTChainHandler)
	//NFT features
	r.POST("create_nft", createNFTHandler)
	r.POST("subscribe_nft", subscribeNFTHandler)
	r.POST("deploy_nft", deployNFTHandler)
	r.POST("execute_nft", executeNFTHandler)
	r.GET("get_nft", getNFTHandler)
	r.GET("get_nft_chain", getNFTChainHandler)
	r.GET("get_all_nft", getAllNFTHandler)
	//SmartContract Endpoints
	r.POST("/generate-smart-contract", generateSmartContractHandler)
	r.POST("/deploy-smart-contract", deploySmartContractHandler)
	r.POST("/execute-smart-contract", executeSmartContractHandler)
	r.POST("/subscribe-smart-contract", subscribeSmartContractHandler)

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.Run(":8080")
}

var portCounter = 20000

func getNextPort() int {
	defer func() { portCounter++ }()
	return 20000
}

// check if node is running
func checkPort(port int) bool {
	address := fmt.Sprintf("localhost:%d", port)
	_, err := net.Dial("tcp", address)
	return err == nil
}

// Login handler to authenticate users and issue JWT
// @Summary Login user and get JWT token
// @Description Authenticate user and return a JWT token
// @Tags Auth
// @Accept json
// @Produce json
// @Param credentials body LoginCredentials true "User credentials"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /login [post]
func loginHandler(c *gin.Context) {
	var creds LoginCredentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Retrieve the hashed password and DID from the database for the user
	var storedHashedPassword, storedHashedSecretKey, did string
	var user User
	row := db.QueryRow("SELECT id, email, name, password, secret_key, did FROM walletUsers WHERE email = ?", creds.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Name, &storedHashedPassword, &storedHashedSecretKey, &did)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Compare the entered password with the stored hashed password
	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(creds.Password))
	if err != nil {
		// If the password does not match, return an Unauthorized error
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token using DID as the "sub" claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": did, // Using DID instead of user ID
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
	c.Writer.Write([]byte("\n"))
}

// CreateUser handler to create a new user and return the user profile
// @Summary Create a new user
// @Description Register a new user and store the details in the database
// @Tags User
// @Accept json
// @Produce json
// @Param user body CreateUserRequest true "New user data"
// @Success 201 {object} User
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /create [post]
func createUserHandler(c *gin.Context) {
	var newUser CreateUserRequest
	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if newUser.WalletType != Custodial && newUser.WalletType != NonCustodial {
		newUser.WalletType = NonCustodial
	}

	// Hash the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	// manage wallet type
	hashedSecretKey := make([]byte, 0)
	if newUser.WalletType == NonCustodial {

		// manage the secret key and hash it
		if newUser.SecretKey == "" {
			newUser.SecretKey = newUser.Password
		}
		hashedSecretKey, err = bcrypt.GenerateFromPassword([]byte(newUser.SecretKey), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash secret key"})
			return
		}
	} // else leave the secret key empty

	// Increment the port counter for each new user, until a running port is found
	var port int
	for {
		port = getNextPort()
		if checkPort(port) {
			log.Printf("Found a free port: %d", port)
			break
		}
	}

	// Create the wallet and fetch the DID
	data := DIDRequest{
		Port:       port,
		WalletType: newUser.WalletType,
		SecretKey:  string(hashedSecretKey), // pass secret key to encrypt private key
	}

	// pass the public key, in case of self-custodial wallet
	if newUser.WalletType == Custodial {
		data.SecretKey = ""
		data.PublicKey = newUser.PublicKey
	}

	walletRequest, err := json.Marshal(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error marshaling JSON, " + err.Error()})
		return
	}

	resp, err := http.Post("http://localhost:8080/create_wallet", "application/json", bytes.NewBuffer(walletRequest))
	if err != nil {
		log.Printf("HTTP request error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not connect to wallet service"})
		return
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Unexpected response from /create_wallet: %s", body)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unexpected response from wallet service"})
		return
	}
	defer resp.Body.Close()

	// Read the raw response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read wallet response"})
		return
	}
	if len(body) == 0 {
		log.Printf("Empty response from /create_wallet")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Empty response from wallet service"})
		return
	}

	// Decode the response
	var didResponse struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(body, &didResponse); err != nil {
		log.Printf("JSON Unmarshal error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid wallet response format"})
		return
	}
	if didResponse.DID == "" {
		log.Printf("Received empty DID from /create_wallet")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid DID in wallet response"})
		return
	}

	// Insert new user into the database with DID
	_, err = db.Exec("INSERT INTO walletUsers (email, password, secret_key, name, did) VALUES (?, ?, ?, ?, ?)", newUser.Email, string(hashedPassword), string(hashedSecretKey), newUser.Name, didResponse.DID)
	if err != nil {
		log.Printf("Database insert error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	// Return a response with the created user's data including the DID
	c.JSON(http.StatusCreated, gin.H{
		"email": newUser.Email,
		"name":  newUser.Name,
		"did":   didResponse.DID,
	})
	c.Writer.Write([]byte("\n"))
}

// Middleware to authenticate the user via JWT
// @Summary Authenticate using JWT token
// @Description Authenticate requests with JWT token in Authorization header
// @Tags Auth
// @Accept json
// @Produce json
// @Failure 401 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /profile [get]
func authenticate(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is required"})
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	// Now we can access the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did := claims["sub"].(string)

	// Optionally, you can check the DID in the database
	var user User
	row := db.QueryRow("SELECT id, email, name, did FROM walletUsers WHERE did = ?", did)
	err = row.Scan(&user.ID, &user.Email, &user.Name, &user.DID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DID"})
		c.Abort()
		return
	}

	// Store the user DID in the context for downstream handlers
	c.Set("userDID", did)
	c.Next()
}

// Profile handler to return user profile information
// @Summary Get user profile by DID
// @Description Fetch user information from the database using the JWT token
// @Tags User
// @Accept json
// @Produce json
// @Success 200 {object} User
// @Failure 500 {object} ErrorResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /profile [get]
func profileHandler(c *gin.Context) {
	// Extract the DID from the token
	tokenString := c.GetHeader("Authorization")[7:] // Strip "Bearer "
	token, _ := jwt.Parse(tokenString, nil)
	claims := token.Claims.(jwt.MapClaims)

	// Use string assertion for DID, since it's a string
	did, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token: missing or invalid DID"})
		return
	}

	// Fetch user info from database using DID
	var user User
	row := db.QueryRow("SELECT id, email, name, did FROM walletUsers WHERE did = ?", did)
	err := row.Scan(&user.ID, &user.Email, &user.Name, &user.DID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// Initialize JWT module with database connection and secret
func InitJWT(database *sql.DB, secret []byte) {
	if db == nil {
		log.Println("Database connection in InitJWT is nil")
	} else {
		log.Println("JWT initialized with database connection")
	}

	db = database
	jwtSecret = secret
}

// generate JWT
func GenerateJWT(did string, receiverDID string, amount float64) (string, error) {
	claims := jwt.MapClaims{
		"did":          did,
		"receiver_did": receiverDID,
		"rbt_amount":   amount,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// define token header
	token.Header["alg"] = "HS256"
	token.Header["typ"] = "JWT"

	//get the signed token
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	// Save token to database
	_, err = db.Exec(
		"INSERT INTO jwt_tokens (did, token, issued_at, expires_at) VALUES (?, ?, ?, ?)",
		did, tokenString, claims["iat"], claims["exp"],
	)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Verify JWT token using public key
func VerifyToken(tokenString string, publicKey *ecdsa.PublicKey) (bool, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is ECDSA
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		log.Printf("failed to parse jwt")
		return false, nil, err
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, claims, nil
	}

	return false, nil, fmt.Errorf("invalid token")
}

// @Summary Create a new key pair
// @Description Generates a key pair and assigns a DID
// @Tags DID
// @Accept json
// @Produce json
// @Param request body DIDRequest true "Port for DID request and secret key"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /create_wallet [post]
func createWalletHandler(c *gin.Context) {
	var req DIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input, " + err.Error()})
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	var entropy []byte
	var mnemonic, pubKeyStr, encryptedPrivateKey string
	var err error

	// handle wallet types
	if req.WalletType == NonCustodial {
		// Generate mnemonic and derive key pair
		entropy, _ = bip39.NewEntropy(128)
		mnemonic, _ = bip39.NewMnemonic(entropy)
		privateKey, publicKey := generateKeyPair(mnemonic)

		// encrypt private key to store
		privKeyStr := hex.EncodeToString(privateKey.Serialize())
		encryptedPrivateKey, err = aesutils.EncryptPrivateKey(privKeyStr, req.SecretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt private key, " + err.Error()})
			c.Writer.Write([]byte("\n"))
			return
		}

		pubKeyStr = hex.EncodeToString(publicKey.SerializeUncompressed())
	} else {
		pubKeyStr = req.PublicKey
	}

	fmt.Println("public key str:", pubKeyStr)

	// Request user DID from Rubix node
	did, err := didRequest(pubKeyStr, strconv.Itoa(req.Port))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid request, " + err.Error()})
		fmt.Println(err)
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	// Save user to database
	err = storage.InsertUser(did, req.WalletType, pubKeyStr, encryptedPrivateKey, mnemonic, req.Port)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user data, " + err.Error()})
		// Add a newline to the response body
		c.Writer.Write([]byte("\n"))
		return
	}

	// Respond with DID
	c.JSON(http.StatusOK, gin.H{"did": did})
	// Add a newline to the response body
	c.Writer.Write([]byte("\n"))
}

// @Summary Register DID
// @Description Publishes the user's DID in the network
// @Tags DID
// @Accept json
// @Produce json
// @Param request body ReqToRubixNode true "DID"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /register_did [post]
func registerDIDHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input"
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := registerDIDRequest(did, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// @Summary Setup Quorum
// @Description sets up the DID to be a quorum and to pledge
// @Tags DID
// @Accept json
// @Produce json
// @Param request body ReqToRubixNode true "DID"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /setup_quorum [post]
func setupQuorumHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input"
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := setupQuorumRequest(req.DID, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = resp
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// registerDIDRequestsends request to rubix node to publish the did info in the network
func setupQuorumRequest(did string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"did":           did,
		"priv_password": "mypassword",
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/setup-quorum", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("failed to setup quorum, %s", respMsg)
	}

	return respMsg, nil
}

// @Summary Add peer to a DID quorum
// @Description Adds a new peer to the quorum of a user's DID
// @Tags DID
// @Accept json
// @Produce json
// @Param request body DIDPeerMap true "Peer details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /add_peer [post]
func addPeerHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req DIDPeerMap
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.SelfDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := addPeerRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = resp
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// addPeerRequest request to rubix node to publish the did info in the network
func addPeerRequest(data DIDPeerMap, rubixNodePort string) (string, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/add-peer-details", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("failed to add peer, %s", respMsg)
	}

	return respMsg, nil
}

// @Summary Sign a transaction
// @Description Signs a transaction for a user
// @Tags Txn
// @Accept json
// @Produce json
// @Param request body SignRequest true "Transaction signing request"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Router /sign [post]
func signTransactionHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusNotFound, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	signature := make([]byte, 0)
	switch user.WalletType {
	case NonCustodial:
		signature, err = ServerCustodialSign(user, req.Data.Hash)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			c.Writer.Write([]byte("\n"))
			return
		}
	case Custodial:
		result := make(map[string]interface{})
		result["did"] = req.DID
		result["result"] = req.Data
		basicResponse.Status = true
		basicResponse.Message = "Signature needed"
		basicResponse.Result = result
		c.JSON(http.StatusOK, basicResponse)
		c.Writer.Write([]byte("\n"))
		return

	default:
		basicResponse.Message = "invalid user wallet type"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// sign response
	signResp := SignRespData{
		ID:   req.Data.ID,
		Mode: req.Data.Mode,
		Signature: DIDSignature{
			Signature: signature,
		},
	}
	resp, err := signResponse(signResp, user.Port)
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string)
	basicResponse.Result = resp["result"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// sign, when keys are managed by server
func ServerCustodialSign(user *storage.User, data string) ([]byte, error) {
	// Retrieve the hashed secret key from the database for the user
	var storedHashedSecretKey string
	var userInfo User
	row := db.QueryRow("SELECT id, secret_key FROM walletUsers WHERE did = ?", user.DID)
	err := row.Scan(&userInfo.ID, &storedHashedSecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret key of user, " + err.Error())
	}

	// decrypt the encrypted private key
	decryptedPrivateKey, err := aesutils.DecryptPrivateKey(user.PrivateKey, storedHashedSecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key, " + err.Error())
	}

	// fmt.Println("private key: ", decryptedPrivateKey)
	// fmt.Println("public key:", &user.PublicKey)
	// fmt.Println("msg", data)

	// Decode private key
	privKeyBytes, err := hex.DecodeString(decryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key," + err.Error())
	}

	privateKey := secp256k1.PrivKeyFromBytes(privKeyBytes)

	// Decode the Base64 string to byte array
	dataBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("Error decoding Base64 string, " + err.Error())
	}

	signature, err := signData(privateKey.ToECDSA(), dataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign, " + err.Error())
	}

	// Verify signature
	if !verifySignature(user.PublicKey, dataBytes, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	return signature, nil
}

// @Summary pass signature manually
// @Description passes the user signature to the rubix node
// @Tags Txn
// @Accept json
// @Produce json
// @Param request body PassSignResponse true "Signature Response"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Router /pass_signature [post]
func PassSignatureHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var signResp PassSignResponse
	if err := c.ShouldBindJSON(&signResp); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := signResponse(signResp.SignRespData, user.Port)
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string) // if the mesaage says "Signature needed" the user should
	basicResponse.Result = resp["result"]            // provide the signature again on the hash provided under result
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))

}

// callSignHandler
func callSignHandler(response map[string]interface{}, did string) (string, error) {
	respResult := response["result"].(map[string]interface{})
	hashStr := respResult["hash"].(string)
	id := respResult["id"].(string)
	mode := respResult["mode"].(float64)

	// prepare sign request
	signReq := SignRequest{
		DID: did,
		Data: SignReqData{
			ID:          id,
			Mode:        int(mode),
			Hash:        hashStr,
			OnlyPrivKey: true,
		},
	}

	// signature response
	bodyJSON, err := json.Marshal(signReq)
	if err != nil {
		fmt.Println("error marshalling:", err.Error())
		return "", err
	}

	resp, err := http.Post("http://localhost:8080/sign", "application/json", bytes.NewBuffer(bodyJSON))
	if err != nil {
		log.Printf("HTTP request error: %v", err)
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Unexpected response from /sign: %s", body)
		return "", fmt.Errorf("Unexpected response from /sign: %s", body)
	}
	defer resp.Body.Close()

	// Read the raw response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return "", err
	}

	if len(body) == 0 {
		return "", fmt.Errorf("empty response from /sign")
	}

	// Parse the response into a map
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return "", err
	}

	respMsg := result["message"].(string)

	// sign again, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(result, did)
	}

	return fmt.Sprintf("%s", respMsg), nil
}

// @Summary Request a transaction
// @Description Initiates a transaction between two DIDs
// @Tags Txn
// @Accept json
// @Produce json
// @Param request body TxnRequest true "Transaction details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /request_txn [post]
func requestTransactionHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req TxnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	jwtToken, err := GenerateJWT(req.DID, req.ReceiverDID, req.RBTAmount)
	if err != nil {
		basicResponse.Message = "Failed to generate JWT, " + err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	isValid, claims, err := VerifyToken(jwtToken, user.PublicKey.ToECDSA())
	if !isValid {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response := SendAuthRequest(jwtToken, strconv.Itoa(user.Port))

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// @Summary Get RBT balance
// @Description Retrieves the RBT balance for a user
// @Tags RBT
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /request_balance [get]
func requestBalanceHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	result, err := RequestBalance(did, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = result["status"].(bool)
	basicResponse.Message = result["message"].(string)
	basicResponse.Result = result["account_info"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// @Summary Create test RBT tokens
// @Description Creates test RBT tokens for a user
// @Tags RBT
// @Accept json
// @Produce json
// @Param request body GenerateTestRBTRequest true "Request to generate test RBTs"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /testrbt/create [post]
func createTestRBTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req GenerateTestRBTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := GenerateTestRBT(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// @Summary Get transactions by DID
// @Description Fetches all transactions involving the specified DID
// @Tags Txn
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Param role query string false "Role in the transaction (e.g., sender, receiver)"
// @Param startDate query string false "Start date for filtering transactions"
// @Param endDate query string false "End date for filtering transactions"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /txn/by_did [get]
func getTxnByDIDHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User nopt found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	role := c.Query("role")
	startDate := c.Query("StartDate")
	endDate := c.Query("EndDate")

	result, err := RequestTxnsByDID(did, role, startDate, endDate, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = result["status"].(bool)
	basicResponse.Message = result["message"].(string)
	basicResponse.Result = result["TxnDetails"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Generate secp256k1 key pair from mnemonic
func generateKeyPair(mnemonic string) (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := secp256k1.PrivKeyFromBytes(seed[:32])
	publicKey := privateKey.PubKey()
	return privateKey, publicKey
}

// send DID request to rubix node
func didRequest(pubKeyStr string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"public_key": pubKeyStr,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:20000/api/request-did-for-pubkey")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respDID, ok := response["did"].(string)
	if !ok {
		fmt.Println("Missing did in the response")
		return "", fmt.Errorf("missing did in the response")
	}

	return respDID, nil
}

// SendAuthRequest sends a JWT authentication request to the Rubix node
func SendAuthRequest(jwtToken string, rubixNodePort string) map[string]interface{} {
	authURL := fmt.Sprintf("http://localhost:%s/api/send-jwt-from-wallet", rubixNodePort)
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
		return nil
	}

	// Add headers
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
		return nil
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
		return nil
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return nil
	}

	return response
}

// Sign data using secp256k1 private key
func signData(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	//use sign function from crypto library
	signature, err := privateKey.(crypto.Signer).Sign(rand.Reader, data, crypto.SHA3_256)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
		return nil, err
	}

	// return signature, signedData
	return signature, nil
}

// respond to signResponse API in Rubix with signature
func signResponse(data SignRespData, rubixNodePort int) (map[string]interface{}, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/signature-response", strconv.Itoa(rubixNodePort))
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("%s", respMsg)
	}

	return response, nil
}

// verifySignature verifies the signature using the public key.
func verifySignature(publicKey *secp256k1.PublicKey, data []byte, signature []byte) bool {
	pubKey := publicKey.ToECDSA()

	// Verify the signature using ECDSA's VerifyASN1 function.
	isValid := ecdsa.VerifyASN1(pubKey, data, signature)

	return isValid
}

// RequestBalance sends request to Rubix node to provide RBT balance info
func RequestBalance(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-account-info?did=%s", rubixNodePort, did)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// GenerateTestRBT sends request to generate test RBTs for userd
func GenerateTestRBT(data GenerateTestRBTRequest, rubixNodePort string) (map[string]interface{}, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/generate-test-token", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("test token generation failed, %s", respMsg)
	}

	return response, nil
}

// RequestTxnsByDID sends request to Rubix node to provide list of all Txns involving the DID
func RequestTxnsByDID(did string, role string, startDate string, endDate string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-by-did?DID=%s&Role=%s&StartDate=%s&EndDate=%s", rubixNodePort, did, role, "", "")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// registerDIDRequestsends request to rubix node to publish the did info in the network
func registerDIDRequest(did string, rubixNodePort string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"did": did,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/register-did", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return nil, err
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("register did failed, %s", respMsg)
	}

	return response, nil
}

// @Summary Unpledge RBT tokens
// @Description Unpledges RBT tokens for a user
// @Tags RBT
// @Accept json
// @Produce json
// @Param request body ReqToRubixNode true "Request to unpledge RBTs"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /rbt/unpledge [post]
func unpledgeRBTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := unpledgeRBTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = resp
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// unpledgeRBTRequest sends request to unpledge pledged RBTs
func unpledgeRBTRequest(data ReqToRubixNode, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/run-unpledge", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("failed to unpledge RBTs, %s", respMsg)
	}

	return respMsg, nil
}

// FT Handlers
// @Summary Create fungible tokens
// @Description Creates fungible tokens for a user
// @Tags FT
// @Accept json
// @Produce json
// @Param request body CreateFTRequest true "Fungible token creation details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /create_ft [post]
func createFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req CreateFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := createFTReq(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// createFTReq requests the rubix node to create FTs
func createFTReq(data CreateFTRequest, rubixNodePort string) (map[string]interface{}, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	log.Println("port in str:", rubixNodePort)
	url := fmt.Sprintf("http://localhost:%s/api/create-ft", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("FT generation failed, %s", respMsg)
	}

	return response, nil
}

// @Summary Transfer fungible tokens
// @Description Transfers fungible tokens from one user to another
// @Tags FT
// @Accept json
// @Produce json
// @Param request body TransferFTReq true "Fungible token transfer details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /transfer_ft [post]
func transferFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req TransferFTReq
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.Sender != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := transferFTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// transferFTRequest sends request to transfer FTs
func transferFTRequest(data TransferFTReq, rubixNodePort string) (map[string]interface{}, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/initiate-ft-transfer", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respStatus := response["status"].(bool)
	respMsg := response["message"].(string)

	if !respStatus {
		return nil, fmt.Errorf("failed to transfer FT, %s", respMsg)
	}

	return response, nil
}

// @Summary Get all fungible tokens
// @Description Retrieves all fungible tokens for a user
// @Tags FT
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /get_all_ft [get]
func getAllFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := getAllFTRequest(did, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	// prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string)
	basicResponse.Result = resp["ft_info"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getAllFTRequest sends request to Rubix node to provide all FTs' info
func getAllFTRequest(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-ft-info-by-did?did=%s", rubixNodePort, did)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// @Summary Get fungible token chain
// @Description Retrieves the chain of a specific fungible token
// @Tags FT
// @Accept json
// @Produce json
// @Param tokenID query string true "Token ID"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /get_ft_chain [get]
func getFTChainHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	tokenID := c.Query("tokenID")

	if tokenID == "" {
		basicResponse.Message = "Missing required parameter: tokenID"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := getFTChainRequest(tokenID, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	//prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string)
	basicResponse.Result = resp["TokenChainData"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getFTChainRequest sends request to Rubix node to provide FT chain
func getFTChainRequest(tokenID string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-ft-token-chain?tokenID=%s", rubixNodePort, tokenID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// NFT Handlers

// @Summary Create a non-fungible token
// @Description Creates a new NFT with metadata and artifact
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body CreateNFTRequest true "NFT creation details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /create_nft [post]
func createNFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req CreateNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := createNFTReq(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = resp
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// createFTReq requests the rubix node to create FTs
func createNFTReq(data CreateNFTRequest, rubixNodePort string) (string, error) {
	// Create a buffer to hold the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add the "did" field
	err := writer.WriteField("did", data.DID)
	if err != nil {
		fmt.Println("Error adding DID field:", err)
		return "", err
	}

	// Add the "metadata" file
	metadataFile, err := os.Open(data.MetadataPath)
	if err != nil {
		fmt.Println("Error opening metadata file:", err)
		return "", err
	}
	defer metadataFile.Close()

	metadataPart, err := writer.CreateFormFile("metadata", data.MetadataPath)
	if err != nil {
		fmt.Println("Error creating metadata form file:", err)
		return "", err
	}

	_, err = io.Copy(metadataPart, metadataFile)
	if err != nil {
		fmt.Println("Error copying metadata file:", err)
		return "", err
	}

	// Add the "artifact" file
	artifactFile, err := os.Open(data.ArtifactPath)
	if err != nil {
		fmt.Println("Error opening artifact file:", err)
		return "", err
	}
	defer artifactFile.Close()

	artifactPart, err := writer.CreateFormFile("artifact", data.ArtifactPath)
	if err != nil {
		fmt.Println("Error creating artifact form file:", err)
		return "", err
	}

	_, err = io.Copy(artifactPart, artifactFile)
	if err != nil {
		fmt.Println("Error copying artifact file:", err)
		return "", err
	}

	// Close the writer to finalize the form data
	err = writer.Close()
	if err != nil {
		fmt.Println("Error finalizing form data:", err)
		return "", err
	}

	// Prepare the HTTP request
	url := fmt.Sprintf("http://localhost:%s/api/create-nft", rubixNodePort)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("failed to create NFT, %s", respMsg)
	}

	return respMsg, nil
}

// @Summary Subscribe to an NFT
// @Description Subscribes a user to an NFT
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body SubscribeNFTRequest true "NFT subscription details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /subscribe_nft [post]
func subscribeNFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req SubscribeNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := subscribeNFTRequest(req.NFT, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// preapre response
	basicResponse.Status = true
	basicResponse.Message = resp
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// subscribeNFTRequest sends request to subscribe NFT
func subscribeNFTRequest(nft string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"nft": nft,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/subscribe-nft", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("failed to subscribe NFT, %s", respMsg)
	}

	return respMsg, nil
}

// @Summary Deploy an NFT
// @Description Deploys an NFT to the blockchain
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body DeployNFTRequest true "NFT deployment details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /deploy_nft [post]
func deployNFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req DeployNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := deployNFTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// deployNFTRequest sends request to deploy NFT
func deployNFTRequest(data DeployNFTRequest, rubixNodePort string) (map[string]interface{}, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/deploy-nft", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("failed to deploy NFT, %s", respMsg)
	}

	return response, nil
}

// @Summary Execute an NFT
// @Description Executes an NFT transaction
// @Tags NFT
// @Accept json
// @Produce json
// @Param request body ExecuteNFTRequest true "NFT execution details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /execute_nft [post]
func executeNFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req ExecuteNFTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := executeNFTRequest(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, did)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// executeNFTRequest sends request to execute NFT
func executeNFTRequest(data ExecuteNFTRequest, rubixNodePort string) (map[string]interface{}, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/execute-nft", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("failed to execute NFT, %s", respMsg)
	}

	return response, nil
}

// @Summary Get NFT details
// @Description Retrieves details of a specific NFT
// @Tags NFT
// @Accept json
// @Produce json
// @Param nft query string true "NFT ID"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /get_nft [get]
func getNFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	nft := c.Query("nft")

	if nft == "" {
		basicResponse.Message = "Missing required parameter: nft"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := getNFTRequest(nft, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string)
	basicResponse.Result = resp["result"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getNFTRequest sends request to Rubix node to provide NFT info
func getNFTRequest(nft string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/fetch-nft?nft=%s", rubixNodePort, nft)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// @Summary Get NFT chain
// @Description Retrieves the chain of a specific NFT
// @Tags NFT
// @Accept json
// @Produce json
// @Param nft query string true "NFT ID"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /get_nft_chain [get]
func getNFTChainHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	nft := c.Query("nft")

	if nft == "" {
		basicResponse.Message = "Missing required parameter: tokenID"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	latest := c.Query("latest")

	resp, err := getNFTChainRequest(nft, latest, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	//prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string)
	basicResponse.Result = resp["NFTDataReply"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getNFTChainRequest sends request to Rubix node to provide NFT chain
func getNFTChainRequest(nft string, latest string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-nft-token-chain-data?nft=%s&latest=%s", rubixNodePort, nft, latest)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// @Summary Get all NFTs
// @Description Retrieves all NFTs for a user
// @Tags NFT
// @Accept json
// @Produce json
// @Param did query string true "DID of the user"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /get_all_nft [get]
func getAllNFTHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	userDID := c.Query("did")

	if userDID == "" {
		basicResponse.Message = "Missing required parameter: did"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if userDID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := getAllNFTRequest(did, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = resp["status"].(bool)
	basicResponse.Message = resp["message"].(string)
	basicResponse.Result = resp["nfts"]
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// getAllNFTRequest sends request to Rubix node to provide all NFTs' info
func getAllNFTRequest(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-nfts-by-did?did=%s", rubixNodePort, did)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// Smart Contract Handlers
// @Summary Deploy a smart contract
// @Description Deploys a smart contract to the Rubix network
// @Tags SmartContract
// @Accept json
// @Produce json
// @Param rubixNodePort query string true "Rubix node port"
// @Param request body DeploySmartContractRequest true "Smart contract deployment details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /deploy-smart-contract [post]
func deploySmartContractHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// rubixNodePort := c.Query("rubixNodePort")
	// if rubixNodePort == "" {
	// 	basicResponse.Message = "Rubix node port is required"
	// 	c.JSON(http.StatusBadRequest, basicResponse)
	// 	c.Writer.Write([]byte("\n"))
	// 	return
	// }

	var req DeploySmartContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	user, err := storage.GetUserByDID(req.DeployerAddr)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := deploySmartContractReq(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, req.DeployerAddr)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	//prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	c.Writer.Write([]byte("\n"))
}

// deploySmartContractReq requests the Rubix node to deploy a smart contract
func deploySmartContractReq(data DeploySmartContractRequest, rubixNodePort string) (map[string]interface{}, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/deploy-smart-contract", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return nil, err
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("smart contract deployment failed: %s", respMsg)
	}

	return response, nil
}

// @Summary Generate a smart contract
// @Description Generates a smart contract using binary code, raw code, and schema files
// @Tags SmartContract
// @Accept multipart/form-data
// @Produce json
// @Param rubixNodePort query string true "Rubix node port"
// @Param did formData string true "DID for the smart contract"
// @Param binaryCodePath formData file true "Binary code file"
// @Param rawCodePath formData file true "Raw code file"
// @Param schemaFilePath formData file true "Schema file"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /generate-smart-contract [post]
func generateSmartContractHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	err = c.Request.ParseMultipartForm(10 << 20) // Limit to 10 MB
	if err != nil {
		basicResponse.Message = "Unable to parse form data, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Save the files to the server's file system
	binaryFile, _, err := c.Request.FormFile("binaryCodePath")
	if err != nil {
		basicResponse.Message = "Error reading binary file, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	defer binaryFile.Close()

	rawFile, _, err := c.Request.FormFile("rawCodePath")
	if err != nil {
		basicResponse.Message = "Error reading raw file"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	defer rawFile.Close()

	schemaFile, _, err := c.Request.FormFile("schemaFilePath")
	if err != nil {
		basicResponse.Message = "Error reading schema file"
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	defer schemaFile.Close()

	// Create a directory to save the files
	saveDir := "./uploads"
	os.MkdirAll(saveDir, os.ModePerm)

	uniqueID := uuid.New().String()
	// Create unique file paths using UUIDs
	binaryFilePath := filepath.Join(saveDir, fmt.Sprintf("%s_binaryCodePath", uniqueID))
	rawFilePath := filepath.Join(saveDir, fmt.Sprintf("%s_rawCodePath", uniqueID))
	schemaFilePath := filepath.Join(saveDir, fmt.Sprintf("%s_schemaFilePath", uniqueID))

	binaryOut, err := os.Create(binaryFilePath)
	if err != nil {
		basicResponse.Message = "Error saving baniry file"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	defer binaryOut.Close()
	_, err = io.Copy(binaryOut, binaryFile)
	if err != nil {
		basicResponse.Message = "Error saving binary file"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	rawOut, err := os.Create(rawFilePath)
	if err != nil {
		basicResponse.Message = "Error saving raw file"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	defer rawOut.Close()
	_, err = io.Copy(rawOut, rawFile)
	if err != nil {
		basicResponse.Message = "Error saving raw file"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	schemaOut, err := os.Create(schemaFilePath)
	if err != nil {
		basicResponse.Message = "Error saving schema file"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}
	defer schemaOut.Close()
	_, err = io.Copy(schemaOut, schemaFile)
	if err != nil {
		basicResponse.Message = "Error saving schema file"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Call the Rubix node to generate the smart contract
	data := GenerateSmartContractRequest{
		DID:            c.PostForm("did"),
		BinaryCodePath: binaryFilePath,
		RawCodePath:    rawFilePath,
		SchemaFilePath: schemaFilePath,
	}

	// get user details by did
	user, err := storage.GetUserByDID(data.DID)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Trigger Rubix Node call
	respMsg, err := generateSmartContractReq(data, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = "Error generating smart contract"
		c.JSON(http.StatusInternalServerError, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Respond with the paths or stream the files back to the client
	basicResponse.Status = true
	basicResponse.Message = respMsg // This will be the response from Rubix node
	basicResponse.Result = map[string]interface{}{
		"binaryFilePath": binaryFilePath,
		"rawFilePath":    rawFilePath,
		"schemaFilePath": schemaFilePath,
	}
	c.JSON(http.StatusOK, basicResponse)
	c.Writer.Write([]byte("\n"))

	// Stream the files back to the client (if required)
	// c.File(binaryFilePath) // Example of sending the binary file back
	// Similarly, you can stream rawFilePath or schemaFilePath if needed.
}

// generateSmartContractReq requests the Rubix node to generate a smart contract
func generateSmartContractReq(data GenerateSmartContractRequest, rubixNodePort string) (string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add DID
	if err := writer.WriteField("did", data.DID); err != nil {
		log.Printf("Error adding DID field: %v", err)
		return "", err
	}

	// Handle Binary File
	log.Println("Binary file path:", data.BinaryCodePath)
	binaryFile, err := os.Open(data.BinaryCodePath)
	if err != nil {
		log.Printf("Failed to open binary file at path: %s, Error: %v", data.BinaryCodePath, err)
		return "", fmt.Errorf("Error opening binary file: %v", err)
	}
	defer binaryFile.Close()

	binaryPart, err := writer.CreateFormFile("binaryCodePath", data.BinaryCodePath)
	if err != nil {
		log.Printf("Error creating binary file part: %v", err)
		return "", err
	}
	_, err = io.Copy(binaryPart, binaryFile)
	if err != nil {
		log.Printf("Error copying binary file: %v", err)
		return "", err
	}

	// Handle Raw Code File
	rawFile, err := os.Open(data.RawCodePath)
	if err != nil {
		log.Printf("Failed to open raw file at path: %s, Error: %v", data.RawCodePath, err)
		return "", err
	}
	defer rawFile.Close()

	rawPart, err := writer.CreateFormFile("rawCodePath", data.RawCodePath)
	if err != nil {
		log.Printf("Error creating raw file part: %v", err)
		return "", err
	}
	_, err = io.Copy(rawPart, rawFile)
	if err != nil {
		log.Printf("Error copying raw file: %v", err)
		return "", err
	}

	// Handle Schema File
	schemaFile, err := os.Open(data.SchemaFilePath)
	if err != nil {
		log.Printf("Failed to open schema file at path: %s, Error: %v", data.SchemaFilePath, err)
		return "", err
	}
	defer schemaFile.Close()

	schemaPart, err := writer.CreateFormFile("schemaFilePath", data.SchemaFilePath)
	if err != nil {
		log.Printf("Error creating schema file part: %v", err)
		return "", err
	}
	_, err = io.Copy(schemaPart, schemaFile)
	if err != nil {
		log.Printf("Error copying schema file: %v", err)
		return "", err
	}

	// Finalize the writer (close it)
	err = writer.Close()
	if err != nil {
		log.Printf("Error closing multipart writer: %v", err)
		return "", err
	}

	log.Printf("Generated smart contract request: %v", data)
	// Create the HTTP request
	url := fmt.Sprintf("http://localhost:%s/api/generate-smart-contract", rubixNodePort)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Printf("Error creating HTTP request: %v", err)
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending HTTP request: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	// Read and process the response
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return "", err
	}

	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		log.Printf("Error unmarshaling response: %v", err)
		return "", err
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("Smart contract generation failed: %s", respMsg)
	}

	return respMsg, nil
}

// @Summary Execute a smart contract
// @Description Executes a smart contract on the Rubix network
// @Tags SmartContract
// @Accept json
// @Produce json
// @Param rubixNodePort query string true "Rubix node port"
// @Param request body ExecuteSmartContractRequest true "Smart contract execution details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /execute-smart-contract [post]
func executeSmartContractHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	var req ExecuteSmartContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// get user info by did
	user, err := storage.GetUserByDID(req.ExecutorAddr)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	response, err := executeSmartContractReq(req, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	respMsg := response["message"].(string)
	// sign, if the message says 'signature needed'
	if strings.Contains(respMsg, "Signature needed") {
		respMsg, err = callSignHandler(response, req.ExecutorAddr)
		if err != nil {
			basicResponse.Message = err.Error()
			c.JSON(http.StatusInternalServerError, basicResponse)
			// Add a newline to the response body if required
			c.Writer.Write([]byte("\n"))
			return
		}
	} else {
		basicResponse.Status = response["status"].(bool)
		basicResponse.Message = respMsg
		c.JSON(http.StatusInternalServerError, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// prepare response
	basicResponse.Status = true
	basicResponse.Message = respMsg
	c.JSON(http.StatusOK, basicResponse)
	c.Writer.Write([]byte("\n"))
}

// executeSmartContractReq requests the Rubix node to execute a smart contract
func executeSmartContractReq(data ExecuteSmartContractRequest, rubixNodePort string) (map[string]interface{}, error) {
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return nil, err
	}

	url := fmt.Sprintf("http://localhost:%s/api/execute-smart-contract", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return nil, err
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return nil, fmt.Errorf("smart contract execution failed: %s", respMsg)
	}

	return response, nil
}

// @Summary Subscribe to an SmartContract
// @Description Subscribes a user to an SmartContract
// @Tags SmartContract
// @Accept json
// @Produce json
// @Param request body SubscribeSmartContractRequest true "SmartContract subscription details"
// @Success 200 {object} BasicResponse
// @Failure 400 {object} BasicResponse
// @Failure 401 {object} BasicResponse
// @Security BearerAuth
// @Param Authorization header string true "Authorization token (Bearer <your_token>)"
// @Router /subscribe-smart-contract [post]
func subscribeSmartContractHandler(c *gin.Context) {
	basicResponse := BasicResponse{
		Status: false,
	}
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		basicResponse.Message = "Token is required"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	tokenString = tokenString[len("Bearer "):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		basicResponse.Message = "Invalid token, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		c.Abort()
		return
	}

	// Extract the DID claim from the token
	claims := token.Claims.(jwt.MapClaims)
	did, ok := claims["sub"].(string)
	if !ok {
		basicResponse.Message = "Invalid token: missing or invalid DID"
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Optionally, verify the DID exists in the database
	user, err := storage.GetUserByDID(did)
	if err != nil {
		basicResponse.Message = "User not found, " + err.Error()
		c.JSON(http.StatusUnauthorized, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	var req SubscribeSmartContractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		basicResponse.Message = "Invalid input, " + err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	// Ensure the DID from the token matches the one in the request body
	if req.DID != did {
		basicResponse.Message = "DID mismatch"
		c.JSON(http.StatusForbidden, basicResponse)
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := subscribeSmartContractRequest(req.SmartContractToken, strconv.Itoa(user.Port))
	if err != nil {
		basicResponse.Message = err.Error()
		c.JSON(http.StatusBadRequest, basicResponse)
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// preapre response
	basicResponse.Status = true
	basicResponse.Message = resp
	c.JSON(http.StatusOK, basicResponse)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// subscribeSmartContractRequest sends request to subscribe SmartContract
func subscribeSmartContractRequest(SmartContract string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"smartContractToken": SmartContract,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/subscribe-smart-contract", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("failed to subscribe SmartContract, %s", respMsg)
	}

	return respMsg, nil
}
