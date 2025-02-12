# RubixLiteWallet
This is a non-custodial wallet server, which manages keys for rubix nodes. It uses BIP39 to generate keys and to sign. The keys are generated on the curve secp256k1. 

## Commands
### Start server 
```
go run wallet.go

```

### Curl request to create a new user
```
curl -X POST http://localhost:8080/create -d '{"email":"<email id>","password":"<password>","name":"<user name>","secret_key":"<secret key to encrypt private key>", "wallet_type":"<self-custody or server-custody>", "public_key": "<public key as hex string>"}'
```
_**Note** : If `secret_key` is not provided explicitly, password will be used as `secret_key`, in case of server-custodial wallet_

#### sample with valid request 
**Self-Custodial**
```
curl -X POST http://localhost:8080/create -d '{"email":"bob@c.com","password":"123","name":"bob", "wallet_type":"self-custody", "public_key":"041756d13ad46e7811c99c961762472aa64a67554ae09e78b9c096350bc6a8bed3798fe19e3e3203a69d0ac00a60dc32b3652a2e7e372a7c60a64a1f3e06ec4c18"}'
```
**Response:**
```
{"did":"bafybmiatw5srgqlw3t5sm4buktu5gcgbfhkgujohem3o3a4cusvt424sei","email":"bob@c.com","name":"bob"}
```

**Server-Custodial**
```
curl -X POST http://localhost:8080/create -d '{"email":"alice@c.com","password":"123","name":"alice","secret_key":"abc123", "wallet_type":"server-custody"}'
```
**Response:**
```
{"did":"bafybmiaf2y3kkmd77e4hxp2yee2mhiquoc5hyr4mjya2sa5hccnnmk4bci","email":"alice@c.com","name":"alice"}
```

#### sample with invalid request (invalid input format to name)
```
curl -X POST http://localhost:8080/create -d '{"email":"jiya@p.com","password":"123","name":jiya,"secret_key":"abc123"}'
```
**Response:**
```
{"error":"Invalid request"}
```


### Curl request to login
```
curl -X POST http://localhost:8080/login -d '{"email":"<email id>","password":"<password>"}'
``` 

### Curl request to view profile
```
curl -L -X GET 'http://localhost:8080/profile' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1Mzk2NzYsInN1YiI6ImJhZnlibWliM3R2cWxuYjI1dWhwZHd2Mnk0d2JodHR6bXB3ZGVsM25ibGZvdTN2dTR2enY3YjNieWJxIn0.eMTEEtErNj4I7_MfO-0PiP2djnVz1rMZtAkCF3Hpbs8' 
```

### Curl request to create a wallet
```
curl -X POST http://localhost:8080/create_wallet -d '{"port":<rubix node port number in int>}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/create_wallet -d '{"port":20009}'
```
**Response:**
```
{"did":"bafybmie5l4jpfxmnnqi3sk4vnt6fx3sbuzf632ubeflc7let6rljzq4usi"}
```
#### sample with invalid request (invalid port)
```
curl -X POST http://localhost:8080/create_wallet -d '{"port":20001}'
```
**Response:**
```
{"error":"Failed to request DID"}
```


### Curl request to register did
```
curl -L -X POST http://localhost:8080/register_did -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<user DID>"}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/register_did -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{"did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina"}'
```
**Response:**
```
{"status":true,"message":"DID registered successfully","result":null}
```
#### sample with invalid request (invalid did)
```
curl -L -X POST http://localhost:8080/register_did -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{"did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvabhg"}'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```


### Curl request to setup quorum 
```
curl -L -X POST http://localhost:8080/setup_quorum -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<user DID>"}'
```
#### sample with valid request 
```
curl -L -X POST 'http://localhost:8080/setup_quorum' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4"}'
```
**Response:**
```
{"status":true,"message":"Quorum setup done successfully","result":null}
```
#### sample with invalid request (invalid did)
```
curl -L -X POST 'http://localhost:8080/setup_quorum' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4nhb"}'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```


### Curl request to add peer info 
```
curl -L -X POST http://localhost:8080/add_peer -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"self_did":"<user did>", "DID":"<peer did>", "DIDType":<0 to 4>, "PeerID":"<peer ID>"}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/add_peer -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"self_did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4", "DID":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4", "DIDType":4, "PeerID":"12D3KooWK87BWaHW2oJEuTSDLSPVMB3UTfHGnqsoqQNW3UBhofyF"}'
```
**Response:**
```
{"status":true,"message":"Peers added successfully","result":null}
```
#### sample with invalid request (invalid peerId)
```
curl -L -X POST http://localhost:8080/add_peer -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"self_did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4", "DID":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4", "DIDType":4, "PeerID":""}'
```
**Response:**
```
{"status":false,"message":"failed to add peer, Invalid Peer ID","result":null}
```

### Curl request to generate test RBT
```
curl -L -X POST http://localhost:8080/testrbt/create -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "number_of_tokens":<amount in int>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/testrbt/create -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4", "number_of_tokens":1}'
```
**Response:**
```
{"status":true,"message":"Test tokens generated successfully","result":null}
```
#### sample with invalid request (invalid input format to number_of_tokens)
```
curl -L -X POST http://localhost:8080/testrbt/create -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4", "number_of_tokens":1.0}'
```
**Response:**
```
{"status":false,"message":"Invalid input, json: cannot unmarshal number 1.0 into Go struct field GenerateTestRBTRequest.number_of_tokens of type int","result":null}
```


### Curl request to get balance
```
curl -L -X GET "http://localhost:8080/request_balance?did=<user DID>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/request_balance?did=bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0'
```
**Response:**
```
{"status":true,"message":"Got account info successfully","result":[{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4","did_type":0,"locked_rbt":0,"pinned_rbt":0,"pledged_rbt":0,"rbt_amount":1}]}
```
#### sample with invalid request (empty input to did)
```
curl -L -X GET "http://localhost:8080/request_balance?did=" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0'
```
**Response:**
```
{"status":false,"message":"Missing required parameter: did","result":null}
```


### Curl request to unpledge pledged RBTs
```
curl -L -X POST http://localhost:8080/rbt/unpledge -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<user DID>"}'

```
#### sample with valid request
```
curl -L -X POST http://localhost:8080/rbt/unpledge -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4wb4"}'
```
**Response:**
```
{"status":true,"message":"No tokens present to unpledge","result":null}
```
#### sample with invalid request (invalid did)
```
curl -L -X POST http://localhost:8080/rbt/unpledge -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjE4MTQsInN1YiI6ImJhZnlibWloc25tcWVyNmY2cmlmejVtZzVlbGY3dXd0M2VuNnQzNXZpY3M3eTV5N3BuNGFueXQ0d2I0In0.LiYfB_qFd13TpsxeGgoi3f2pDsZ7RDAeqzG1vtNTbu0' -d '{"did":"bafybmihsnmqer6f6rifz5mg5elf7uwt3en6t35vics7y5y7pn4anyt4nhb"}'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```


### Curl request to sign
```
curl -X POST http://localhost:8080/sign -d '{"did":"<rubix node DID>","sign_data":{"hash":"<string>","id":"<string>","mode":4}}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/sign -d '{"did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","sign_data":{"hash":"NDkzYTkyN2NjYTA1YTgzZDA1ZWVjZjcwMzgxYjQ5ZGY1YTFlOTNiODM0OTE5OWJiYWY4NGVmNjBkNDdkMTEzNA==","id":"4CC6CE58-3C12-4CCB-B0D3-05395D4E3650","mode":4, "only_priv_key":true}}'
```
**Response:**
(While registering DID)
```
{"status":true,"message":"DID registered successfully","result":null}
```
#### sample with invalid request (invalid did)
```
curl -X POST http://localhost:8080/sign -d '{"did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvanhb","sign_data":{"hash":"ZWQ1MWY0OWYxNTYzMTEzNGEzZTQyMDJmYWJkYmRjMzAzY2I3OGZlZjk1Zjc3MjhlM2M5NTllNGMxOWY5ZjFjZQ==","id":"BA81DDB1-5DBD-4C86-877B-1FA630A868D3","mode":4, "only_priv_key":true}}'
```
**Response:**
```
{"status":false,"message":"User not found, sql: no rows in result set","result":null}
```


### Curl request to transfer RBTs
```
curl -L -X POST http://localhost:8080/request_txn -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<sender DID>","receiver":"<receiver DID>", "rbt_amount":<transaction amount in float>}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/request_txn -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{"did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","receiver":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q", "rbt_amount":1.0}'
```
**Response:**
```
{"status":true,"message":"Transfer finished successfully in 14.059856393s with trnxid d5e06dbdb20e235031afdbc958fe153357ee748dcb79d3b50d49a6f0413d39e4","result":null}
```
#### sample with invalid request (invalid rbt_amount)
```
curl -L -X POST http://localhost:8080/request_txn -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{"did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","receiver":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q", "rbt_amount":2.56087}'
```
**Response:**
```
{"status":false,"message":"transaction amount exceeds 3 decimal places","result":null}
```


### Curl request to get all transactions by DID
```
curl -L -X GET "http://localhost:8080/txn/by_did?did=<user DID>&role=<Sender/Receiver>&StartDate=<start of the date range>&EndDate=<end of the date range>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
**Note** : either provide role of the did or else date range to filter the Txns list

#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/txn/by_did?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina&role=sender" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4'
```
**Response:**
```
{"status":true,"message":"Retrieved Txn Details","result":[{"Amount":1,"BlockID":"1-2ae85d00a01ec1f787f956d761a5221fc9603a4d9fb229afa58bddeb6cb27efc","Comment":"","DateTime":"2025-01-22T11:13:21.354098426+05:30","DeployerDID":"","Epoch":1737524583,"Mode":0,"ReceiverDID":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q","SenderDID":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","Status":true,"TotalTime":18035,"TransactionID":"aba3785b943dafec5b84d998eb867d30eb445e3033eaac34c1d8e57756af156c","TransactionType":"02"},{"Amount":1,"BlockID":"1-de180f0825e9ef950feec5bd6284edc6de719d8ddd16c5ffe04a8f92bdd53427","Comment":"","DateTime":"2025-01-22T11:18:37.005228346+05:30","DeployerDID":"","Epoch":1737524903,"Mode":0,"ReceiverDID":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q","SenderDID":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","Status":true,"TotalTime":14059,"TransactionID":"d5e06dbdb20e235031afdbc958fe153357ee748dcb79d3b50d49a6f0413d39e4","TransactionType":"02"},{"Amount":5,"BlockID":"1-d7a706e1e683586b7e3bd194ca1e98c7e4e341683957d2f07e6f28a5c6882fc5","Comment":"","DateTime":"2025-01-22T11:37:38.441091027+05:30","DeployerDID":"","Epoch":1737526039,"Mode":0,"ReceiverDID":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q","SenderDID":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","Status":true,"TotalTime":19642,"TransactionID":"8c9c8ca4c9888fd4a15434757268ac83bb52cdfe190d8eeb4565ac237d3d9cc0","TransactionType":"02"}]}
```
#### sample with invalid request (invalid did)
```
curl -L -X GET "http://localhost:8080/txn/by_did?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvamnb&role=sender" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```

### Curl request to create FT
```
curl -L -X POST "http://localhost:8080/create_ft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "ft_count":<number of FTs in int>, "ft_name":"<ft name>", "token_count":<number of RBTs in int>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/create_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "ft_name":"testFT-1",
    "ft_count":5,
    "token_count":1
}'
```
**Response:**
```
{"status":true,"message":"FT created successfully","result":null}
```
#### sample with invalid request (invalid input format to token_count)
```
curl -L -X POST http://localhost:8080/create_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "ft_name":"testFT-1",
    "ft_count":5,
    "token_count":0.8
}'
```
**Response:**
```
{"status":false,"message":"Invalid input, json: cannot unmarshal number 0.8 into Go struct field CreateFTRequest.token_count of type int","result":null}
```

### Curl request to transfer FT
```
curl -L -X POST "http://localhost:8080/transfer_ft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"sender":"<sender DID>", "receiver":<receiver DID>, "ft_count":<number of FTs in int>, "ft_name":"<ft name>", "creatorDID":<DID of FT creator>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/transfer_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "sender":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "receiver":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
    "creatorDID":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "ft_name":"testFT-1",
    "ft_count":1, 
    "quorum_type":2
}'
```
**Response:**
```
{"status":true,"message":"FT Transfer finished successfully in 12.41772759s with trnxid 8effdf7d21d8a4b019ddb30c4441bfa8c575a6b055785d160fd4d11a7d9ee633","result":null}
```
#### sample with invalid request (invalid input format to ft_count)
```
curl -L -X POST http://localhost:8080/transfer_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "sender":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "receiver":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
    "creatorDID":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "ft_name":"testFT-1",
    "ft_count":1.6, 
    "quorum_type":2
}'
```
**Response:**
```
{"status":false,"message":"Invalid input, json: cannot unmarshal number 1.6 into Go struct field TransferFTReq.ft_count of type int","result":null}
```

### Curl request to get all FTs' info
```
curl -L -X GET "http://localhost:8080/get_all_ft?did=<user DID>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_all_ft?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' 
```
**Response:**
```
{"status":true,"message":"Got FT info successfully","result":[{"creator_did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","ft_count":4,"ft_name":"testFT-1"}]}
```
#### sample with invalid request (empty input to did)
```
curl -L -X GET "http://localhost:8080/get_all_ft?did=" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' 
```
**Response:**
```
{"status":false,"message":"Missing required parameter: did","result":null}
```

### Curl request to get FT chain
```
curl -L -X GET "http://localhost:8080/get_ft_chain?did=<user DID>&tokenID=<FT token ID>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_ft_chain?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina&tokenID=QmQ2UsVPPkMhoZdXq3XjUZHkxoCQMcU5gqE8yg231fRseV" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4'
```
**Response:**
```
{"status":true,"message":"FT tokenchain data fetched successfully","result":[{"TCBlockHashKey":"dddfeea488ac5b0b0be323d7277023518f29031671f7eccb11639ff88f1f9243","TCChildTokensKey":[],"TCGenesisBlockKey":{"GBInfoKey":{"QmQ2UsVPPkMhoZdXq3XjUZHkxoCQMcU5gqE8yg231fRseV":{"GICommitedTokensKey":{},"GIParentIDKey":"QmddtfTnv3yRsCSbJn8D5jF11H7yhymKTvWzJkPfJFxSVb","GITokenLevelKey":0,"GITokenNumberKey":0}},"GBTypeKey":""},"TCSignatureKey":{"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina":"304502201af02d06758a73f343a783f3077ce01cf5a0bf04655da0214fbf1c5c132eb7f9022100d5ad44f4bd090816649ee016e6521d82d06d0d3eedb775366d97d37ed4100054"},"TCTokenOwnerKey":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","TCTokenValueKey":0.2,"TCTransInfoKey":{"TICommentKey":"FT generated at : 2025-01-22 11:44:48.452452437 +0530 IST m=+51997.497202936 for FT Name : testFT-1","TITokensKey":{"QmQ2UsVPPkMhoZdXq3XjUZHkxoCQMcU5gqE8yg231fRseV":{"TTBlockNumberKey":"0","TTPreviousBlockIDKey":"","TTTokenTypeKey":10}}},"TCTransTypeKey":"05"},{"TCBlockHashKey":"6854b21219a47cd845dbff57818747b26778b4eda5749898aa9f7991c373e6ab","TCChildTokensKey":[],"TCPledgeDetailsKey":{"bafybmiatw3hxfzvuyoiz3hinuicmeri2yq5o3lioajtasfp6cmiu2j3kom":[{"8-1":"QmdNvSPPHvpWpA5QoUXP1qeHhKAgCLmXpW7YxPsXMB1BMb","8-2":5,"8-3":"0-56c5d05e09c5eaf167b62f02f49353ac9f2691e766f3acf541a24a533ea228a6"}],"bafybmibvafoolczvyg33vrn3nubyidgvznwiwj4poem76oz7d2f6jgsxxu":[{"8-1":"QmYRv1QN1jciwdMyKAxq3SSAo71KxyrVoa8rXhNKe8PED1","8-2":5,"8-3":"0-e1980baee57ab39e147612b5fc42bc9fc726701fca01d67a580294af0abb6091"}],"bafybmic6nkiab457zk4gz4cvvsrr4rqhprffq6gypj6cdkqouuslnkq7ry":[{"8-1":"QmTnKoYUickXpFqX5iFe9mxaZSZMzA6w4iDVSr6qKE6pgt","8-2":5,"8-3":"0-5ed90edd6d57c88a8cb63b98949d7401372c623026b39cce3054997ccb25e5a8"}],"bafybmiegfotvu2yjhkcop2pwosc2zv2pqimez6mv7yzg3piw6dmxxihiue":[{"8-1":"QmQi98kVw4jZE1xQ6c3oSpaj3yyX8Th3r1MvUBjkrGvFoC","8-2":5,"8-3":"0-8978b1eb76991ecfd37dfc125db75bc9dc5c8dd68929475cd3f926ce049f8798"},{"8-1":"QmeEKwPHafzKJxbhrDkoFkMEZYF5YTVmfpHvti46seDfda","8-2":5,"8-3":"0-c1cbf416c6764989f57241b224ebfd6fda105e7ed849a754f7c00c3f4e8d8377"}],"bafybmihok6fpv7kc2kcsc2xkooyexr3aguhrjoitgvkeevanw6wqrb2bnq":[{"8-1":"QmeJFThqqo2dYq25pyFQaLW7RGaDVuYuQGrfzb74be43pm","8-2":5,"8-3":"0-94f8b73b2ce65fcb660a2c89c8d5e052c81853dc8ca368e7ad3b8558de56ccc7"}]},"TCQuorumSignatureKey":[{"did":"bafybmic6nkiab457zk4gz4cvvsrr4rqhprffq6gypj6cdkqouuslnkq7ry","hash":"","priv_signature":"3045022100a3a00867173377896c7911c2e4455cda8adbb972d5577380239de80b6ee4c94f022074a8ad43e3c80a850a725a1506aad499fd91adaaba462f2a71d01af937d6c58d","sign_type":"0","signature":""},{"did":"bafybmiegfotvu2yjhkcop2pwosc2zv2pqimez6mv7yzg3piw6dmxxihiue","hash":"","priv_signature":"30450220313fc30a7f523afa794a350b05e0dc9634342c84ee58c224ba3b78eb927985b1022100eb10e40938882e6cb838b5a2a3f29de13edede56e0b4e5306369599805ccb08c","sign_type":"0","signature":""},{"did":"bafybmiatw3hxfzvuyoiz3hinuicmeri2yq5o3lioajtasfp6cmiu2j3kom","hash":"","priv_signature":"3045022100df47d4a338afff03e9a849385c7d522fa22bac33e56b63c25d44a3ba04360cc1022040f228270809368d9d8022f151e4aa03e705efb7b17acbfddccbec60201107e8","sign_type":"0","signature":""},{"did":"bafybmihok6fpv7kc2kcsc2xkooyexr3aguhrjoitgvkeevanw6wqrb2bnq","hash":"","priv_signature":"3046022100a97adbb293393d2dde7ab6696afefb65d3a01d327d6b4bc03f48743d381fd394022100cd7e39646ebbcbd949354101d5291ffb24fbc905f28f89e6846d0897ae98f5da","sign_type":"0","signature":""},{"did":"bafybmibvafoolczvyg33vrn3nubyidgvznwiwj4poem76oz7d2f6jgsxxu","hash":"","priv_signature":"3044022061d8b8254a3c4208d387a14e4dd0e8178e0d638a647b19bd59dfffaa07c25e12022040a7fa48a70df8bc60cdf6f8bccb9942c619c55f6056e3fb75f08eb9b6522d80","sign_type":"0","signature":""}],"TCSenderSignatureKey":{"InitiatorDID":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","hash":"3f31b49975fce7c24ee6b705e59f097ebc7be998d139cb164d72f565fcee8bff","nlss_share_signature":"","priv_signature":"304402200ebe7f12a6501ea9334bbac7f3063d6ac3998b9694e051e98170f3683797e04402204a7e4ff6ae418f55598cb1c6d353191cc9870b22c4aad37ea36ddb4164b0d106","sign_type":0},"TCSignatureKey":{"bafybmiatw3hxfzvuyoiz3hinuicmeri2yq5o3lioajtasfp6cmiu2j3kom":"304402202ef9819a6d274f5fe1ef6c7bb1275990ed999ef5e505f2de9f301810dafa8ae202204523f0d7d29f51376a67094d8f43f221113b5a2920621e5154444b82da2d22a0","bafybmibvafoolczvyg33vrn3nubyidgvznwiwj4poem76oz7d2f6jgsxxu":"30450221009d774df850144154001f39da73c834188de4293b499c5afa14d78ffe04257bc902203d328b4881065c24b1fa027facc8008889da73b9677f6ae7e28d3dced9f4a5ce","bafybmic6nkiab457zk4gz4cvvsrr4rqhprffq6gypj6cdkqouuslnkq7ry":"3045022005c85eec36db7e7b02e78c6a37fb6cc2e17d3fe51f41736e53e1815cc3775e7f022100c4bda99a943c640f9b94e6f45a46d673c067dfe3760397cdf39a19f7f8d4fb27","bafybmiegfotvu2yjhkcop2pwosc2zv2pqimez6mv7yzg3piw6dmxxihiue":"30450220541b6ae527eb8ab398d77a740e4b1c2589cf1f1dceb8f635b6bd2862fe605745022100bf0123d4b246d9d6440c8d28dfa87c84208a3dce9c1fe8b2d47854fbe1271a0b","bafybmihok6fpv7kc2kcsc2xkooyexr3aguhrjoitgvkeevanw6wqrb2bnq":"3045022100e9a4958d0eaffeb6a7dd49db2d704dcd7ca71feea084c393fdb0f5cdb8f92f96022047ced665aea3eb8eedf8a0c4caee6b68c4910f14dac025a057a1770d90b60981"},"TCSmartContractKey":"a36131590154a46131086132006133a36131783b62616679626d696179737962356862646236636c736b376a6e6364656a78776f6d78756d76337a6f7335743537663662777a376e756d7661696e616132783b62616679626d696671706933366d767a6f6371717073683372746a726a7935343334776c7176346e7a377a7234656a71783371756c35676c3336716134a1782e516d513255735650506b4d686f5a64587133586a555a486b786f43514d6355356771453879673233316652736556a461310a6132783b62616679626d696179737962356862646236636c736b376a6e6364656a78776f6d78756d76337a6f7335743537663662777a376e756d7661696e6161337842302d646464666565613438386163356230623062653332336437323737303233353138663239303331363731663765636362313136333966663838663166393234336134fb3fc999999999999a6134f900006132583fa1783b62616679626d696179737962356862646236636c736b376a6e6364656a78776f6d78756d76337a6f7335743537663662777a376e756d7661696e6160613358cca1783b62616679626d696179737962356862646236636c736b376a6e6364656a78776f6d78756d76337a6f7335743537663662777a376e756d7661696e61788c3330343430323230306562653766313261363530316561393333346262616337663330363364366163333939386239363934653035316539383137306633363833373937653034343032323034613765346666366165343138663535353938636231633664333533313931636339383730623232633461616433376561333664646234313634623064313036","TCTokenOwnerKey":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q","TCTransInfoKey":{"TIReceiverDIDKey":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q","TISenderDIDKey":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","TITIDKey":"8effdf7d21d8a4b019ddb30c4441bfa8c575a6b055785d160fd4d11a7d9ee633","TITokensKey":{"QmQ2UsVPPkMhoZdXq3XjUZHkxoCQMcU5gqE8yg231fRseV":{"TTBlockNumberKey":"1","TTPreviousBlockIDKey":"0-dddfeea488ac5b0b0be323d7277023518f29031671f7eccb11639ff88f1f9243","TTTokenTypeKey":10}}},"TCTransTypeKey":"02"}]}
```
#### sample with invalid request (empty input to tokenID)
```
curl -L -X GET "http://localhost:8080/get_ft_chain?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina&tokenID=" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4'
```
**Response:**
```
{"status":false,"message":"Missing required parameter: tokenID","result":null}
```

### Curl request to create NFT
```
curl -L -X POST "http://localhost:8080/create_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "metadata":<metadata file path>, "artifact":"<artifact file path>"}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/create_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/NFT/test2.png"
}'
```
**Response:**
```
{"status":true,"message":"NFT Token generated successfully","result":null}
```
#### sample with invalid request (invalid input path to artifact)
```
curl -L -X POST http://localhost:8080/create_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/test2.png"
}'
```
**Response:**
```
{"status":false,"message":"open /home/maneesha/Rubix-Git/test2.png: no such file or directory","result":null}
```

### Curl request to subscribe NFT
```
curl -L -X POST "http://localhost:8080/subscribe_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "nft":<nft token ID>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/subscribe_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y' -d '{
    "did":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
    "nft":"QmNMBaU9B6ZaBjaPgufTaTsTu9dHjtf3XWWogFPJ3zy9u6"
}'
```
**Response:**
```
{"status":true,"message":"NFT subscribed successfully","result":null}
```
#### sample with invalid request (invalid input to did)
```
curl -L -X POST http://localhost:8080/subscribe_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y' -d '{
    "did":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5glnhb",
    "nft":"QmNMBaU9B6ZaBjaPgufTaTsTu9dHjtf3XWWogFPJ3zy9u6"
}'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```

### Curl request to deploy NFT
```
curl -L -X POST "http://localhost:8080/deploy_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "nft":"<nft ID>", "quorum_type":<1 or 2>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/deploy_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "nft":"QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P",
    "quorum_type":2
}'
```
**Response:**
```
{"status":true,"message":"NFT Deployed successfully in 10.891008617s","result":null}
```
#### sample with invalid request (invalid input to quorum_type)
```
curl -L -X POST http://localhost:8080/deploy_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "nft":"QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P",
    "quorum_type":4
}'
```
**Response:**
```
{"status":false,"message":"failed to deploy NFT, Invalid quorum type","result":null}
```

### Curl request to execute NFT
```
curl -L -X POST http://localhost:8080/execute_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{
  "comment": "string",
  "nft": "string",
  "nft_data": "string",
  "nft_value": 0.0,
  "owner": "string",
  "quorum_type": 0,
  "receiver": "string"
}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/execute_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
  "comment": "testing nft transfer from wallet",
  "nft": "QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P",
  "nft_data": "",
  "nft_value": 11.0,
  "owner": "bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
  "quorum_type": 2,
  "receiver": "bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q"
}'
```
**Response:**
```
{"status":true,"message":"NFT Executed successfully in 11.213855241s","result":null}
```
#### sample with invalid request (invalid owner)
```
curl -L -X POST http://localhost:8080/execute_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
  "comment": "testing nft transfer from wallet",
  "nft": "QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P",
  "nft_data": "",
  "nft_value": 11.0,
  "owner": "bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvamnq",
  "quorum_type": 2,
  "receiver": "bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q"
}'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```

### Curl request to fetch NFT
```
curl -L -X GET "http://localhost:8080/get_nft?did=<string>&nft=<string>" -H 'Authorization: Bearer <jwt token returned while logging in>'
```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_nft?did=bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q&nft=QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y'
```
**Response:**
```
{"status":true,"message":"NFT fetched successfully","result":null}
```
#### sample with invalid request (invalid did)
```
curl -L -X GET "http://localhost:8080/get_nft?did=bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5glmnb&nft=QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```

### Curl request to get NFT chain
```
curl -L -X GET "http://localhost:8080/get_nft_chain?did=<string>&nft=<string>&latest=<string>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_nft_chain?did=bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q&nft=QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7P" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y'
```
**Response:**
```
{"status":true,"message":"Fetched NFT data","result":[{"BlockId":"0-545c71dbbefd73709d8b13c4f6cd756d1a445898bdd823a9dd200a43d951c1a1","BlockNo":0,"NFTData":"","NFTOwner":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina","NFTValue":0},{"BlockId":"1-be986f46ca72891f0b046a16bd369051de168ef0581026175b7b7829bd8c36f6","BlockNo":1,"NFTData":"","NFTOwner":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q","NFTValue":11}]}
```
#### sample with invalid request (invalid input to nft)
```
curl -L -X GET "http://localhost:8080/get_nft_chain?did=bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q&nft=QmV8SEuVqrqhQxDsden9t22Hp7vyXUJCPLcS5ic6MnPK7k" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y'
```
**Response:**
```
{"status":false,"message":"Failed to get nft data, token does not exist","result":null}
```

### Curl request to get all NFTs
```
curl -L -X GET "http://localhost:8080/get_all_nft?did=<string>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_all_nft?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4'
```
**Response:**
```
{"status":true,"message":"Got All NFTs","result":[{"nft":"QmNMBaU9B6ZaBjaPgufTaTsTu9dHjtf3XWWogFPJ3zy9u6","nft_value":0,"owner_did":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina"}]}
```
#### sample with invalid request (invalid input to did)
```
curl -L -X GET "http://localhost:8080/get_all_nft?did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvabhg" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4'
```
**Response:**
```
{"status":false,"message":"DID mismatch","result":null}
```

### Curl request to generate Smart Contract Token
```
curl -L -X POST "http://localhost:8080/generate-smart-contract -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "binary_code_path":<binary file path>, "raw_code_path":"<rust file path>", "schema_file_path":"<schema file path>}'
```
#### sample with valid request 
```
curl -L -X POST 'http://localhost:8080/generate-smart-contract' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' \
-F 'did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina' \
-F 'binaryCodePath=@/home/maneesha/Rubix-Git/Smart-Contract/code_files/bidding_contract.wasm' \
-F 'rawCodePath=@/home/maneesha/Rubix-Git/Smart-Contract/code_files/lib.rs' \
-F 'schemaFilePath=@/home/maneesha/Rubix-Git/Smart-Contract/code_files/bidding_contract.json'

```
**Response:**
```
{"status":true,"message":"Smart contract generated successfully","result":{"binaryFilePath":"uploads/36b74eed-d3af-435d-8b72-e618ee998bf9_binaryCodePath","rawFilePath":"uploads/36b74eed-d3af-435d-8b72-e618ee998bf9_rawCodePath","schemaFilePath":"uploads/36b74eed-d3af-435d-8b72-e618ee998bf9_schemaFilePath"}}
```
#### sample with invalid request (invalid did)
```
curl -L -X POST 'http://localhost:8080/generate-smart-contract' \
-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' \
-F 'did=bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvanhb' \
-F 'binaryCodePath=@/home/maneesha/Rubix-Git/Smart-Contract/code_files/bidding_contract.wasm' \
-F 'rawCodePath=@/home/maneesha/Rubix-Git/Smart-Contract/code_files/lib.rs' \
-F 'schemaFilePath=@/home/maneesha/Rubix-Git/Smart-Contract/code_files/bidding_contract.json'
```
**Response:**
```
{"status":false,"message":"User not found, sql: no rows in result set","result":null}
```

### Curl request to deploy Smart Contract
```
curl -L -X POST "http://localhost:8080/deploy-smart-contract -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"deployerAddr":"<rubix node DID>", "smartContractToken":"<smart Contract Token ID>", "quorumType":<1 or 2>, "rbtAmount":<float64>,"comment":"<string>"}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/deploy-smart-contract -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "deployerAddr":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "smartContractToken":"QmWi85birn8KiNeVxRdH6mCWqVtimK2SUzecKhnKxgBt4H",
    "quorumType":2,
    "rbtAmount":3,
    "comment":"testing sct deploy"
}'
```
**Response:**
```
{"status":true,"message":"Smart Contract Token Deployed successfully in 16.916829104s","result":null}
```
#### sample with invalid request (invalid input to smartContractToken)
```
curl -L -X POST http://localhost:8080/deploy-smart-contract -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3MjExODgsInN1YiI6ImJhZnlibWlheXN5YjVoYmRiNmNsc2s3am5jZGVqeHdvbXh1bXYzem9zNXQ1N2Y2Ynd6N251bXZhaW5hIn0.WU8P4UJiq-Jap_NhmHONhCah6d5xtoL6lHaH6ceUFJ4' -d '{
    "deployerAddr":"bafybmiaysyb5hbdb6clsk7jncdejxwomxumv3zos5t57f6bwz7numvaina",
    "smartContractToken":"QmWi85birn8KiNeVxRdH6mCWqVtimK2SUzecKhnKxgH",
    "quorumType":2,
    "rbtAmount":3,
    "comment":"testing sct deploy"
}'
```
**Response:**
```
{"status":false,"message":"smart contract deployment failed: Invalid smart contract token","result":null}
```

### Curl request to execute Smart Contract
```
curl -L -X POST http://localhost:8080/execute-smart-contract -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{
  "comment": "string",
  "smartContractToken": "string",
  "smartContractData": "string",
  "executorAddr": "string",
  "quorumType": 0
}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/execute-smart-contract -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y' -d '{
  "comment": "testing nft transfer from wallet",
  "smartContractToken": "QmWi85birn8KiNeVxRdH6mCWqVtimK2SUzecKhnKxgBt4H",
  "smartContractData": "54",
  "executorAddr": "bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
  "quorumType": 2
}'
```
**Response:**
```
{"status":true,"message":"Smart Contract Token Executed successfully in 11.302358297s","result":null}
```
#### sample with invalid request (invalid input format of quorumType)
```
curl -L -X POST http://localhost:8080/execute-smart-contract -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y' -d '{
  "comment": "testing nft transfer from wallet",
  "smartContractToken": "QmWi85birn8KiNeVxRdH6mCWqVtimK2SUzecKhnKxgBt4H",
  "smartContractData": "54",
  "executorAddr": "bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
  "quorumType": "2"
}'
```
**Response:**
```
{"status":false,"message":"Invalid input, json: cannot unmarshal string into Go struct field ExecuteSmartContractRequest.quorumType of type int","result":null}
```

### Curl request to subscribe Smart Contract
```
curl -L -X POST "http://localhost:8080/subscribe-smart-contract -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "smartContractToken":<smart contract token ID>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/subscribe-smart-contract -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y' -d '{
    "did":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
    "smartContractToken":"QmWi85birn8KiNeVxRdH6mCWqVtimK2SUzecKhnKxgBt4H"
}'
```
**Response:**
```
{"status":true,"message":"Smart contract subscribed successfully","result":null}
```
#### sample with invalid request (invalid input to smartContractToken)
```
curl -L -X POST http://localhost:8080/subscribe-smart-contract -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mzc3ODc5NDQsInN1YiI6ImJhZnlibWlmcXBpMzZtdnpvY3FxcHNoM3J0anJqeTU0MzR3bHF2NG56N3pyNGVqcXgzcXVsNWdsMzZxIn0.yeC38PkFauWhOkOiWeyCAT-813O-KahTrr9ESZ8TF4Y' -d '{
    "did":"bafybmifqpi36mvzocqqpsh3rtjrjy5434wlqv4nz7zr4ejqx3qul5gl36q",
    "smartContractToken":"QmWi85birn8KiNeVxRdH6mCWqVtimK2SUzecKhnKxgH"
}'
```
**Response:**
```
{"status":false,"message":"failed to subscribe SmartContract, Invalid smart contract token","result":null}
```