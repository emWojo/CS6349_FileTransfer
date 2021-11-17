# CS6349_FileTransfer

## Directories for Server and Client
The server directory is assumed to be `serverStore\\` stored in the constant `fStore`

The client directory is assumed to be `clientStore\\` stored in the constant `fStore`

## Get requirements
python 3.x

`py -m pip install -r reqs.txt`

## Run Server First
`py server.py`

## Run Client Next
`py client.py`

## Client CLI
`help` - Print Usage

`upload <test.txt>` - Upload test.txt from client fStore

`download <test.txt>` - Download test.txt from server fStore

`exit` - Close Server and Client connection
