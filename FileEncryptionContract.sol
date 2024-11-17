// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FileEncryptionContract {

    struct FileData {
        string filename;          
	string username;
        bytes aesKey;             
        bytes encryptedData;      
        string ecdsaPublicKey;   
        bytes ecdsaSignature;     
        string uploadedAt;        
    }

   
    mapping(string => FileData) private fileStorage;

    event FileStored(string indexed filename, string ecdsaPublicKey, string uploadedAt);

    function storeFileData(
        string memory filename,
	string memory username,
        bytes memory aesKey,
        bytes memory encryptedData,
        string memory ecdsaPublicKey,
        bytes memory ecdsaSignature,
        string memory uploadedAt
    ) public {
        // Store the file-related data in the mapping
        fileStorage[filename] = FileData({
            filename: filename,
	    username: username,
            aesKey: aesKey,
            encryptedData: encryptedData,
            ecdsaPublicKey: ecdsaPublicKey,
            ecdsaSignature: ecdsaSignature,
            uploadedAt: uploadedAt
        });

        emit FileStored(filename, ecdsaPublicKey, uploadedAt);
    }

    // Function to retrieve the encrypted data, ECDSA public key, and signature for a specific filename
    function retrieveFileMetadata(string memory filename)
        public
        view
        returns (
            bytes memory encryptedData,
            string memory ecdsaPublicKey,
            bytes memory ecdsaSignature
        )
    {

        require(bytes(fileStorage[filename].filename).length > 0, "File not found");

        // Return the encrypted data, ECDSA public key, and signature
        FileData storage fileData = fileStorage[filename];
        return (fileData.encryptedData, fileData.ecdsaPublicKey, fileData.ecdsaSignature);
    }

    // Function to retrieve the encrypted data and AES key for a specific filename
    function retrieveFileAndKey(string memory filename)
        public
        view
        returns (
            bytes memory encryptedData,
            bytes memory aesKey
        )
    {
        // Ensure the file exists
        require(bytes(fileStorage[filename].filename).length > 0, "File not found");

        // Return the encrypted data and AES key
        FileData storage fileData = fileStorage[filename];
        return (fileData.encryptedData, fileData.aesKey);
    }
}
