// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessManagement {
 string public filename;
 string public requester; 
 string public owner;
 string public requestTime;
 string public status;
   
    
    function storeAccess(string memory _filename, string memory _requester, string memory _owner, string memory _requestTime, string memory _status) public {
            filename = _filename;
            requester = _requester;
            owner = _owner;
	    requestTime = _requestTime;
	    status = _status;
            
        }
}

