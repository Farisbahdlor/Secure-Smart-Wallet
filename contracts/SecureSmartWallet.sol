// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureSmartWallet {
    address public owner;
    uint256 private constant SESSION_DURATION = 24 hours; // Session duration (24 hours)

    struct UserSession {
        bool isLoggedIn;
        uint256 loginTime;
    }

    struct UserAuth {
        bytes32 passcodeHash;
        address authorizedVerifier;
    }

    mapping(address => UserAuth) private userAuth; // Tracks passcode hash and verifier for each user
    mapping(address => UserSession) private sessions; // Tracks login status and timestamp for each user
    mapping(address => uint256) private balances; // Tracks balances for each user

    event AccessGranted(address indexed user, string method);
    event LoggedIn(address indexed user);
    event LoggedOut(address indexed user);
    event FundsDeposited(address indexed from, uint amount);
    event FundsSent(address indexed to, uint amount);
    event UserAdded(address indexed user);
    event UserUpdated(address indexed user);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    modifier onlyLoggedIn() {
        require(sessions[msg.sender].isLoggedIn, "User is not logged in");
        require(block.timestamp <= sessions[msg.sender].loginTime + SESSION_DURATION, "Session expired, please log in again");
        _;
    }

    constructor() {
        owner = msg.sender; // Contract deployer is the owner
    }

    // Add a new user with passcode hash and verifier
    function addUser(address _user, bytes32 _passcodeHash, address _authorizedVerifier) public onlyOwner {
        require(userAuth[_user].authorizedVerifier == address(0), "User already exists");
        
        userAuth[_user] = UserAuth({
            passcodeHash: _passcodeHash,
            authorizedVerifier: _authorizedVerifier
        });
        
        emit UserAdded(_user);
    }

    // Update user's passcode and verifier
    function updateUser(address _user, bytes32 _newPasscodeHash, address _newAuthorizedVerifier) public onlyOwner {
        require(userAuth[_user].authorizedVerifier != address(0), "User does not exist");

        userAuth[_user].passcodeHash = _newPasscodeHash;
        userAuth[_user].authorizedVerifier = _newAuthorizedVerifier;
        
        emit UserUpdated(_user);
    }

    // Login function
    function login(bytes32 _hashedPasscode) public returns (bool) {
        require(userAuth[msg.sender].authorizedVerifier != address(0), "User not registered");
        require(_hashedPasscode == userAuth[msg.sender].passcodeHash, "Invalid passcode");

        sessions[msg.sender] = UserSession({
            isLoggedIn: true,
            loginTime: block.timestamp
        });

        emit LoggedIn(msg.sender);
        return true;
    }

    // Logout function
    function logout() public onlyLoggedIn returns (bool) {
        sessions[msg.sender].isLoggedIn = false;
        emit LoggedOut(msg.sender);
        return true;
    }

    // Verify Biometric Authentication
    function verifyBiometric(bytes memory signature) public returns (bool) {
        require(userAuth[msg.sender].authorizedVerifier != address(0), "User not registered");

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender));
        address signer = recoverSigner(messageHash, signature);
        require(signer == owner, "Biometric verification failed");

        sessions[msg.sender] = UserSession({
            isLoggedIn: true,
            loginTime: block.timestamp
        });

        emit AccessGranted(msg.sender, "Biometric");
        emit LoggedIn(msg.sender);
        return true;
    }

    // Verify Social Media Authentication
    function verifySocialMedia(bytes memory authToken) public returns (bool) {
        require(userAuth[msg.sender].authorizedVerifier != address(0), "User not registered");

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, authToken));
        require(recoverSigner(messageHash, authToken) == userAuth[msg.sender].authorizedVerifier, "Social media verification failed");

        sessions[msg.sender] = UserSession({
            isLoggedIn: true,
            loginTime: block.timestamp
        });

        emit AccessGranted(msg.sender, "SocialMedia");
        emit LoggedIn(msg.sender);
        return true;
    }

    // Deposit funds (requires login)
    function deposit() external payable onlyLoggedIn {
        balances[msg.sender] += msg.value;
        emit FundsDeposited(msg.sender, msg.value);
    }

    // Send funds to another address (requires login)
    function sendFunds(address payable _to, uint256 _amount) external onlyLoggedIn {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        balances[msg.sender] -= _amount;
        balances[_to] += _amount;

        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transaction failed");

        emit FundsSent(_to, _amount);
    }

    // Utility to recover the signer from the hashed message and signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        return ecrecover(messageHash, v, r, s);
    }

    // View balance of the caller
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }

    // View login status of the caller
    function isLoggedIn() public view returns (bool) {
        UserSession memory session = sessions[msg.sender];
        return session.isLoggedIn && (block.timestamp <= session.loginTime + SESSION_DURATION);
    }
}
