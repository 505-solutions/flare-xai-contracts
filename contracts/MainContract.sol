// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FlareVtpmAttestation.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "@openzeppelin/contracts/utils/Strings.sol";

contract MainContract {
    FlareVtpmAttestation public attestationContract;
    IERC20 public wlfrToken;
    address public owner;

    struct WalletRequest {
        address requester;
        uint256 depositAmount;
    }

    mapping(address => WalletRequest) public walletRequests;

    event WalletRegistered(address indexed requester, uint256 amount);
    event WalletActivated(address indexed walletAddress, uint256 amount);
    event RewardsDistributed(address[] rewardees, uint256[] rewards);

    string public imageDigest;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    constructor(address _attestationContract, address _wlfrToken, string memory _imageDigest) {
        attestationContract = FlareVtpmAttestation(_attestationContract);
        wlfrToken = IERC20(_wlfrToken);
        owner = msg.sender;
        imageDigest = _imageDigest;
    }

    function setImageDigest(string memory _imageDigest) external onlyOwner {
        imageDigest = _imageDigest;
    }

    function setAttestationContract(address _attestationContract) external onlyOwner {
        attestationContract = FlareVtpmAttestation(_attestationContract);
    }

    function registerWallet(uint256 amount) external {
        require(amount > 0, "Amount must be greater than zero");
        require(wlfrToken.transferFrom(msg.sender, address(this), amount), "Token transfer failed");

        walletRequests[msg.sender] = WalletRequest({requester: msg.sender, depositAmount: amount});

        emit WalletRegistered(msg.sender, amount);
    }

    function activateWallet(
        bytes calldata header,
        bytes calldata payload,
        bytes calldata signature,
        address walletAddress
    ) external {
        require(walletRequests[msg.sender].depositAmount > 0, "No wallet request found");

        bool success = attestationContract.verifyAndAttest(header, payload, signature);
        require(success, "Attestation verification failed");

        QuoteConfig memory registeredConfig = attestationContract.getRegisteredQuote(address(this));

        
        uint256 depositAmount = walletRequests[msg.sender].depositAmount;

        delete walletRequests[msg.sender];

        require(wlfrToken.transfer(walletAddress, depositAmount), "Token transfer failed");

        emit WalletActivated(walletAddress, depositAmount);
    }

    function distributeRewards(address[] calldata rewardees, uint256[] calldata rewards) external onlyOwner {
        require(rewardees.length == rewards.length, "Mismatched arrays");

        for (uint256 i = 0; i < rewardees.length; i++) {
            // Minting dummy tokens to rewardees
            // Assuming a mint function exists in the token contract
            // wlfrToken.mint(rewardees[i], rewards[i]);
        }

        emit RewardsDistributed(rewardees, rewards);
    }
}
