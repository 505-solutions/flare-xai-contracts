// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {FlareVtpmAttestation} from "../contracts/FlareVtpmAttestation.sol";
import {OidcSignatureVerification} from "../contracts/verifiers/OidcSignatureVerification.sol";

import {
    Header, PayloadValidationFailed, QuoteConfig, SignatureVerificationFailed
} from "../contracts/types/Common.sol";

/**
 * @title FlareVtpmAttestationTest
 * @dev Test suite for the FlareVtpmAttestation contract.
 */
contract FlareVtpmAttestationTest is Test {
    /// @notice Instance of the contract to be tested
    FlareVtpmAttestation public flareVtpm;
    OidcSignatureVerification public oidcVerifier;

    // Example attestation token components for testing (Base64URL decoded)
    bytes constant HEADER =
        hex"7b22616c67223a225253323536222c226b6964223a2239393964323732396666376666613235316466653463336563646630366533626431643937303832222c22747970223a224a5754227d";
    bytes constant PAYLOAD =
        hex"7b22617564223a2268747470733a2f2f7374732e676f6f676c652e636f6d222c22657870223a313734313937383730362c22696174223a313734313937353130362c22697373223a2268747470733a2f2f636f6e666964656e7469616c636f6d707574696e672e676f6f676c65617069732e636f6d222c226e6266223a313734313937353130362c22737562223a2268747470733a2f2f7777772e676f6f676c65617069732e636f6d2f636f6d707574652f76312f70726f6a656374732f76657269666961626c652d61692d6861636b6174686f6e2f7a6f6e65732f75732d63656e7472616c312d612f696e7374616e6365732f64656d6973746966792d6261636b656e64222c226561745f6e6f6e6365223a22307835613733333844393430333330313039413237323231343042373739306643346532383645353443222c226561745f70726f66696c65223a2268747470733a2f2f636c6f75642e676f6f676c652e636f6d2f636f6e666964656e7469616c2d636f6d707574696e672f636f6e666964656e7469616c2d73706163652f646f63732f7265666572656e63652f746f6b656e2d636c61696d73222c22736563626f6f74223a747275652c226f656d6964223a31313132392c2268776d6f64656c223a224743505f414d445f534556222c2273776e616d65223a22434f4e464944454e5449414c5f5350414345222c22737776657273696f6e223a5b22323530313030225d2c2264626773746174223a22656e61626c6564222c227375626d6f6473223a7b22636f6e666964656e7469616c5f7370616365223a7b226d6f6e69746f72696e675f656e61626c6564223a7b226d656d6f7279223a66616c73657d7d2c22636f6e7461696e6572223a7b22696d6167655f7265666572656e6365223a22676863722e696f2f3530352d736f6c7574696f6e732f666c6172652d61692d64656661693a6d61696e222c22696d6167655f646967657374223a227368613235363a36396336633934313566346437616437353761373562383464343166356363333362393332373263633831356566613138393266333165653733313235613863222c22726573746172745f706f6c696379223a224e65766572222c22696d6167655f6964223a227368613235363a38383730343963646163373332336632353334643266303161316661626432646565663834646464346233616537363162373765313366646362393036313330222c22656e765f6f76657272696465223a7b2247454d494e495f4150495f4b4559223a2241497a61537942316b4f71735843316d6d734a6538537943756e586f72773243506e6357696467222c2247454d494e495f454d42454444494e475f4b4559223a2241497a615379424d624b2d6d6d3946444e676a3243595741777931426c6b76756b5a526e45636f222c2247454d494e495f4d4f44454c223a2267656d696e692d322e302d666c617368222c224f50454e5f524f555445525f4150495f4b4559223a22736b2d6f722d76312d33313861303231363233663131616338653639333333383732303362353166613939653234663065363261656137636430646464623735623036623436326136222c2253494d554c4154455f4154544553544154494f4e223a2266616c7365222c22574542335f50524f56494445525f55524c223a2268747470733a2f2f636f73746f6e322d6170692e666c6172652e6e6574776f726b2f6578742f432f727063227d2c22656e76223a7b2247454d494e495f4150495f4b4559223a2241497a61537942316b4f71735843316d6d734a6538537943756e586f72773243506e6357696467222c2247454d494e495f454d42454444494e475f4b4559223a2241497a615379424d624b2d6d6d3946444e676a3243595741777931426c6b76756b5a526e45636f222c2247454d494e495f4d4f44454c223a2267656d696e692d322e302d666c617368222c224750475f4b4559223a2237313639363035463632433735313335364430353441323641383231453638304535464136333035222c22484f53544e414d45223a2264656d6973746966792d6261636b656e64222c224c414e47223a22432e5554462d38222c224f50454e5f524f555445525f4150495f4b4559223a22736b2d6f722d76312d33313861303231363233663131616338653639333333383732303362353166613939653234663065363261656137636430646464623735623036623436326136222c2250415448223a222f7573722f6c6f63616c2f62696e3a2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e222c22505954484f4e5f534841323536223a2237323230383335643966393062333763303036653938343261386466663435383061616361343331383637346639343733303262386432386633663831313132222c22505954484f4e5f56455253494f4e223a22332e31322e39222c2253494d554c4154455f4154544553544154494f4e223a2266616c7365222c22574542335f50524f56494445525f55524c223a2268747470733a2f2f636f73746f6e322d6170692e666c6172652e6e6574776f726b2f6578742f432f727063227d2c2261726773223a5b222f7573722f62696e2f73757065727669736f7264222c222d63222c222f6574632f73757065727669736f722f636f6e662e642f73757065727669736f72642e636f6e66225d7d2c22676365223a7b227a6f6e65223a2275732d63656e7472616c312d61222c2270726f6a6563745f6964223a2276657269666961626c652d61692d6861636b6174686f6e222c2270726f6a6563745f6e756d626572223a22333635383337383137383239222c22696e7374616e63655f6e616d65223a2264656d6973746966792d6261636b656e64222c22696e7374616e63655f6964223a2236343835353034373835393133353939373733227d7d2c22676f6f676c655f736572766963655f6163636f756e7473223a5b22636f6e666964656e7469616c2d73614076657269666961626c652d61692d6861636b6174686f6e2e69616d2e67736572766963656163636f756e742e636f6d225d7d";

    bytes constant SIGNATURE =
        hex"1ab2ce08e5577834fd0b5d443de68e2e144a6e89751823071b2f6da85708bd98f7c813b5e568d909032d3aa547b8bb4d2d5186d21a459616a5053275e4a0bf79a98e8e25334f63125634f574e6dff88513643e1b0eae95ca908bbc76280407bd8036f14cb7633184a990b63ebb826e693798db6c22d6b17d55da2c3d36f79f7e896a96ed0b5dbcdcbcd20e8f770b7ca692c5a817b5da855f20c4c061c3122b352c688bded599f9d7466e2ac198654583512c8cc4053617d977467f06000292bdb620d5140cf8ae4eeb884c9c8e02214afcf450ec7030cf67f872290a1483557aac43907b27afac6b7a318481aff945882c5ff95f7fcc0c0d5d1d5beacbde4b99";

    // Decoded components of the token for testing
    bytes32 constant DIGEST = 0xdad7ca6937b8f8c7080bdd350b0cd5af9f2030e89fc806c09b84e3b6a22726f3;
    uint256 constant EXP = 1741978706;
    uint256 constant IAT = 1741975106;

    // Example RSA public key components
    bytes constant TOKENTYPE = bytes("OIDC");
    bytes constant KID = bytes("999d2729ff7ffa251dfe4c3ecdf06e3bd1d97082"); // Key ID
    bytes constant E = hex"010001"; // Public exponent (65537)
    bytes constant N =
        hex"915ff7517b0953ffd8975e24356c0eb58222e5a5cfac30fa8c1c5fed1c62aeba0fc5dcbbea6e86a751eb1d0c2ac1f6096c351df92f48a71f15c28f79a0345d8639e98caf3303c44f313861c071eb2206cf89cd2d074b7a7ffad435dc371b04bd64c685351c19b3713bf02fb3455c13b2370473a947f34f035b216bc05f3d74209c774a122318ba4e16e828c3a33c53abed680bd42ac0e9aa08a98e95fbac4b8d7bcaa1ff663431641db36da396762b62103b4dfa55da16705ab22382e7564b8d9fdef84e6d2405308573dc6a3c55b171060dd04ce9c9e6826b079850ae0faacebd4b111f926bd7cef924df16df7cc7950437cb2790892a5558bb72a313e85f53"; // Modulus

    // Example configuration for a Confidential Space TEE
    string constant ISS = "https://confidentialcomputing.googleapis.com";
    string constant HWMODEL = "GCP_AMD_SEV";
    string constant SWNAME = "CONFIDENTIAL_SPACE";
    string constant IMAGEDIGEST = "sha256:69c6c9415f4d7ad757a75b84d41f5cc33b93272cc815efa1892f31ee73125a8c";
    bool constant SECBOOT = true;

    /**
     * @dev Sets up the test environment by deploying the FlareVtpmAttestation contract
     * and initializing it with test data.
     */
    function setUp() public {
        // Deploy the FlareVtpmAttestation contract
        flareVtpm = new FlareVtpmAttestation();

        // Set the required vTPM configuration in the contract
        flareVtpm.setBaseQuoteConfig(HWMODEL, SWNAME, IMAGEDIGEST, ISS, SECBOOT);

        // Deploy the OIDC signature verifier and register it with the contract
        oidcVerifier = new OidcSignatureVerification();
        flareVtpm.setTokenTypeVerifier(address(oidcVerifier));

        // Add the RSA public key to the verifier's key registry
        oidcVerifier.addPubKey(KID, E, N);

        // Set current block time between issued and expiry time for testing
        vm.warp((IAT + EXP) / 2);
    }

    /**
     * @dev Tests the verifySignature function to ensure that the RSA signature
     * is correctly verified and that the digest matches the expected value.
     */
    function test_verifySignature() public view {
        Header memory header = Header({kid: KID, tokenType: TOKENTYPE});
        (bool verified, bytes32 digest) = oidcVerifier.verifySignature(HEADER, PAYLOAD, SIGNATURE, header);

        // Verify that the RSA signature is valid
        assertTrue(verified, "RSA signature could not be verified");

        // Verify that the computed digest matches the expected digest
        assertEq(digest, DIGEST, "Invalid digest");
    }

    /**
     * @dev Tests the verifyAndAttest function to ensure that a full verification and attestation
     * process succeeds.
     */
    function test_verifyAndAttest_Success() public {
        // Perform the verification and attestation
        bool success = flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);

        // Verify that the function returned true
        assertTrue(success, "Verification and attestation failed");

        // Verify that the registered quote matches the expected configuration
        QuoteConfig memory registeredConfig = flareVtpm.getRegisteredQuote(address(this));
        assertEq(registeredConfig.exp, EXP, "Invalid registered exp");
        assertEq(registeredConfig.iat, IAT, "Invalid registered iat");
        assertEq0(registeredConfig.base.hwmodel, bytes(HWMODEL), "Invalid registered hwmodel");
        assertEq0(registeredConfig.base.swname, bytes(SWNAME), "Invalid registered swname");
        assertEq0(registeredConfig.base.imageDigest, bytes(IMAGEDIGEST), "Invalid registered image digest");
        assertEq0(registeredConfig.base.iss, bytes(ISS), "Invalid registered iss");
        assertEq(registeredConfig.base.secboot, SECBOOT, "Invalid registered secboot");
    }

    /**
     * @dev Tests the verifyAndAttest function to revert on an expired token.
     */
    function test_verifyAndAttest_InvalidExp() public {
        // Set the block time after the token's expiration
        vm.warp(EXP + 1);

        // Expect the function to revert with PayloadValidationFailed error
        vm.expectRevert(abi.encodeWithSelector(PayloadValidationFailed.selector, "Invalid expiry time"));

        // Attempt to perform verification and attestation
        flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);
    }

    /**
     * @dev Tests the verifyAndAttest function to revert on a token issued in the future.
     */
    function test_verifyAndAttest_InvalidIat() public {
        // Set the block time before the token's issuance
        vm.warp(IAT - 1);

        // Expect the function to revert with PayloadValidationFailed error
        vm.expectRevert(abi.encodeWithSelector(PayloadValidationFailed.selector, "Invalid issued at time"));

        // Attempt to perform verification and attestation
        flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);
    }

    /**
     * @dev Tests the verifyAndAttest function to revert when the signature is invalid.
     */
    function test_verifyAndAttest_InvalidSignature() public {
        // Modify the signature to make it invalid
        bytes memory invalidSignature = SIGNATURE;
        invalidSignature[0] = ~invalidSignature[0];

        // Expect the function to revert with SignatureVerificationFailed error
        vm.expectRevert(abi.encodeWithSelector(SignatureVerificationFailed.selector, "Signature does not match"));

        // Attempt to perform verification and attestation with invalid signature
        flareVtpm.verifyAndAttest(HEADER, PAYLOAD, invalidSignature);
    }

    /**
     * @dev Tests the verifyAndAttest function to revert when the required public key is not registered.
     */
    function test_verifyAndAttest_MissingPublicKey() public {
        // Remove the public key from the verifier
        oidcVerifier.removePubKey(KID);

        // Expect the function to revert with SignatureVerificationFailed error
        vm.expectRevert(abi.encodeWithSelector(SignatureVerificationFailed.selector, "Public key not found"));

        // Attempt to perform verification and attestation
        flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);
    }

    /**
     * @dev Tests the verifyAndAttest function to revert when the payload contains invalid issuer.
     */
    function test_verifyAndAttest_InvalidIssuer() public {
        // Modify the ISS to an invalid value
        string memory invalidIss = "https://invalid-issuer.com";
        bytes memory modifiedPayload = replaceInPayload(PAYLOAD, '"iss":"', '"', bytes(invalidIss));

        // Expect the function to revert with PayloadValidationFailed error
        vm.expectRevert(abi.encodeWithSelector(SignatureVerificationFailed.selector, "Signature does not match"));

        // Attempt to perform verification and attestation with modified payload
        flareVtpm.verifyAndAttest(HEADER, modifiedPayload, SIGNATURE);
    }

    /**
     * @dev Utility function to replace a value in the payload for testing purposes.
     * @param payload The original payload bytes.
     * @param key The key to search for in the payload.
     * @param delimiter The delimiter that indicates the end of the value.
     * @param newValue The new value to insert.
     * @return modifiedPayload The payload with the value replaced.
     */
    function replaceInPayload(bytes memory payload, string memory key, string memory delimiter, bytes memory newValue)
        internal
        pure
        returns (bytes memory modifiedPayload)
    {
        bytes memory keyBytes = bytes(key);
        bytes memory delimiterBytes = bytes(delimiter);

        uint256 start = indexOf(payload, keyBytes);
        require(start != type(uint256).max, "Key not found in payload");
        start += keyBytes.length;

        uint256 end = indexOf(payload, delimiterBytes) + start;
        require(end != type(uint256).max, "Delimiter not found in payload");

        // Create slices for the parts before `start` and after `end`
        bytes memory prefix = sliceMemoryArray(payload, 0, start);
        bytes memory suffix = sliceMemoryArray(payload, end, payload.length);

        // Concatenate the slices with the new value in the middle
        modifiedPayload = bytes.concat(prefix, newValue, suffix);
    }

    /**
     * @dev Extracts a slice from a memory array.
     * @param array The array to slice.
     * @param start The start index of the slice (inclusive).
     * @param end The end index of the slice (exclusive).
     * @return result The sliced portion of the array.
     */
    function sliceMemoryArray(bytes memory array, uint256 start, uint256 end)
        internal
        pure
        returns (bytes memory result)
    {
        require(start <= end && end <= array.length, "Invalid slice indices");

        result = new bytes(end - start);
        for (uint256 i = start; i < end; i++) {
            result[i - start] = array[i];
        }
    }

    /**
     * @dev Finds the index of the first occurrence of needle in haystack.
     * @param haystack The bytes sequence to search within.
     * @param needle The bytes sequence to search for.
     * @return index The index of the first occurrence, or uint256 max value if not found.
     */
    function indexOf(bytes memory haystack, bytes memory needle) internal pure returns (uint256) {
        if (needle.length == 0 || haystack.length < needle.length) {
            return type(uint256).max;
        }

        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return type(uint256).max;
    }
}
