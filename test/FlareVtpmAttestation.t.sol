// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {FlareVtpmAttestation} from "../src/FlareVtpmAttestation.sol";
import {VtpmConfig, SignatureVerificationFailed, PayloadValidationFailed} from "../src/types/VtpmStructs.sol";

/**
 * @title FlareVtpmAttestationTest
 * @dev Test suite for the FlareVtpmAttestation contract.
 */
contract FlareVtpmAttestationTest is Test {
    /// @notice Instance of the contract to be tested
    FlareVtpmAttestation public flareVtpm;

    // Example attestation token components for testing
    bytes constant HEADER =
        hex"7b22616c67223a225253323536222c226b6964223a2234363736633439306463343338323936333635393534343265393363646335643237616161323739222c22747970223a224a5754227d";
    bytes constant PAYLOAD =
        hex"7b22617564223a2268747470733a2f2f7374732e676f6f676c652e636f6d222c22657870223a313733303638313631322c22696174223a313733303637383031322c22697373223a2268747470733a2f2f636f6e666964656e7469616c636f6d707574696e672e676f6f676c65617069732e636f6d222c226e6266223a313733303637383031322c22737562223a2268747470733a2f2f7777772e676f6f676c65617069732e636f6d2f636f6d707574652f76312f70726f6a656374732f666c6172652d6e6574776f726b2d73616e64626f782f7a6f6e65732f75732d63656e7472616c312d622f696e7374616e6365732f746573742d636f6e666964656e7469616c222c226561745f6e6f6e6365223a22307830303030303030303030303030303030303030303030303030303030303030303030303064456144222c226561745f70726f66696c65223a2268747470733a2f2f636c6f75642e676f6f676c652e636f6d2f636f6e666964656e7469616c2d636f6d707574696e672f636f6e666964656e7469616c2d73706163652f646f63732f7265666572656e63652f746f6b656e2d636c61696d73222c22736563626f6f74223a747275652c226f656d6964223a31313132392c2268776d6f64656c223a224743505f414d445f534556222c2273776e616d65223a22434f4e464944454e5449414c5f5350414345222c22737776657273696f6e223a5b22323430393030225d2c2264626773746174223a22656e61626c6564222c227375626d6f6473223a7b22636f6e666964656e7469616c5f7370616365223a7b226d6f6e69746f72696e675f656e61626c6564223a7b226d656d6f7279223a66616c73657d7d2c22636f6e7461696e6572223a7b22696d6167655f7265666572656e6365223a22676863722e696f2f64696e65736870696e746f2f746573742d636f6e666964656e7469616c3a6d61696e222c22696d6167655f646967657374223a227368613235363a61663733386664646433316562653438656434643865633933366632343231323738353064366230316161363861316663396264656239633036336665623763222c22726573746172745f706f6c696379223a224e65766572222c22696d6167655f6964223a227368613235363a37626362306539396530386333346337353931396136353430633261303763316464383434636433376639323763663066353838663064333566633666316562222c22656e765f6f76657272696465223a7b2241554449454e4345223a2268747470733a2f2f7374732e676f6f676c652e636f6d222c224e4f4e4345223a22307830303030303030303030303030303030303030303030303030303030303030303030303064456144227d2c22656e76223a7b2241554449454e4345223a2268747470733a2f2f7374732e676f6f676c652e636f6d222c224750475f4b4559223a2237313639363035463632433735313335364430353441323641383231453638304535464136333035222c22484f53544e414d45223a22746573742d636f6e666964656e7469616c222c224c414e47223a22432e5554462d38222c224e4f4e4345223a22307830303030303030303030303030303030303030303030303030303030303030303030303064456144222c2250415448223a222f7573722f6c6f63616c2f62696e3a2f7573722f6c6f63616c2f7362696e3a2f7573722f6c6f63616c2f62696e3a2f7573722f7362696e3a2f7573722f62696e3a2f7362696e3a2f62696e222c22505954484f4e5f534841323536223a2232343838376239326532616664346132616336303234313961643462353936333732663637616339623037373139306634353961626133393066616635353530222c22505954484f4e5f56455253494f4e223a22332e31322e37227d2c2261726773223a5b227576222c2272756e222c226174746573746174696f6e2e7079225d7d2c22676365223a7b227a6f6e65223a2275732d63656e7472616c312d62222c2270726f6a6563745f6964223a22666c6172652d6e6574776f726b2d73616e64626f78222c2270726f6a6563745f6e756d626572223a223833363734353137383736222c22696e7374616e63655f6e616d65223a22746573742d636f6e666964656e7469616c222c22696e7374616e63655f6964223a2232333039303234353433373130343933343837227d7d2c22676f6f676c655f736572766963655f6163636f756e7473223a5b2238333637343531373837362d636f6d7075746540646576656c6f7065722e67736572766963656163636f756e742e636f6d225d7d";
    bytes constant SIGNATURE =
        hex"7f65406db365d4df42bcbebd1c9ccd2b3a9dc68e3154af4854168eed6c29d200fc2fc20aaefa92533cd713f82ec378695f67a71274d41332fa3ea2e3d1bbc207c94c730a202af867576abe5a03921e7de43cc66d86b9d35ed35aac83aa6454c5b72dc7905363091a04da2b28b12e2b7fd40b800480e42e0048519452e15984e0c2ebcb0059307c98691de2a4ce445f32cb9fb68bf26038265542128a24b6845f0bd466625760ee62d8e9247054a86274b562f7e86c58bccee891229ab1f9cbf9683188ea2f758978e4e362e3738fbb05857f80bb1ffa9de506f704abd7acf9d1855135072de5268415dda5169281181690e805e973682e5e26a2f2016702e0bc";
    // Decoded components of the token for testing
    bytes32 constant DIGEST = 0x010b9c426d538b9f48c9d5aefc5bc2e7d9f7870773619ecbe0a8c39509c9663e;
    uint256 constant EXP = 1730681612;
    uint256 constant IAT = 1730678012;

    // Example RSA public key components
    bytes constant KID = bytes("4676c490dc43829636595442e93cdc5d27aaa279"); // Key ID
    bytes constant E = hex"010001"; // Public exponent
    bytes constant N =
        hex"d18d190543021f236db73c2be2121d8c4908ac069a2ac985f8761e7e116a46b1b66e3024b947a1cc593188e4895447217bc5a2793115ed29ac8e0e5a988094dd937bda1ab89de7c20dd22963bca94d9427602c38af72a87d3ded2eaa4ac15fd2059649ef1a8e4f5e4d96e7e7045f3e520cb3ae742e335c81102556a27ce89a082306f610792a4635b7b40f137e4d0ad1d9faaf251908afe9cb15791ef5ee8b0652f19a79db1eaacadfa2001ad830c7b3e30b89c04ecd289841504fe8ef317a82d4c8a38ebed355a51bef30255b9ab3d42cd3fad63a715e369cdb602f393af9c18775749ed1ec910ca0235e2397a1c0a5bab04bfdf620e649b8e23018589b93c9"; // Modulus

    // Example configuration for a Confidential Space TEE
    string constant ISS = "https://confidentialcomputing.googleapis.com";
    string constant HWMODEL = "GCP_AMD_SEV";
    string constant SWNAME = "CONFIDENTIAL_SPACE";
    string constant IMAGEDIGEST = "sha256:af738fddd31ebe48ed4d8ec936f242127850d6b01aa68a1fc9bdeb9c063feb7c";
    bool constant SECBOOT = true;

    /**
     * @dev Sets up the test environment by deploying the FlareVtpmAttestation contract
     * and initializing it with test data.
     */
    function setUp() public {
        // Deploy the FlareVtpmAttestation contract
        flareVtpm = new FlareVtpmAttestation();
        // Set current block time between issued and expiry time
        vm.warp((IAT + EXP) / 2);

        // Set the required vTPM configuration in the contract
        flareVtpm.setBaseVtpmConfig(HWMODEL, SWNAME, IMAGEDIGEST, ISS, SECBOOT);

        // Add the RSA public key to the contract's key registry
        flareVtpm.addOidcPubKey(KID, E, N);
    }

    /**
     * @dev Tests the verifyRsaSignature function to ensure that the RSA signature
     * is correctly verified and that the digest matches the expected value.
     */
    function test_verifyRsaSignature() public view {
        (bool verified, bytes32 digest) = flareVtpm.verifyRsaSignature(HEADER, PAYLOAD, SIGNATURE, KID);

        // Verify that the RSA signature is valid
        assertEq(verified, true, "RSA signature could not be verified");

        // Verify that the computed digest matches the expected digest
        assertEq(digest, DIGEST, "Invalid digest");
    }

    /**
     * @dev Tests the parseHeader function to ensure that the Key ID (kid) is correctly extracted from the JWT header.
     */
    function test_parseHeader() public view {
        bytes memory kid = flareVtpm.parseHeader(HEADER);
        assertEq(kid, KID, "Invalid kid");
    }

    /**
     * @dev Tests the parsePayload function to ensure that the payload is correctly parsed
     * and that the extracted values match the expected configuration.
     */
    function test_parsePayload() public view {
        VtpmConfig memory config = flareVtpm.parsePayload(PAYLOAD);

        assertEq(config.exp, EXP, "Invalid exp");
        assertEq(config.iat, IAT, "Invalid iat");
        assertEq(config.base.hwmodel, bytes(HWMODEL), "Invalid hwmodel");
        assertEq(config.base.swname, bytes(SWNAME), "Invalid swname");
        assertEq(config.base.imageDigest, bytes(IMAGEDIGEST), "Invalid image digest");
        assertEq(config.base.iss, bytes(ISS), "Invalid iss");
        assertEq(config.base.secboot, SECBOOT, "Invalid secboot");
    }

    /**
     * @dev Tests the verifyAndAttest function to ensure that a full verification and attestation
     * process succeeds.
     */
    function test_verifyAndAttest() public {
        bool success = flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);
        assertEq(success, true, "Verification and attestation failed");
    }

    /**
     * @dev Tests the verifyAndAttest function to revert on an expired token.
     */
    function test_verifyAndAttest_invalidExp() public {
        vm.warp(EXP + 1);
        vm.expectRevert(abi.encodeWithSelector(PayloadValidationFailed.selector, "invalid 'exp' in payload"));
        flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);
    }

    /**
     * @dev Tests the verifyAndAttest function to revert on an invalid iat.
     */
    function test_verifyAndAttest_invalidIat() public {
        vm.warp(IAT - 1);
        vm.expectRevert(abi.encodeWithSelector(PayloadValidationFailed.selector, "invalid 'iat' in payload"));
        flareVtpm.verifyAndAttest(HEADER, PAYLOAD, SIGNATURE);
    }
}
