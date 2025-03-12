const hre = require("hardhat");

async function main() {
  // Deploy the FlareVtpmAttestation contract
  const FlareVtpmAttestation = await hre.ethers.getContractFactory("FlareVtpmAttestation");
  const flareVtpmAttestation = await FlareVtpmAttestation.deploy();
  await flareVtpmAttestation.deployed();
  console.log("FlareVtpmAttestation deployed to:", flareVtpmAttestation.address);

  // Deploy a mock ERC20 token
  const MockERC20 = await hre.ethers.getContractFactory("MockERC20");
  const mockERC20 = await MockERC20.deploy();
  await mockERC20.deployed();
  console.log("MockERC20 deployed to:", mockERC20.address);

  // Deploy the MainContract
  const MainContract = await hre.ethers.getContractFactory("MainContract");
  const mainContract = await MainContract.deploy(flareVtpmAttestation.address, mockERC20.address);
  await mainContract.deployed();
  console.log("MainContract deployed to:", mainContract.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 