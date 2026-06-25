import { expect } from "chai";
import hre from "hardhat";

describe("Anvil / Hardhat Local Network Verifications", function () {
  it("debe conectar exitosamente y el Chain ID debe ser 31337", async function () {
    const publicClient = await hre.viem.getPublicClient();
    const chainId = await publicClient.getChainId();
    expect(chainId).to.equal(31337);
  });

  it("debe poder obtener el número de bloque actual", async function () {
    const publicClient = await hre.viem.getPublicClient();
    const blockNumber = await publicClient.getBlockNumber();
    expect(Number(blockNumber)).to.be.at.least(0);
  });

  it("debe tener wallets locales inicializadas con fondos (ETH)", async function () {
    const walletClients = await hre.viem.getWalletClients();
    expect(walletClients.length).to.be.greaterThan(0);

    const firstWallet = walletClients[0];
    const publicClient = await hre.viem.getPublicClient();
    const balance = await publicClient.getBalance({ address: firstWallet.account.address });
    
    // Al menos 1 ETH
    expect(balance).to.be.greaterThan(10n ** 18n);
  });
});
