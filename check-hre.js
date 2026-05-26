import hre from "hardhat";
console.log("ConfigFile loaded:", hre.config?.paths?.configFile);
console.log("Plugins defined in config:", hre.config?.plugins);
console.log("HRE keys:", Object.keys(hre));
console.log("viem present?", !!hre.viem);
process.exit(0);
