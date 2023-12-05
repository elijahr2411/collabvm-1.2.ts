import * as toml from 'toml';
import IConfig from './IConfig.js';
import * as fs from "fs";
import WSServer from './WSServer.js';
import log from './log.js';
import RDPUser from './RDPUser.js';
import LDAPClient from './LDAP.js';

log("INFO", "CollabVM Server starting up");

// Parse the config file

var Config : IConfig;

if (!fs.existsSync("config.toml")) {
    log("FATAL", "Config.toml not found. Please copy config.example.toml and fill out fields")
    process.exit(1);
}
try {
    var configRaw = fs.readFileSync("config.toml").toString();
    Config = toml.parse(configRaw);
} catch (e) {
    log("FATAL", `Failed to read or parse the config file: ${e}`);
    process.exit(1);
}


async function start() {
    var RDPUsers = new Map<string, RDPUser>();
    var ldap = new LDAPClient(Config.vm.ldapuri, Config.vm.ldapbind, Config.vm.ldappass, Config.vm.ldapdomain);
    await ldap.connect();
    // Start up the websocket server
    var WS = new WSServer(Config, RDPUsers, ldap);
    WS.listen();
}
start();