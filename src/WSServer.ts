import {WebSocketServer, WebSocket} from 'ws';
import * as http from 'http';
import IConfig from './IConfig.js';
import internal from 'stream';
import * as Utilities from './Utilities.js';
import { User, Rank } from './User.js';
import * as guacutils from './guacutils.js';
// I hate that you have to do it like this
import CircularBuffer from 'mnemonist/circular-buffer.js';
import { createHash } from 'crypto';
import { isIP } from 'net';
import { IPData } from './IPData.js';
import { readFileSync } from 'fs';
import log from './log.js';
import { fileURLToPath } from 'url';
import path from 'path';
import RDPUser from './RDPUser.js';
import LDAPClient from './LDAP.js';
import Scancodes from './Scancode.js';
import RDPUserDatabase from './RDPUserDatabase.js';
import { execa, execaCommand } from 'execa';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default class WSServer {
    private Config : IConfig;
    private server : http.Server;
    private socket : WebSocketServer;
    private clients : User[];
    private ips : IPData[];
    private ChatHistory : CircularBuffer<{user:string,msg:string}>
    private voteInProgress : boolean;
    // Interval to keep track of vote resets
    private voteInterval? : NodeJS.Timeout;
    // How much time is left on the vote
    private voteTime : number;
    // How much time until another reset vote can be cast
    private voteCooldown : number;
    // Interval to keep track
    private voteCooldownInterval? : NodeJS.Timeout;
    private ModPerms : number;
    private noConnectionImg : string;
    private thumbnail : string;
    private rdpusers : RDPUserDatabase
    private LDAP : LDAPClient;
    constructor(config : IConfig, rdpusers : RDPUserDatabase, LDAP : LDAPClient) {
        this.Config = config;
        this.ChatHistory = new CircularBuffer<{user:string,msg:string}>(Array, this.Config.collabvm.maxChatHistoryLength);
        this.clients = [];
        this.ips = [];
        this.ModPerms = Utilities.MakeModPerms(this.Config.collabvm.moderatorPermissions);
        this.server = http.createServer();
        this.socket = new WebSocketServer({noServer: true});
        this.server.on('upgrade', (req : http.IncomingMessage, socket : internal.Duplex, head : Buffer) => this.httpOnUpgrade(req, socket, head));
        this.server.on('request', (req, res) => {
            res.writeHead(426);
            res.write("This server only accepts WebSocket connections.");
            res.end();
        });
        this.socket.on('connection', (ws : WebSocket, req : http.IncomingMessage) => this.onConnection(ws, req));
        this.noConnectionImg = readFileSync(__dirname + "/../assets/noconnection.jpeg").toString("base64");
        this.thumbnail = readFileSync(__dirname + "/../assets/thumbnail.jpeg").toString("base64");
        this.rdpusers = rdpusers;
        this.LDAP = LDAP;

        this.voteInProgress = false;
        this.voteTime = 0;
        this.voteCooldown = 0;
    }

    listen() {
        this.server.listen(this.Config.http.port, this.Config.http.host);
    }

    private httpOnUpgrade(req : http.IncomingMessage, socket : internal.Duplex, head : Buffer) {
        var killConnection = () => {
            socket.write("HTTP/1.1 400 Bad Request\n\n400 Bad Request");
            socket.destroy();
        }

        if (req.headers['sec-websocket-protocol'] !== "guacamole") {
            killConnection();
            return;
        }

        if (this.Config.http.origin) {
            // If the client is not sending an Origin header, kill the connection.
            if(!req.headers.origin) {
                killConnection();
                return;
            }

            // Try to parse the Origin header sent by the client, if it fails, kill the connection.
            var _host;
            try {
                _host = new URL(req.headers.origin.toLowerCase()).hostname;
            } catch {
                killConnection();
                return;
            }

            // If the domain name is not in the list of allowed origins, kill the connection.
            if(!this.Config.http.originAllowedDomains.includes(_host)) {
                killConnection();
                return;
            }
        }

        if (this.Config.http.proxying) {
            // If the requesting IP isn't allowed to proxy, kill it
            //@ts-ignore
            if (this.Config.http.proxyAllowedIps.indexOf(req.socket.remoteAddress) === -1) {
                killConnection();
                return;
            }
            var _ip;
            try {
                // Get the first IP from the X-Forwarded-For variable
                _ip = req.headers["x-forwarded-for"]?.toString().replace(/\ /g, "").split(",")[0];
            } catch {
                // If we can't get the IP, kill the connection
                killConnection();
                return;
            }
            // If for some reason the IP isn't defined, kill it
            if (!_ip) {
                killConnection();
                return;
            }
            // Make sure the IP is valid. If not, kill the connection.
            if (!isIP(_ip)) {
                killConnection();
                return;
            }
            //@ts-ignore
            req.proxiedIP = _ip;
        }

        let ip: string;
        if (this.Config.http.proxying) {
            //@ts-ignore
            if (!req.proxiedIP) return;
            //@ts-ignore
            ip = req.proxiedIP;
        } else {
            if (!req.socket.remoteAddress) return;
            ip = req.socket.remoteAddress;
        }

        //@ts-ignore
        req.IP = ip;

        // Get the amount of active connections coming from the requesting IP.
        let connections = this.clients.filter(client => client.IP.address == ip);
        // If it exceeds the limit set in the config, reject the connection with a 429.
        if(connections.length + 1 > this.Config.http.maxConnections) {
            socket.write("HTTP/1.1 429 Too Many Requests\n\n429 Too Many Requests");
            socket.destroy();
        }

        this.socket.handleUpgrade(req, socket, head, (ws: WebSocket) => this.socket.emit('connection', ws, req));
    }

    private onConnection(ws : WebSocket, req: http.IncomingMessage) {
        //@ts-ignore
        var _ipdata = this.ips.filter(data => data.address == req.IP);
        var ipdata;
        if(_ipdata.length > 0) {
            ipdata = _ipdata[0];
        }else{
            //@ts-ignore
            ipdata = new IPData(req.IP);
            this.ips.push(ipdata);
        }

        var user = new User(ws, ipdata, this.Config, this.rdpusers, this.LDAP, this.noConnectionImg);
        this.clients.push(user);
        ws.on('error', (e) => {
            //@ts-ignore
            log("ERROR", `${e} (caused by connection ${req.IP})`);
            ws.close();
        });
        ws.on('close', () => this.connectionClosed(user));
        ws.on('message', (e) => {
            var msg;
            try {msg = e.toString()}
            catch {
                // Close the user's connection if they send a non-string message
                user.closeConnection();
                return;
            }
            this.onMessage(user, msg);
        });
        user.sendMsg(this.getAdduserMsg());
        log("INFO", `Connect from ${user.IP.address}`);
    };

    private connectionClosed(user : User) {
        this.clients.splice(this.clients.indexOf(user), 1);
        log("INFO", `Disconnect From ${user.IP.address}${user.username ? ` with username ${user.username}` : ""}`);
        if (user.RDPReconnectInterval !== null) clearTimeout(user.RDPReconnectInterval);
        if (user.RDPClient) user.RDPClient.close();
        if (!user.username) return;
        //@ts-ignore
        this.clients.forEach((c) => c.sendMsg(guacutils.encode("remuser", "1", user.username)));
    }
    private async onMessage(client : User, message : string) {
        var msgArr = guacutils.decode(message);
        if (msgArr.length < 1) return;
        switch (msgArr[0]) {
            case "list":
                client.sendMsg(guacutils.encode("list", this.Config.collabvm.node, this.Config.collabvm.displayname, this.thumbnail));
                break;
            case "connect":
                if (!client.username || msgArr.length !== 2 || msgArr[1] !== this.Config.collabvm.node) {
                    client.sendMsg(guacutils.encode("connect", "0"));
                    return;
                }
                client.connectedToNode = true;
                client.sendMsg(guacutils.encode("connect", "1", "1", "0", "0"));
                if (this.ChatHistory.size !== 0) client.sendMsg(this.getChatHistoryMsg());
                if (this.Config.collabvm.motd) client.sendMsg(guacutils.encode("chat", "", this.Config.collabvm.motd));
                client.sendMsg(guacutils.encode("size", "0", "1024", "768"));
                client.sendMsg(guacutils.encode("png", "0", "0", "0", "0", this.noConnectionImg));
                client.sendMsg(guacutils.encode("sync", Date.now().toString()));
                client.sendMsg(guacutils.encode("turn", "99999999999999", "1", client.username));
                client.connectRDP();
                break;
            case "rename":
                if (!client.RenameRateLimit.request()) return;
                if (client.connectedToNode && client.IP.muted) return;
                this.renameUser(client, msgArr[1]);
                break;
            case "chat":
                if (!client.username) return;
                if (client.IP.muted) return;
                if (msgArr.length !== 2) return;
                var msg = Utilities.HTMLSanitize(msgArr[1]);
                // One of the things I hated most about the old server is it completely discarded your message if it was too long
                if (msg.length > this.Config.collabvm.maxChatLength) msg = msg.substring(0, this.Config.collabvm.maxChatLength);
                if (msg.trim().length < 1) return;
                //@ts-ignore
                this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", client.username, msg)));
                this.ChatHistory.push({user: client.username, msg: msg});
                client.onMsgSent();
                break;
            case "mouse":
                if (!client?.RDPClient?.connected) return;
                var x = parseInt(msgArr[1]);
                var y = parseInt(msgArr[2]);
                var mask = parseInt(msgArr[3]);
                if (x === undefined || y === undefined || mask === undefined) return;
                client.RDPClient.sendPointerEvent(x, y, 1, ((mask & 1) !== 0));
                client.RDPClient.sendPointerEvent(x, y, 2, ((mask & 4) !== 0));
                client.RDPClient.sendPointerEvent(x, y, 3, ((mask & 2) !== 0));
                break;
            case "key":
                if (!client?.RDPClient?.connected) return;
                var keysym = parseInt(msgArr[1]);
                var down = parseInt(msgArr[2]);
                if (keysym === undefined || (down !== 0 && down !== 1)) return;
                //@ts-ignore
                if (Scancodes["0x" + keysym.toString(16).padStart(4, "0")] === undefined) return;
                //@ts-ignore
                var scancode = Scancodes["0x" + keysym.toString(16).padStart(4, "0")];
                client.RDPClient.sendKeyEventScancode(scancode, down === 1);
                break;
            case "vote":
                if (!this.Config.vm.snapshots) return;
                if (!client.connectedToNode) return;
                if (msgArr.length !== 2) return;
                if (!client.VoteRateLimit.request()) return;
                switch (msgArr[1]) {
                    case "1":
                        if (!this.voteInProgress) {
                            if (this.voteCooldown !== 0) {
                                client.sendMsg(guacutils.encode("vote", "3", this.voteCooldown.toString()));
                                return;
                            }
                            this.startVote();
                            this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", "", `${client.username} has started a vote to reset the VM.`)));
                        }
                        else if (client.IP.vote !== true)
                            this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", "", `${client.username} has voted yes.`)));
                        client.IP.vote = true;
                        break;
                    case "0":
                        if (!this.voteInProgress) return;
                        if (client.IP.vote !== false)
                            this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", "", `${client.username} has voted no.`)));
                        client.IP.vote = false;
                        break;
                }
                this.sendVoteUpdate();
                break;
            case "admin":
                if (msgArr.length < 2) return;
                switch (msgArr[1]) {
                    case "2":
                        // Login
                        if (!client.LoginRateLimit.request()) return;
                        if (msgArr.length !== 3) return;
                        var sha256 = createHash("sha256");
                        sha256.update(msgArr[2]);
                        var pwdHash = sha256.digest('hex');
                        sha256.destroy();
                        if (pwdHash === this.Config.collabvm.adminpass) {
                            client.rank = Rank.Admin;
                            client.sendMsg(guacutils.encode("admin", "0", "1"));
                        } else if (this.Config.collabvm.moderatorEnabled && pwdHash === this.Config.collabvm.modpass) {
                            client.rank = Rank.Moderator;
                            client.sendMsg(guacutils.encode("admin", "0", "3", this.ModPerms.toString()));
                        } else {
                            client.sendMsg(guacutils.encode("admin", "0", "0"));
                            return;
                        }
                        //@ts-ignore
                        this.clients.forEach((c) => c.sendMsg(guacutils.encode("adduser", "1", client.username, client.rank)));
                        break;
                    case "5":
                        // QEMU Monitor
                        client.sendMsg(guacutils.encode("admin", "2", "This is not a QEMU VM and therefore QEMU monitor commands cannot be run."));
                        break;
                    case "8":
                        // Restore
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.restore)) return;
                        execaCommand(this.Config.vm.resetcmd);
                        break;
                    case "10":
                        // Reboot
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.reboot)) return;
                        if (msgArr.length !== 3 || msgArr[2] !== this.Config.collabvm.node) return;
                        execaCommand(this.Config.vm.rebootcmd);
                        break;
                    case "8":
                        // Restore
                        client.sendMsg(guacutils.encode("chat", "Resets are not supported. If the VM is broken, please contact @elijahr.dev on Discord."));
                        break;
                    case "10":
                        // Reboot
                        // TODO: Some WMI stuff
                        break;
                    case "12":
                        // Ban
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.ban)) return;
                        var user = this.clients.find(c => c.username === msgArr[2]);
                        if (!user) return;
                        user.ban();
                        break;
                    case "14":
                        // Mute
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.mute)) return;
                        if (msgArr.length !== 4) return;
                        var user = this.clients.find(c => c.username === msgArr[2]);
                        if (!user) return;
                        var permamute;
                        switch (msgArr[3]) {
                            case "0":
                                permamute = false;
                                break;
                            case "1":
                                permamute = true;
                                break;
                            default:
                                return;
                        }
                        user.mute(permamute);
                        break;
                    case "15":
                        // Kick
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.kick)) return;
                        var user = this.clients.find(c => c.username === msgArr[2]);
                        if (!user) return;
                        user.kick();
                        break;
                    case "18":
                        // Rename user
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.rename)) return;
                        if (msgArr.length !== 4) return;
                        var user = this.clients.find(c => c.username === msgArr[2]);
                        if (!user) return;
                        this.renameUser(user, msgArr[3]);
                        break;
                    case "19":
                        // Get IP
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.grabip)) return;
                        if (msgArr.length !== 3) return;
                        var user = this.clients.find(c => c.username === msgArr[2]);
                        if (!user) return;
                        client.sendMsg(guacutils.encode("admin", "19", msgArr[2], user.IP.address));
                        break;
                    case "21":
                        // XSS
                        if (client.rank !== Rank.Admin && (client.rank !== Rank.Moderator || !this.Config.collabvm.moderatorPermissions.xss)) return;
                        if (msgArr.length !== 3) return;
                        switch (client.rank) {
                            case Rank.Admin:
                                //@ts-ignore
                                this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", client.username, msgArr[2])));
                                //@ts-ignore
                                this.ChatHistory.push({user: client.username, msg: msgArr[2]});
                                break;
                            case Rank.Moderator:
                                //@ts-ignore
                                this.clients.filter(c => c.rank !== Rank.Admin).forEach(c => c.sendMsg(guacutils.encode("chat", client.username, msgArr[2])));
                                //@ts-ignore
                                this.clients.filter(c => c.rank === Rank.Admin).forEach(c => c.sendMsg(guacutils.encode("chat", client.username, Utilities.HTMLSanitize(msgArr[2]))));
                                break;
                        }
                        break;
            }
            break;

        }
    }

    getUsernameList() : string[] {
        var arr : string[] = [];
        //@ts-ignore
        this.clients.filter(c => c.username).forEach((c) => arr.push(c.username));
        return arr;
    }

    renameUser(client : User, newName? : string) {
        // This shouldn't need a ternary but it does for some reason
        var hadName : boolean = client.username ? true : false;
        var oldname : any;
        if (hadName) oldname = client.username;
        var status = "0";
        if (!newName) {
            client.assignGuestName(this.getUsernameList());
        } else {
            newName = newName.trim();
            if (hadName && newName === oldname) {
                //@ts-ignore
                client.sendMsg(guacutils.encode("rename", "0", "0", client.username, client.rank));
                return;
            }
            if (this.getUsernameList().indexOf(newName) !== -1) {
                client.assignGuestName(this.getUsernameList());
                if(client.connectedToNode) {
                    status = "1";
                }
            } else
            if (!/^[a-zA-Z0-9\ \-\_\.]+$/.test(newName) || newName.length > 20 || newName.length < 3) {
                client.assignGuestName(this.getUsernameList());
                status = "2";
            } else
            if (this.Config.collabvm.usernameblacklist.indexOf(newName) !== -1) {
                client.assignGuestName(this.getUsernameList());
                status = "3";
            } else client.username = newName;
        }
        //@ts-ignore
        client.sendMsg(guacutils.encode("rename", "0", status, client.username, client.rank));
        if (hadName) {
            log("INFO", `Rename ${client.IP.address} from ${oldname} to ${client.username}`);
            this.clients.forEach((c) =>
            //@ts-ignore
            c.sendMsg(guacutils.encode("rename", "1", oldname, client.username, client.rank)));
        } else {
            log("INFO", `Rename ${client.IP.address} to ${client.username}`);
            this.clients.forEach((c) =>
            //@ts-ignore
            c.sendMsg(guacutils.encode("adduser", "1", client.username, client.rank)));
        }
    }

    getAdduserMsg() : string {
        var arr : string[] = ["adduser", this.clients.filter(c=>c.username).length.toString()];
        //@ts-ignore
        this.clients.filter(c=>c.username).forEach((c) => arr.push(c.username, c.rank));
        return guacutils.encode(...arr);
    }
    getChatHistoryMsg() : string {
        var arr : string[] = ["chat"];
        this.ChatHistory.forEach(c => arr.push(c.user, c.msg));
        return guacutils.encode(...arr);
    }
    startVote() {
        if (this.voteInProgress) return;
        this.voteInProgress = true;
        this.clients.forEach(c => c.sendMsg(guacutils.encode("vote", "0")));
        this.voteTime = this.Config.collabvm.voteTime;
        this.voteInterval = setInterval(() => {
            this.voteTime--;
            if (this.voteTime < 1) {
                this.endVote();
            }
        }, 1000);
    }

    endVote(result? : boolean) {
        if (!this.voteInProgress) return;
        this.voteInProgress = false;
        clearInterval(this.voteInterval);
        var count = this.getVoteCounts();
        this.clients.forEach((c) => c.sendMsg(guacutils.encode("vote", "2")));
        if (result === true || (result === undefined && count.yes >= count.no)) {
            this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", "", "The vote to reset the VM has won.")));
            execaCommand(this.Config.vm.resetcmd);
        } else {
            this.clients.forEach(c => c.sendMsg(guacutils.encode("chat", "", "The vote to reset the VM has lost.")));
        }
        this.clients.forEach(c => {
            c.IP.vote = null;
        });
        this.voteCooldown = this.Config.collabvm.voteCooldown;
        this.voteCooldownInterval = setInterval(() => {
            this.voteCooldown--;
            if (this.voteCooldown < 1)
                clearInterval(this.voteCooldownInterval);
        }, 1000);
    }

    sendVoteUpdate(client? : User) {
        if (!this.voteInProgress) return;
        var count = this.getVoteCounts();
        var msg = guacutils.encode("vote", "1", (this.voteTime * 1000).toString(), count.yes.toString(), count.no.toString());
        if (client)
            client.sendMsg(msg);
        else
            this.clients.forEach((c) => c.sendMsg(msg));
    }

    getVoteCounts() : {yes:number,no:number} {
        var yes = 0;
        var no = 0;
        this.ips.forEach((c) => {
            if (c.vote === true) yes++;
            if (c.vote === false) no++;
        });
        return {yes:yes,no:no};
    }
}
