import * as Utilities from './Utilities.js';
import * as guacutils from './guacutils.js';
import {WebSocket} from 'ws';
import {IPData} from './IPData.js';
import IConfig from './IConfig.js';
import RateLimiter from './RateLimiter.js';
import { execa, execaCommand, ExecaSyncError } from 'execa';
import log from './log.js';
import { createClient, RdpClient, RDPClientConfig } from 'node-rdpjs';
import RDPUser from './RDPUser.js';
import LDAPClient from './LDAP.js';
import { Canvas, CanvasRenderingContext2D, createCanvas, createImageData } from 'canvas';
import RDPUserDatabase from './RDPUserDatabase.js';

export class User {
    socket : WebSocket;
    nopSendInterval : NodeJS.Timeout;
    msgRecieveInterval : NodeJS.Timeout;
    nopRecieveTimeout? : NodeJS.Timeout;
    username? : string;
    connectedToNode : boolean;
    viewMode : number;
    rank : Rank;
    msgsSent : number;
    Config : IConfig;
    IP : IPData;
    RDPUser : RDPUser | null;
    RDPUsers : RDPUserDatabase;
    LDAP : LDAPClient;
    RDPClient : RdpClient | null;
    RDPReconnectInterval : NodeJS.Timeout | null;
    NoConnectionImg : string;
    // Rate limiters
    ChatRateLimit : RateLimiter;
    LoginRateLimit : RateLimiter;
    RenameRateLimit : RateLimiter;
    TurnRateLimit : RateLimiter;
    VoteRateLimit : RateLimiter;
    constructor(ws : WebSocket, ip : IPData, config : IConfig, rdpusers : RDPUserDatabase, LDAP : LDAPClient, noconnectionimg : string, username? : string, node? : string) {
        this.IP = ip;
        this.connectedToNode = false;
        this.viewMode = -1;
        this.Config = config;
        this.socket = ws;
        this.msgsSent = 0;
        this.socket.on('close', () => {
            clearInterval(this.nopSendInterval);
        });
        this.socket.on('message', (e) => {
            clearTimeout(this.nopRecieveTimeout);
            clearInterval(this.msgRecieveInterval);
            this.msgRecieveInterval = setInterval(() => this.onNoMsg(), 10000);
        })
        this.nopSendInterval = setInterval(() => this.sendNop(), 5000);
        this.msgRecieveInterval = setInterval(() => this.onNoMsg(), 10000);
        this.sendNop();
        if (username) this.username = username;
        this.rank = 0;
        this.ChatRateLimit = new RateLimiter(this.Config.collabvm.automute.messages, this.Config.collabvm.automute.seconds);
        this.ChatRateLimit.on('limit', () => this.mute(false));
        this.RenameRateLimit = new RateLimiter(3, 60);
        this.RenameRateLimit.on('limit', () => this.closeConnection());
        this.LoginRateLimit = new RateLimiter(4, 3);
        this.LoginRateLimit.on('limit', () => this.closeConnection());
        this.TurnRateLimit = new RateLimiter(5, 3);
        this.TurnRateLimit.on('limit', () => this.closeConnection());
        this.VoteRateLimit = new RateLimiter(3, 3);
        this.VoteRateLimit.on('limit', () => this.closeConnection());

        this.RDPReconnectInterval = null;
        this.NoConnectionImg = noconnectionimg;
        this.RDPUsers = rdpusers;
        this.LDAP = LDAP;
        this.RDPClient = null;
        this.RDPUser = null;
    }
    connectRDP() {
        return new Promise<void>(async (res, rej) => {
            if (!this.username) {rej(); return;}
            if (this.RDPReconnectInterval) {
                clearTimeout(this.RDPReconnectInterval);
                this.RDPReconnectInterval = null;
            }

            if (this.RDPUser === null) this.RDPUser = await this.RDPUsers.getUser(this.IP.address);
            if (this.RDPUser === null) {
                this.RDPUser = {
                    Username: this.username + Utilities.Randint(10000000, 99999999),
                    Password: Utilities.Randstr(32),
                };
                await this.LDAP.createUser(this.RDPUser.Username, this.RDPUser.Password);
                this.RDPUsers.addUser(this.IP.address, this.RDPUser);
            }
            this.RDPClient = createClient({
                domain: this.Config.vm.ldapdomain,
                userName: this.RDPUser.Username,
                password: this.RDPUser.Password,
                enablePerf: false,
                autoLogin: true,
                decompress: true,
                screen: {
                    width: 1024,
                    height: 768,
                },
                locale: "en",
                logLevel: "INFO",
            });
            this.RDPClient.once('connect', () => {
                log("INFO", `RDP connection established for ${this.username}`);
                res();
            });
            this.RDPClient.once('error', (e) => {
                var err = e as Error;
                log("ERROR", `RDP connection error for ${this.username}: ${err.message}.`);
                return false;
            });
            this.RDPClient.once('close', () => {
                if (this.socket.readyState !== this.socket.OPEN) return;
                log("WARN", `RDP connection closed for ${this.username}. Reconnecting in 5 seconds`);
                if (this.RDPReconnectInterval) return;
                this.sendMsg(guacutils.encode("png", "0", "0", "0", "0", this.NoConnectionImg));
                this.RDPClient?.close();
                this.RDPClient = null;
                this.RDPReconnectInterval = setTimeout(() => this.connectRDP(), 5000);
            });
            this.RDPClient.on('bitmap', (bitmap) => {
                var imgdata = createImageData(Uint8ClampedArray.from(bitmap.data), bitmap.width, bitmap.height);
                var cnv = createCanvas(bitmap.width, bitmap.height);
                var ctx = cnv.getContext('2d');
                ctx.putImageData(imgdata, 0, 0);
                var b64 = cnv.toBuffer('image/jpeg').toString('base64');
                this.sendMsg(guacutils.encode("png", "0", "0", bitmap.destLeft.toString(), bitmap.destTop.toString(), b64));
                this.sendMsg(guacutils.encode("sync", Date.now().toString()));
            });
            this.RDPClient.connect(this.Config.vm.rdpip, 3389);
        });
    }
    assignGuestName(existingUsers : string[]) : string {
        var username;
        do {
            username = "guest" + Utilities.Randint(10000, 99999);
        } while (existingUsers.indexOf(username) !== -1);
        this.username = username;
        return username;
    }
    sendNop() {
        this.socket.send("3.nop;");
    }
    sendMsg(msg : string | Buffer) {
        if (this.socket.readyState !== this.socket.OPEN) return;
        clearInterval(this.nopSendInterval);
        this.nopSendInterval = setInterval(() => this.sendNop(), 5000);
        this.socket.send(msg);
    }
    private onNoMsg() {
        this.sendNop();
        this.nopRecieveTimeout = setTimeout(() => {
            this.closeConnection();
        }, 3000);
    }
    closeConnection() {
        this.socket.send(guacutils.encode("disconnect"));
        this.socket.close();
    }
    onMsgSent() {
        if (!this.Config.collabvm.automute.enabled) return;
        if (this.rank !== 0) return;
        this.ChatRateLimit.request();
    }
    mute(permanent : boolean) {
        this.IP.muted = true;
        this.sendMsg(guacutils.encode("chat", "", `You have been muted${permanent ? "" : ` for ${this.Config.collabvm.tempMuteTime} seconds`}.`));
        if (!permanent) {
            clearTimeout(this.IP.tempMuteExpireTimeout);
            this.IP.tempMuteExpireTimeout = setTimeout(() => this.unmute(), this.Config.collabvm.tempMuteTime * 1000);
        }
    }
    unmute() {
        clearTimeout(this.IP.tempMuteExpireTimeout);
        this.IP.muted = false;
        this.sendMsg(guacutils.encode("chat", "", "You are no longer muted."));
    }

    private banCmdArgs(arg: string) : string {
        return arg.replace(/\$IP/g, this.IP.address).replace(/\$NAME/g, this.username || "");
    }

    async ban() {
        // Prevent the user from taking turns or chatting, in case the ban command takes a while
        this.IP.muted = true;

        try {
            if (Array.isArray(this.Config.collabvm.bancmd)) {
                let args: string[] = this.Config.collabvm.bancmd.map((a: string) => this.banCmdArgs(a));
                if (args.length || args[0].length) {
                    await execa(args.shift()!, args, {stdout: process.stdout, stderr: process.stderr});
                    this.kick();
                } else {
                    log("ERROR", `Failed to ban ${this.IP.address} (${this.username}): Empty command`);
                }
            } else if (typeof this.Config.collabvm.bancmd == "string") {
                let cmd: string = this.banCmdArgs(this.Config.collabvm.bancmd);
                if (cmd.length) {
                    await execaCommand(cmd, {stdout: process.stdout, stderr: process.stderr});
                    this.kick();
                } else {
                    log("ERROR", `Failed to ban ${this.IP.address} (${this.username}): Empty command`);
                }
            }
        } catch (e) {
            log("ERROR", `Failed to ban ${this.IP.address} (${this.username}): ${(e as ExecaSyncError).shortMessage}`);
        }
    }
    
    async kick() {
        this.sendMsg("10.disconnect;");
        this.socket.close();
    }
}

export enum Rank {
    Unregistered = 0,
    Admin = 2,
    Moderator = 3,
    // Giving a good gap between server only internal ranks just in case
    Turn = 10,
}
