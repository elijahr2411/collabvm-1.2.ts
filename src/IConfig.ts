export default interface IConfig {
    http : {
        host : string;
        port : number;
        proxying : boolean;
        proxyAllowedIps : string[];
        origin : boolean;
        originAllowedDomains : string[];
        maxConnections: number;
    };
    vm : {
        ldapuri : string;
        ldapbind : string;
        ldappass : string;
        ldapdomain : string;
        rdpip : string;
        rebootcmd : string;
        snapshots : boolean;
        resetcmd : string;
    };
    collabvm : {
        node : string;
        displayname : string;
        motd : string;
        bancmd : string | string[];
        moderatorEnabled : boolean;
        usernameblacklist : string[];
        maxChatLength : number;
        maxChatHistoryLength : number;
        automute : {
            enabled: boolean;
            seconds: number;
            messages: number;
        };
        tempMuteTime : number;
        voteTime : number;
        voteCooldown: number;
        adminpass : string;
        modpass : string;
        moderatorPermissions : Permissions;
    };
};

export interface Permissions {
    restore : boolean;
    reboot : boolean;
    ban : boolean;
    forcevote : boolean;
    mute : boolean;
    kick : boolean;
    rename : boolean;
    grabip : boolean;
    xss : boolean;
}