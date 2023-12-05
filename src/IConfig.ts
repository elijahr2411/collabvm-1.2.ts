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
        adminpass : string;
        modpass : string;
        moderatorPermissions : Permissions;
    };
};

export interface Permissions {
    ban : boolean;
    mute : boolean;
    kick : boolean;
    rename : boolean;
    grabip : boolean;
    xss : boolean;
}