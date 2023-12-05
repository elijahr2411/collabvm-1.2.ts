import { Permissions } from "./IConfig";

export function Randint(min : number, max : number) {
    return Math.floor((Math.random() * (max - min)) + min);
}

export function Randstr(length : number) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()<>?,./;':\"[]{}\\|`~-=_+";
    var result = "";
    for (var i = 0; i < length; i++) {
        result += chars.charAt(Randint(0, chars.length));
    }
    return result;
}
export function HTMLSanitize(input : string) : string {
    var output = "";
    for (var i = 0; i < input.length; i++) {
        switch (input[i]) {
            case "<":
                output += "&lt;"
                break;
            case ">":
                output += "&gt;"
                break;
            case "&":
                output += "&amp;"
                break;
            case "\"":
                output += "&quot;"
                break;
            case "'":
                output += "&#x27;";
                break;
            case "/":
                output += "&#x2F;";
                break;
            case "\n":
                output += "&#13;&#10;";
                break;
            default:
                var charcode : number = input.charCodeAt(i);
                if (charcode >= 32 && charcode <= 126)
                    output += input[i];
                break;
        }
    }
    return output;
}

export function MakeModPerms(modperms : Permissions) : number {
    var perms = 0;
    if (modperms.ban) perms |= 4;
    if (modperms.mute) perms |= 16;
    if (modperms.kick) perms |= 32;
    if (modperms.rename) perms |= 128;
    if (modperms.grabip) perms |= 256;
    if (modperms.xss) perms |= 512;
    return perms;
}