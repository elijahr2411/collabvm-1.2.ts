import ldap from 'ldapjs';
export default class LDAPClient {
    #host : string;
    #bind : string;
    #pass : string;
    #domain : string;
    #connected : boolean = false;
    #ldap : ldap.Client;
    constructor(host : string, bind : string, pass : string, domain : string) {
        this.#host = host;
        this.#bind = bind;
        this.#pass = pass;
        this.#domain = domain;
        this.#ldap = ldap.createClient({
            url: this.#host,
            reconnect: true,
            tlsOptions: {
                rejectUnauthorized: false,
            },
        });
    }
    public connect() {
        return new Promise<void>((res, rej) => {
            this.#ldap.bind(this.#bind, this.#pass, (err) => {
                if (err) {
                    rej(err);
                } else {
                    this.#connected = true;
                    res();
                }
            });
        });
    }
    public createUser(username : string, password : string) {
        return new Promise<void>((res, rej) => {
            var pass = Buffer.from(`"${password}"`, 'utf16le');
            const dn = `CN=${username},CN=Users,dc=${this.#domain.split('.').join(',dc=')}`;
            const entry = {
                cn: username,
                sAMAccountName: username,
                objectClass: ['top', 'person', 'organizationalPerson', 'user'],
                unicodePwd: pass,
                userAccountControl: (512 | 65536)
            };
            this.#ldap.add(dn, entry, (err) => {
                if (err) {
                    rej(err);
                } else res();
            });
        });

    }
    public isConnected() : boolean {
        return this.#connected;
    }
}
