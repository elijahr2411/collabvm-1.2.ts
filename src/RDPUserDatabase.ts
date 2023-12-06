import sqlite3 from 'sqlite3';
import RDPUser from './RDPUser';

export default class RDPUserDatabase {
    #db : sqlite3.Database;
    constructor(filename : string) {
        this.#db = new sqlite3.Database(filename);
    }
    public init() : Promise<void> {
        return new Promise((res, rej) => {
            this.#db.run("CREATE TABLE IF NOT EXISTS users (ip TEXT PRIMARY KEY, username TEXT, password TEXT)", (err) => {
                if (err) rej(err);
                else res();
            });
        });
    }
    public getUser(ip : string) : Promise<RDPUser | null> {
        return new Promise((res, rej) => {
            this.#db.get("SELECT username, password FROM users WHERE ip = ?", ip, (err, row) => {
                if (err) rej(err);
                else if (row) {
                    var _user = row as {username : string, password : string};
                    var user : RDPUser = {
                        Username: _user.username,
                        Password: _user.password
                    };
                    res(user);
                } else res(null);
            });
        });
    }
    public addUser(ip : string, user : RDPUser) : Promise<void> {
        return new Promise((res, rej) => {
            this.#db.run("INSERT INTO users (ip, username, password) VALUES (?, ?, ?)", ip, user.Username, user.Password, (err : Error) => {
                if (err) rej(err);
                else res();
            });
        });
    }
}