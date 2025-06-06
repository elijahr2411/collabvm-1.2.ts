import { VMState } from "@computernewb/superqemu";
import { VMDisplay } from "../display/interface.js";
import VM from "./interface.js";
import pino from "pino";
import { VncDisplay } from "../display/vnc.js";
import { EventEmitter } from "events";

export interface VirtServer2005VMDef {
    vncHost: string;
    vncPort: number;
    httpUrl: string;
    httpOverrideHost?: string;
    domain: string;
    username: string;
    password: string;
    vm: string;
}

export class VirtServer2005ApiClient {
    private host: string;
    private referer: string;
    private url: URL;
    private authHeader: string;

    constructor(def: VirtServer2005VMDef) {
        this.url = new URL(def.httpUrl);
        this.host = def.httpOverrideHost ?? this.url.host;
        this.referer = `http://${this.host}/VirtualServer/VSWebApp.exe?view=3`;
        this.authHeader = 'Basic ' + Buffer.from(`${def.domain}\\${def.username}:${def.password}`).toString('base64');
    }

    private async postVMAction(vm: string, action: string) {
        let res = await fetch(this.url, {
            method: "POST",
            headers: {
                'Authorization': this.authHeader,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': this.referer,
                'Host': this.host
            },
            body: new URLSearchParams({
                resp: '3',
                action,
                vm,
            })
        });
        if (!res.ok) {
            throw new Error(`Got HTTP ${res.status} when POSTing ${action} for ${vm}`);
        }
    }

    async startVM(vm: string) {
        await this.postVMAction(vm, 'poweron');
    }

    async stopVM(vm: string) {
        await this.postVMAction(vm, 'turnOffAndDiscard');
    }

    async resetVM(vm: string) {
        await this.postVMAction(vm, 'reset');
    }
}

export class VirtServer2005VM extends EventEmitter implements VM {
    private def: VirtServer2005VMDef;
    private logger;
	private vnc: VncDisplay | null = null;
	private state = VMState.Stopped;
    private api: VirtServer2005ApiClient;

    constructor(def: VirtServer2005VMDef) {
        super();
        this.def = def;
        this.logger = pino({ name: `CVMTS.VS2005VM` });
        this.api = new VirtServer2005ApiClient(def);
    }

	private Disconnect() {
		if (this.vnc) {
			this.vnc.Disconnect();
			this.vnc.removeAllListeners();
			this.vnc = null;
		}
	}

    async Start(): Promise<void> {
        this.Disconnect();
        this.SetState(VMState.Starting);
        await this.api.startVM(this.def.vm);
        this.SetState(VMState.Started);
    }

    async Stop(): Promise<void> {
        this.logger.info('Disconnecting');
        this.SetState(VMState.Stopping);
        this.Disconnect();
        await this.api.stopVM(this.def.vm);
        this.SetState(VMState.Stopped);
    }

    async Reboot(): Promise<void> {
        await this.api.resetVM(this.def.vm);
    }

    async Reset(): Promise<void> {
        await this.api.stopVM(this.def.vm);
        await this.api.startVM(this.def.vm);
    }

    async MonitorCommand(command: string): Promise<any> {
        // TODO: basic shell thingy?
		return 'This VM does not support monitor commands.';
    }

	StartDisplay(): void {
		this.logger.info('Connecting to VNC server');
		let self = this;

		this.vnc = new VncDisplay({
			host: this.def.vncHost,
			port: this.def.vncPort,
			path: null,
            auth: {
                domain: this.def.domain,
                username: this.def.username,
                password: this.def.password,
                vm: this.def.vm
            }
		});

		self.vnc!.on('connected', () => {
			self.logger.info('Connected to VNC server');
			self.SetState(VMState.Started);
		});

		self.vnc!.Connect();
	}

    GetDisplay(): VMDisplay | null {
        return this.vnc;
    }
    
    GetState(): VMState {
        return this.state;
    }

    SnapshotsSupported(): boolean {
        return true;
    }

    Events(): EventEmitter {
        return this;
    }


	private SetState(newState: VMState) {
		this.state = newState;
		this.emit('statechange', newState);
	}
}
