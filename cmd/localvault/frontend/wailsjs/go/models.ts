export namespace main {
	
	export class AddKeyPairInput {
	    accessKeyAlias: string;
	    accessKeyValue: string;
	    secretKeyAlias: string;
	    secretKeyValue: string;
	    providerKey: string;
	    environment: string;
	    description: string;
	    expiresAt?: number;
	
	    static createFrom(source: any = {}) {
	        return new AddKeyPairInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.accessKeyAlias = source["accessKeyAlias"];
	        this.accessKeyValue = source["accessKeyValue"];
	        this.secretKeyAlias = source["secretKeyAlias"];
	        this.secretKeyValue = source["secretKeyValue"];
	        this.providerKey = source["providerKey"];
	        this.environment = source["environment"];
	        this.description = source["description"];
	        this.expiresAt = source["expiresAt"];
	    }
	}
	export class AddKeyPairResult {
	    accessKeyId: number;
	    secretKeyId: number;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new AddKeyPairResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.accessKeyId = source["accessKeyId"];
	        this.secretKeyId = source["secretKeyId"];
	        this.err = source["err"];
	    }
	}
	export class AddSecretInput {
	    alias: string;
	    providerKey: string;
	    environment: string;
	    description: string;
	    value: string;
	    expiresAt?: number;
	    rotationDays?: number;
	
	    static createFrom(source: any = {}) {
	        return new AddSecretInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.alias = source["alias"];
	        this.providerKey = source["providerKey"];
	        this.environment = source["environment"];
	        this.description = source["description"];
	        this.value = source["value"];
	        this.expiresAt = source["expiresAt"];
	        this.rotationDays = source["rotationDays"];
	    }
	}
	export class AuditDTO {
	    seq: number;
	    ts: number;
	    actor: string;
	    action: string;
	    target: string;
	    outcome: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new AuditDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.seq = source["seq"];
	        this.ts = source["ts"];
	        this.actor = source["actor"];
	        this.action = source["action"];
	        this.target = source["target"];
	        this.outcome = source["outcome"];
	        this.detail = source["detail"];
	    }
	}
	export class BoolResult {
	    ok: boolean;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new BoolResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ok = source["ok"];
	        this.err = source["err"];
	    }
	}
	export class ColMapDTO {
	    alias: number;
	    value: number;
	    providerKey: number;
	    environment: number;
	    description: number;
	    expiresAt: number;
	
	    static createFrom(source: any = {}) {
	        return new ColMapDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.alias = source["alias"];
	        this.value = source["value"];
	        this.providerKey = source["providerKey"];
	        this.environment = source["environment"];
	        this.description = source["description"];
	        this.expiresAt = source["expiresAt"];
	    }
	}
	export class HealthDTO {
	    secretId: number;
	    alias: string;
	    status: string;
	    flags: string[];
	    score: number;
	    dupAliases: string[];
	
	    static createFrom(source: any = {}) {
	        return new HealthDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.secretId = source["secretId"];
	        this.alias = source["alias"];
	        this.status = source["status"];
	        this.flags = source["flags"];
	        this.score = source["score"];
	        this.dupAliases = source["dupAliases"];
	    }
	}
	export class IDResult {
	    id: number;
	    err?: string;
	
	    static createFrom(source: any = {}) {
	        return new IDResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.err = source["err"];
	    }
	}
	export class ImportCommitResult {
	    imported: number;
	    skipped: number;
	    duplicate: number;
	    invalid: number;
	    errors: string[];
	
	    static createFrom(source: any = {}) {
	        return new ImportCommitResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.imported = source["imported"];
	        this.skipped = source["skipped"];
	        this.duplicate = source["duplicate"];
	        this.invalid = source["invalid"];
	        this.errors = source["errors"];
	    }
	}
	export class ImportRowDTO {
	    sourceRow: number;
	    alias: string;
	    value: string;
	    providerKey: string;
	    environment: string;
	    description: string;
	    expiresAt?: number;
	    status: string;
	    statusNote: string;
	
	    static createFrom(source: any = {}) {
	        return new ImportRowDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sourceRow = source["sourceRow"];
	        this.alias = source["alias"];
	        this.value = source["value"];
	        this.providerKey = source["providerKey"];
	        this.environment = source["environment"];
	        this.description = source["description"];
	        this.expiresAt = source["expiresAt"];
	        this.status = source["status"];
	        this.statusNote = source["statusNote"];
	    }
	}
	export class ImportPreviewResult {
	    headers: string[];
	    rows: ImportRowDTO[];
	    colMap: ColMapDTO;
	    errors: string[];
	
	    static createFrom(source: any = {}) {
	        return new ImportPreviewResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.headers = source["headers"];
	        this.rows = this.convertValues(source["rows"], ImportRowDTO);
	        this.colMap = this.convertValues(source["colMap"], ColMapDTO);
	        this.errors = source["errors"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ProviderDTO {
	    key: string;
	    name: string;
	    category: string;
	    builtin: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProviderDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.name = source["name"];
	        this.category = source["category"];
	        this.builtin = source["builtin"];
	    }
	}
	export class SecretSummaryDTO {
	    id: number;
	    alias: string;
	    providerKey: string;
	    providerName: string;
	    environment: string;
	    tags: string[];
	    folderName: string;
	    description: string;
	    expiresAt?: number;
	    lastUsedAt?: number;
	    isArchived: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SecretSummaryDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.alias = source["alias"];
	        this.providerKey = source["providerKey"];
	        this.providerName = source["providerName"];
	        this.environment = source["environment"];
	        this.tags = source["tags"];
	        this.folderName = source["folderName"];
	        this.description = source["description"];
	        this.expiresAt = source["expiresAt"];
	        this.lastUsedAt = source["lastUsedAt"];
	        this.isArchived = source["isArchived"];
	    }
	}

}

