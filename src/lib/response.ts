
export interface IResponse {
    code: number;
    json?: {};
    file?: {
        filepath: string;
        filename?: string;
    };
    [key: string]: any;
}

export class Response {
    
    private _response: IResponse;

    public getResponse(): IResponse {
        return this._response;
    }

    protected _send(code: number, data: { [propName: string]: any }): void {
        this._response = { code: 200, ...data };
    }

    protected _json (json: any): void {
        this._response = { code: 200, json };
    }

    protected _status (code: number, data: any): void {
        this._response = { code, data };
    }

    protected _file (file: any): void {
        this._response = { code: 200, file };
    }
}