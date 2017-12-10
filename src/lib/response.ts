
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

    public send(code: number, data: { [propName: string]: any }): IResponse {
        return this._response = { code: 200, ...data };
    }

    public json (json: any): IResponse {
        return this._response = { code: 200, json };
    }

    public status (code: number, data: any = ''): IResponse {
        return this._response = { code, data };
    }

    public file (file: any): IResponse {
        return this._response = { code: 200, file };
    }
}
