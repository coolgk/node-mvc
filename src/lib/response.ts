export interface IResponse {
    code: number;
    json?: any;
    data?: any;
    file?: {
        filepath: string,
        filename?: string
    };
}

export class Response {

    private _response: IResponse;

    public getResponse (): IResponse {
        return this._response;
    }

    public send (data: any, code: number = 200): IResponse {
        return this._response = { data, code };
    }

    public json (json: any, code: number = 200): IResponse {
        return this._response = { json, code };
    }

    public status (code: number): IResponse {
        return this._response = { code };
    }

    public file (file: any, code: number = 200): IResponse {
        return this._response = { file, code };
    }

}
