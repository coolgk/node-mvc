import { basename } from 'path';

export interface IResponse {
    code: number;
    json?: any;
    status?: string;
    file?: {
        path: string;
        name?: string;
    };
    [index: string]: any;
}

export class Response {

    private _response: IResponse;

    public getResponse (): IResponse {
        return this._response;
    }

    public send (data: {[propName: string]: any}, code: number = 200): IResponse {
        return this._response = { ...data, code };
    }

    public json (json: any, code: number = 200): IResponse {
        return this._response = { json, code };
    }

    public status (code: number, status: string): IResponse {
        return this._response = { code, status };
    }

    public file (path: string, name: string = '', code: number = 200): IResponse {
        if (path) {
            if (!name || String(name).trim() === '') {
                name = basename(path);
            }
            return this._response = { file: { path, name }, code };
        }
        return this.status(404, 'File Not Found');
    }

}
