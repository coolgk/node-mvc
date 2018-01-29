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

export enum ResponseError {
    File_Not_Found = 'File Not Found'
}

/**
 * setting / getting standard responses in controllers
 */
export class Response {

    private _response: IResponse;

    /**
     * @returns {object} - last set response. format: { code: number, json?: any, status?: string, file?: { path: string, name?: string } }
     * @memberof Response
     */
    public getResponse (): IResponse {
        return this._response;
    }

    /**
     * set arbitrary response
     * @param {object} data - any json data
     * @param {number} [code=200] - http status code
     * @returns {object} - set response. format: { code: number, ...data }
     * @memberof Response
     */
    public send (data: {[propName: string]: any}, code: number = 200): IResponse {
        return this._response = { ...data, code };
    }

    /**
     * set a json response
     * @param {object} json - any json data
     * @param {number} [code=200] - http status code
     * @returns {object} - set response. format: { code: number, json }
     * @memberof Response
     */
    public json (json: any, code: number = 200): IResponse {
        return this._response = { json, code };
    }

    /**
     * set a http status response
     * @param {string} [text] - text in response
     * @param {number} code - http status code
     * @returns {object} - set response. format: { code, status }
     * @memberof Response
     */
    public text (text: string, code: number = 200): IResponse {
        return this._response = { text, code };
    }

    /**
     * set a file download response
     * @param {string} path - file path
     * @param {string} [name] - file name, if undefined require('path').basename(path) will be used
     * @param {number} [code=200] - http status code
     * @returns {object} - set response. format: { file: { path, name }, code }
     * @memberof Response
     */
    public file (path: string, name: string, code: number = 200): IResponse {
        if (path) {
            if (!name || String(name).trim() === '') {
                name = basename(path);
            }
            return this._response = { file: { path, name }, code };
        }
        return this.text(ResponseError.File_Not_Found, 404);
    }

}

export default Response;
