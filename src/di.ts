
export interface IServices {
    [key: string]: any;
}

export default class DI {
    protected _services: IServices;

    constructor (): void {
        this._services = this._getServices();
    }

    public getServices (): IServices {
        return {};
    }
}
