export interface IServices {
    [key: string]: any;
}

export class DI {
    protected _services: IServices;

    constructor () {
        this._services = this.getServices();
    }

    public getServices (): IServices {
        return {};
    }
}
