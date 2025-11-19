/**
 * @example ```js
 * {
 *       "1-3-3-7.net":"disposable"
 * }
 * ```
 */
declare type TBlacklist = Object;

declare type TOptions = {
    blacklist: TBlacklist,
    allowFreemail:boolean,
    allowDisposable:boolean
}

declare type TPtrStatus = "good" | "suspicious"

declare type TDnsResults = {
    valid: boolean;
    reason: string;
    mxRecords?: undefined;
    ptrStatus?: TPtrStatus;
} | {
    valid: boolean;
    mxRecords: ({
        mx: string;
        valid: boolean;
        reason: string;
        ips?: undefined;
        ptrOk?: undefined;
    } | {
        mx: string;
        ips: string[];
        ptrOk: boolean | undefined;
        valid?: undefined;
        reason?: undefined;
    })[];
    ptrStatus: TPtrStatus;
    reason?: undefined;
}
declare type TValidateReturn = Promise<{
    dnsResults: TDnsResults
    domainAllowed: boolean;
}>

declare type TValidateEmailDnsReturn = Promise<TDnsResults>

declare class Validator {
    constructor(options:TOptions = { allowDisposable:false, allowFreemail:false});
    private options: TOptions;
    private expandIpv6(ip:string): string;
    private validateEmailDns(email:string): TValidateEmailDnsReturn;
    validate(mail:string): TValidateReturn;
}

export = Validator;
