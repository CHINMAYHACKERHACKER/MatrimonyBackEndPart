export class ResultSuccess {
    status: number;
    isDisplayMessage: boolean;
    message: string;
    recordList: any[];
    totalRecords: number;
    token: string;

    constructor(status: number, isDisplayMessage: boolean, message: string, recordList: any[], totalRecords: number, token: string) {
        this.status = status;
        this.isDisplayMessage = isDisplayMessage;
        this.message = message;
        this.recordList = recordList;
        this.totalRecords = totalRecords;
        this.token = token;
    }
}