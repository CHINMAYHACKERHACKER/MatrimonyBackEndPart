export class ResultError {
    status: number;
    isDisplayMessage: boolean;
    message: string;
    error: Error;
    value: string;

    constructor(status: number, isDisplayMessage: boolean, message: string, error: Error, value: string) {
        this.status = status;
        this.isDisplayMessage = isDisplayMessage;
        this.message = message;
        this.error = error;
        this.value = value;
    }
}