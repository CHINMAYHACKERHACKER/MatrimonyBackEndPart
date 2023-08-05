import { Roles } from "../roles";

export class Users {
    id: number
    firstName: string;
    middleName: string;
    lastName: string;
    contactNo: string;
    email: string;
    gender: string;
    password: string;
    imageId: number;
    isPasswordSet: boolean;
    isDisabled: boolean;
    isVerified: boolean;
    isActive: boolean;
    isDelete: boolean;
    createdDate: Date;
    modifiedDate: Date;
    createdBy: number;
    modifiedBy: number;
    roleId: number;
    role: Roles;
    token: string

    constructor(id: number, firstName: string, middleName: string, lastName: string, contactNo: string, email: string, gender: string, password: string, imageId: number, isPasswordSet: boolean, isDisabled: boolean, isVerified: boolean, isActive: boolean, isDelete: boolean, createdDate: Date, modifiedDate: Date, createdBy: number, modifiedBy: number, roleId: number, role: Roles, token: string ) {
        this.id = id;
        this.firstName = firstName;
        this.middleName = middleName;
        this.lastName = lastName;
        this.contactNo = contactNo;
        this.email = email;
        this.gender = gender;
        this.password = password;
        this.imageId = imageId;
        this.isPasswordSet = isPasswordSet;
        this.isDisabled = isDisabled;
        this.isVerified = isVerified;
        this.isActive = isActive;
        this.isDelete = isDelete;
        this.createdDate = createdDate;
        this.modifiedDate = modifiedDate;
        this.createdBy = createdBy;
        this.modifiedBy = modifiedBy;
        this.roleId = roleId;
        this.role = role;
        this.token = token;
    }
}