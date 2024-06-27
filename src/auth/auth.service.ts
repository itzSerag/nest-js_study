import { Injectable } from "@nestjs/common";
// import { AuthController } from "./auth.controller";



@Injectable()
export class AuthService {

    async login() {
        return 'login';
    }
}