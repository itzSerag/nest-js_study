import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
// import { AuthController } from "./auth.controller";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) {}

    async signup(dto: AuthDto) {
        // hash

        try {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(dto.password, salt);

            const user = await this.prisma.user.create({
                data: {
                    password: hash,
                    email: dto.email,
                    firstName: dto.firstName,
                    lastName: dto.lastName,
                },

                select: {
                    id: true,
                    email: true,
                    createdAt: true,
                },
            });

            return user;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    // duplicate
                    throw new ForbiddenException('Duplicated Credntials');
                }
            }
        }
    }

    async login(dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if (!user) {
            throw new ForbiddenException('User not found')
        }

        const pwMatches = await bcrypt.compare(dto.password , user.password);
        if (!pwMatches) throw new ForbiddenException('User not found');
        
        delete user.password
        return user
    }
}
