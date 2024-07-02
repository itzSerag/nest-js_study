import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) {}

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

            return this.generateToken(user.id, user.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    // duplicate
                    throw new ForbiddenException('Duplicated Credentials');
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
            throw new ForbiddenException('User not found');
        }

        const pwMatches = await bcrypt.compare(dto.password, user.password);
        if (!pwMatches) throw new ForbiddenException('User not found');

        return this.generateToken(user.id, user.email);
    }

    async generateToken(
        userId: number,
        email: string,
    ): Promise<{ access_token: string }> {
        const payload = {
            userId,
            email,
        };

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15d',
            secret: this.config.get('JWT_SECRET'),
        });

        return {
            access_token: token,
        };
    }
}
