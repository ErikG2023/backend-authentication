import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { InvalidToken } from './entities/invalid-token.entity';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { TokenCleanupService } from './token-cleanup.service';
import { UserActivity } from './entities/user-activity.entity';
import { UserActivityService } from './user-activity.service';
import { LoginAttempt } from './entities/login-attempt.entity';

@Module({
  imports: [
    PassportModule,
    TypeOrmModule.forFeature([
      User,
      RefreshToken,
      InvalidToken,
      UserActivity,
      LoginAttempt,
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('ACCESS_TOKEN_EXPIRATION'),
        }, // Duración del Access Token desde el .env
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    LocalStrategy,
    JwtAuthGuard,
    TokenCleanupService,
    UserActivityService,
  ],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}
