import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan, MoreThan } from 'typeorm';
import { User } from './entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { RefreshToken } from './entities/refresh-token.entity';
import { v4 as uuidv4 } from 'uuid';
import { InvalidToken } from './entities/invalid-token.entity';
import { ConfigService } from '@nestjs/config';
import { UserActivityService } from './user-activity.service';
import { ActivityType } from './entities/user-activity.entity';
import { LoginAttempt } from './entities/login-attempt.entity';
import { AuthUtils } from './auth.utils';
import { UserRole } from '../common/enums/user-role.enum';
import { Response } from 'express';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class AuthService {
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_TIME = 2 * 60 * 1000; // 2 minutos en milisegundos

  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(InvalidToken)
    private invalidTokenRepository: Repository<InvalidToken>,
    @InjectRepository(LoginAttempt)
    private loginAttemptRepository: Repository<LoginAttempt>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private userActivityService: UserActivityService,
  ) {}

  async validateUser(
    email: string,
    pass: string,
    ipAddress: string,
  ): Promise<any> {
    const now = new Date();
    console.log(`[${now.toISOString()}] Attempting to validate user: ${email}`);

    const lockoutPeriodStart = new Date(now.getTime() - this.LOCKOUT_TIME);

    const recentFailedAttempts = await this.loginAttemptRepository.count({
      where: {
        email,
        successful: false,
        createdAt: MoreThan(lockoutPeriodStart),
      },
    });

    console.log(`Recent failed attempts: ${recentFailedAttempts}`);

    const lastFailedAttempt = await this.loginAttemptRepository.findOne({
      where: {
        email,
        successful: false,
      },
      order: { createdAt: 'DESC' },
    });

    let isLockoutPeriodOver = true;
    let remainingLockoutTime = 0;

    if (lastFailedAttempt) {
      isLockoutPeriodOver = AuthUtils.isLockoutPeriodOver(
        lastFailedAttempt.createdAt,
        this.LOCKOUT_TIME,
      );
      remainingLockoutTime = AuthUtils.calculateRemainingLockoutTime(
        lastFailedAttempt.createdAt,
        this.LOCKOUT_TIME,
      );

      console.log(
        `Last failed attempt: ${lastFailedAttempt.createdAt.toISOString()}`,
      );
      console.log(`Current time: ${now.toISOString()}`);
      console.log(`Remaining lockout time: ${remainingLockoutTime} ms`);
    }

    console.log(`Is lockout period over: ${isLockoutPeriodOver}`);

    if (
      recentFailedAttempts >= this.MAX_LOGIN_ATTEMPTS &&
      !isLockoutPeriodOver
    ) {
      const remainingMinutes = Math.ceil(remainingLockoutTime / 60000);
      console.log(
        `Account is locked. Remaining lockout time: ${remainingMinutes} minutes`,
      );
      throw new UnauthorizedException(
        `Demasiados intentos fallidos. Por favor, inténtelo de nuevo en ${remainingMinutes} minuto(s).`,
      );
    }

    const user = await this.usersRepository.findOne({ where: { email } });
    if (user && (await bcrypt.compare(pass, user.password))) {
      await this.loginAttemptRepository.save({
        email,
        ipAddress,
        successful: true,
      });
      console.log(`[${now.toISOString()}] Login successful`);
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      return result;
    }

    await this.loginAttemptRepository.save({
      email,
      ipAddress,
      successful: false,
    });
    console.log(`[${now.toISOString()}] Login failed`);

    await this.cleanupOldAttempts(email);

    return null;
  }

  private async cleanupOldAttempts(email: string) {
    const cleanupDate = new Date(Date.now() - this.LOCKOUT_TIME);
    const result = await this.loginAttemptRepository.delete({
      email,
      createdAt: LessThan(cleanupDate),
    });
    console.log(
      `Cleaned up ${result.affected} old login attempts for ${email}`,
    );
  }

  async register(
    registerDto: RegisterDto,
    ipAddress: string,
    userAgent: string,
  ): Promise<User> {
    const { email, password, firstName, lastName, role } = registerDto;

    const existingUser = await this.usersRepository.findOne({
      where: { email },
    });
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    const user = new User();
    user.email = email;
    user.firstName = firstName;
    user.lastName = lastName;
    user.role = role;

    const salt = await bcrypt.genSalt();
    user.password = await bcrypt.hash(password, salt);

    try {
      const savedUser = await this.usersRepository.save(user);
      await this.userActivityService.logActivity(
        savedUser,
        ActivityType.REGISTER,
        ipAddress,
        userAgent,
      );
      return savedUser;
    } catch (error) {
      throw new InternalServerErrorException('Error creating user');
    }
  }

  async login(
    user: any,
    ipAddress: string,
    userAgent: string,
    response: Response,
  ) {
    const payload = {
      email: user.email,
      sub: user.id,
      role: user.role,
    };
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = await this.createRefreshToken(user);

    await this.invalidTokenRepository.delete({ token: user.id });

    await this.userActivityService.logActivity(
      user,
      ActivityType.LOGIN,
      ipAddress,
      userAgent,
    );

    const accessTokenExpiration = AuthUtils.parseDurationToMs(
      this.configService.get<string>('ACCESS_TOKEN_EXPIRATION'),
    );
    const refreshTokenExpiration = AuthUtils.parseDurationToMs(
      this.configService.get<string>('REFRESH_TOKEN_EXPIRATION'),
    );

    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: accessTokenExpiration,
    });

    response.cookie('refresh_token', refreshToken.token, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: refreshTokenExpiration,
    });

    return {
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };
  }

  async createRefreshToken(user: User): Promise<RefreshToken> {
    const refreshToken = new RefreshToken();
    refreshToken.user = user;
    refreshToken.token = uuidv4();
    refreshToken.expiresAt = new Date(
      Date.now() + this.getRefreshTokenExpiration(),
    );
    return this.refreshTokenRepository.save(refreshToken);
  }

  private getRefreshTokenExpiration(): number {
    const duration = this.configService.get<string>('REFRESH_TOKEN_EXPIRATION');
    return AuthUtils.parseDurationToMs(duration);
  }

  async refreshToken(
    token: string,
    ipAddress: string,
    userAgent: string,
    response: Response,
  ) {
    AuthUtils.validateRefreshToken(token);

    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token },
      relations: ['user'],
    });

    if (!refreshToken || refreshToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const invalidToken = await this.invalidTokenRepository.findOne({
      where: { token: refreshToken.user.id },
    });

    if (invalidToken) {
      await this.refreshTokenRepository.remove(refreshToken);
      throw new UnauthorizedException('Session has been invalidated');
    }

    const user = refreshToken.user;
    const payload = { email: user.email, sub: user.id, role: user.role };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.configService.get<string>('ACCESS_TOKEN_EXPIRATION'),
    });

    await this.refreshTokenRepository.remove(refreshToken);
    const newRefreshToken = await this.createRefreshToken(user);

    await this.userActivityService.logActivity(
      user,
      ActivityType.TOKEN_REFRESH,
      ipAddress,
      userAgent,
    );

    const accessTokenExpiration = AuthUtils.parseDurationToMs(
      this.configService.get<string>('ACCESS_TOKEN_EXPIRATION'),
    );
    const refreshTokenExpiration = AuthUtils.parseDurationToMs(
      this.configService.get<string>('REFRESH_TOKEN_EXPIRATION'),
    );

    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: accessTokenExpiration,
    });

    response.cookie('refresh_token', newRefreshToken.token, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: refreshTokenExpiration,
    });

    return {
      message: 'Token refreshed successfully',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };
  }

  decodeToken(token: string): any {
    try {
      return this.jwtService.verify(token);
    } catch (error) {
      return null;
    }
  }

  async isTokenInvalid(userId: string): Promise<boolean> {
    const invalidToken = await this.invalidTokenRepository.findOne({
      where: { token: userId },
    });
    return !!invalidToken;
  }

  async logout(
    userId: string,
    ipAddress: string,
    userAgent: string,
    response: Response,
  ) {
    const user = await this.usersRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('Invalid user');
    }

    await this.invalidTokenRepository.save({ token: userId });
    await this.refreshTokenRepository.delete({ userId });

    await this.userActivityService.logActivity(
      user,
      ActivityType.LOGOUT,
      ipAddress,
      userAgent,
    );

    response.clearCookie('access_token');
    response.clearCookie('refresh_token');

    return { message: 'Logout successful' };
  }

  async getUserById(id: string, requestUser: any): Promise<User> {
    console.log('Request User:', requestUser);

    const isInvalidToken = await this.isTokenInvalid(requestUser.id);
    if (isInvalidToken) {
      throw new UnauthorizedException('Token has been invalidated');
    }

    if (requestUser.role !== UserRole.ADMIN) {
      throw new UnauthorizedException(
        'Only administrators can access user information',
      );
    }

    const user = await this.usersRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }

    console.log('Requested User:', user);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...result } = user;
    return result as User;
  }

  async forgotPassword(
    email: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<void> {
    const user = await this.usersRepository.findOne({ where: { email } });
    if (!user) {
      return;
    }

    const resetToken = uuidv4();
    const resetTokenExpiration = new Date();
    resetTokenExpiration.setHours(resetTokenExpiration.getHours() + 1);

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetTokenExpiration;
    await this.usersRepository.save(user);

    await this.userActivityService.logActivity(
      user,
      ActivityType.PASSWORD_RESET_REQUEST,
      ipAddress,
      userAgent,
    );

    console.log(
      `Password reset link: http://yourfrontend.com/reset-password?token=${resetToken}`,
    );
  }

  async resetPassword(
    token: string,
    newPassword: string,
    ipAddress: string,
    userAgent: string,
  ): Promise<void> {
    const user = await this.usersRepository.findOne({
      where: { passwordResetToken: token },
    });

    if (!user || user.passwordResetExpires < new Date()) {
      throw new UnauthorizedException(
        'Invalid or expired password reset token',
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;

    await this.usersRepository.save(user);

    await this.userActivityService.logActivity(
      user,
      ActivityType.PASSWORD_RESET_SUCCESS,
      ipAddress,
      userAgent,
    );
  }

  async verifyToken(userId: string) {
    const isInvalidToken = await this.isTokenInvalid(userId);
    if (isInvalidToken) {
      throw new UnauthorizedException('Token has been invalidated');
    }

    const user = await this.usersRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Excluir la contraseña y otra información sensible
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, passwordResetToken, passwordResetExpires, ...result } =
      user;

    return {
      isValid: true,
      user: result,
    };
  }

  async getUsers(requestUser: any): Promise<User[]> {
    if (requestUser.role !== UserRole.ADMIN) {
      throw new UnauthorizedException(
        'Only administrators can access user list',
      );
    }

    const users = await this.usersRepository.find();
    return users.map((user) => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, ...result } = user;
      return result as User;
    });
  }

  async updateUser(
    id: string,
    updateUserDto: UpdateUserDto,
    requestUser: any,
  ): Promise<User> {
    const userToUpdate = await this.usersRepository.findOne({ where: { id } });
    if (!userToUpdate) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }

    if (requestUser.id !== id && requestUser.role !== UserRole.ADMIN) {
      throw new UnauthorizedException(
        'You are not authorized to update this user',
      );
    }

    // Solo los administradores pueden cambiar roles
    if (updateUserDto.role && requestUser.role !== UserRole.ADMIN) {
      throw new UnauthorizedException(
        'Only administrators can change user roles',
      );
    }

    // Verificar si el email ya está en uso
    if (updateUserDto.email && updateUserDto.email !== userToUpdate.email) {
      const userWithEmail = await this.usersRepository.findOne({
        where: { email: updateUserDto.email },
      });
      if (userWithEmail) {
        throw new ConflictException('Email is already in use');
      }
    }

    // Actualizar los campos
    Object.assign(userToUpdate, updateUserDto);

    // Si se proporciona una nueva contraseña, hashearla
    if (updateUserDto.password) {
      const salt = await bcrypt.genSalt();
      userToUpdate.password = await bcrypt.hash(updateUserDto.password, salt);
    }

    await this.usersRepository.save(userToUpdate);

    // Eliminar la contraseña del objeto de respuesta
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...result } = userToUpdate;
    return result as User;
  }
}
