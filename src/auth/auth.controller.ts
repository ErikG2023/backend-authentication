import {
  Controller,
  Post,
  UseGuards,
  Body,
  Get,
  Param,
  Res,
  Req,
  UnauthorizedException,
  Put,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Request, Response } from 'express';
import { UpdateUserDto } from './dto/update-user.dto';

// Extendemos la interfaz Request de Express para incluir las propiedades adicionales
interface ExtendedRequest extends Request {
  user?: any;
}

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(
    @Body() registerDto: RegisterDto,
    @Req() req: ExtendedRequest,
  ) {
    const ipAddress =
      req.ip || (req.socket?.remoteAddress as string) || 'Unknown';
    const userAgent = req.get('user-agent') || 'Unknown';
    return this.authService.register(registerDto, ipAddress, userAgent);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(
    @Req() req: ExtendedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ipAddress =
      req.ip || (req.socket?.remoteAddress as string) || 'Unknown';
    const userAgent = req.get('user-agent') || 'Unknown';
    return this.authService.login(req.user, ipAddress, userAgent, res);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @Req() req: ExtendedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ipAddress =
      req.ip || (req.socket?.remoteAddress as string) || 'Unknown';
    const userAgent = req.get('user-agent') || 'Unknown';
    const userId = req.user?.id || req.user?.sub;
    return this.authService.logout(userId, ipAddress, userAgent, res);
  }

  @UseGuards(JwtAuthGuard)
  @Get('user/:id')
  async getUserById(@Param('id') id: string, @Req() req: ExtendedRequest) {
    console.log('User in controller:', req.user);
    return this.authService.getUserById(id, req.user);
  }

  @Post('refresh')
  async refreshToken(
    @Req() req: ExtendedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }

    const ipAddress =
      req.ip || (req.socket?.remoteAddress as string) || 'Unknown';
    const userAgent = req.get('user-agent') || 'Unknown';

    return this.authService.refreshToken(
      refreshToken,
      ipAddress,
      userAgent,
      res,
    );
  }

  @Post('forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Req() req: ExtendedRequest,
  ) {
    const ipAddress =
      req.ip || (req.socket?.remoteAddress as string) || 'Unknown';
    const userAgent = req.get('user-agent') || 'Unknown';
    await this.authService.forgotPassword(
      forgotPasswordDto.email,
      ipAddress,
      userAgent,
    );
    return { message: 'If the email exists, a reset link has been sent.' };
  }

  @Post('reset-password')
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() req: ExtendedRequest,
  ) {
    const ipAddress =
      req.ip || (req.socket?.remoteAddress as string) || 'Unknown';
    const userAgent = req.get('user-agent') || 'Unknown';
    await this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
      ipAddress,
      userAgent,
    );
    return { message: 'Password has been reset successfully.' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('verify-token')
  async verifyToken(@Req() req: ExtendedRequest) {
    const userId = req.user?.id;
    return this.authService.verifyToken(userId);
  }

  @UseGuards(JwtAuthGuard)
  @Get('users')
  async getUsers(@Req() req: ExtendedRequest) {
    return this.authService.getUsers(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Put('user/:id')
  async updateUser(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Req() req: ExtendedRequest,
  ) {
    return this.authService.updateUser(id, updateUserDto, req.user);
  }
}
