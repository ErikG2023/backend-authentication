import { UnauthorizedException } from '@nestjs/common';

export class AuthUtils {
  static parseDurationToMs(duration: string): number {
    const units = {
      s: 1000,
      m: 1000 * 60,
      h: 1000 * 60 * 60,
      d: 1000 * 60 * 60 * 24,
    };
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error('Invalid duration format');
    }
    const value = parseInt(match[1], 10);
    const unit = match[2] as keyof typeof units;
    return value * units[unit];
  }

  static extractTokenFromHeader(request: any): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  static validateRefreshToken(refreshToken: string | undefined): void {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token is required');
    }
  }

  static isLockoutPeriodOver(
    lastFailedAttempt: Date,
    lockoutTime: number,
  ): boolean {
    const now = new Date();
    return now.getTime() - lastFailedAttempt.getTime() >= lockoutTime;
  }

  static calculateRemainingLockoutTime(
    lastFailedAttempt: Date,
    lockoutTime: number,
  ): number {
    const now = new Date();
    return Math.max(
      0,
      lockoutTime - (now.getTime() - lastFailedAttempt.getTime()),
    );
  }
}
