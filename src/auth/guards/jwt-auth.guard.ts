import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private authService: AuthService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromCookie(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    // Decodificar el token para obtener el userId
    const decodedToken = this.authService.decodeToken(token);
    if (!decodedToken || !decodedToken.sub) {
      throw new UnauthorizedException('Invalid token');
    }

    const isInvalidToken = await this.authService.isTokenInvalid(
      decodedToken.sub,
    );
    if (isInvalidToken) {
      throw new UnauthorizedException(
        'Token is invalid or has been logged out',
      );
    }

    return super.canActivate(context) as Promise<boolean>;
  }

  private extractTokenFromCookie(request: any): string | undefined {
    return request.cookies['access_token'];
  }
}
