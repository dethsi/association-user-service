import {
  Controller,
  Post,
  Body,
  UseGuards,
  Req,
  HttpCode,
  HttpStatus,
  Query,
  Get,
} from '@nestjs/common';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtPayload } from './guards/jwt.strategy';
import {
  RegisterDto,
  LoginDto,
  RefreshDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './dto';

interface RequestWithUser extends Request {
  user: JwtPayload;
}

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email, dto.password, dto.role);
  }

  @Post('login')
  @Throttle({ short: { limit: 5, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto.email, dto.password);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() dto: RefreshDto) {
    return this.authService.refreshToken(dto.refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: RequestWithUser) {
    await this.authService.logout(req.user.sub);
    return { message: 'Déconnexion réussie' };
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    await this.authService.verifyEmail(token);
    return { message: 'Email vérifié avec succès' };
  }

  @Post('resend-verification')
  @UseGuards(JwtAuthGuard)
  @Throttle({ short: { limit: 2, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async resendVerification(@Req() req: RequestWithUser) {
    await this.authService.resendVerification(req.user.sub);
    return { message: 'Email de vérification envoyé' };
  }

  @Post('forgot-password')
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.authService.forgotPassword(dto.email);
    return { message: 'Si cet email existe, un lien de réinitialisation a été envoyé' };
  }

  @Post('reset-password')
  @Throttle({ short: { limit: 3, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.resetPassword(dto.token, dto.password);
    return { message: 'Mot de passe réinitialisé avec succès' };
  }
}
