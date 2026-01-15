import { IsEmail } from 'class-validator';
import { Transform } from 'class-transformer';

export class ForgotPasswordDto {
  @IsEmail({}, { message: 'Format email invalide' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;
}
