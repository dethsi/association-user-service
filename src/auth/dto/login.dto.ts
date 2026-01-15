import { IsEmail, IsString, IsNotEmpty } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
  @IsEmail({}, { message: 'Format email invalide' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Le mot de passe est requis' })
  password: string;
}
