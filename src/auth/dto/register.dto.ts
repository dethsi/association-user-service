import {
  IsEmail,
  IsString,
  MinLength,
  MaxLength,
  Matches,
  IsEnum,
  IsOptional,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { UserRole } from '../../users/entities/user.entity';

export class RegisterDto {
  @IsEmail({}, { message: 'Format email invalide' })
  @Transform(({ value }) => value?.toLowerCase().trim())
  email: string;

  @IsString()
  @MinLength(8, { message: 'Le mot de passe doit contenir au moins 8 caractères' })
  @MaxLength(50, { message: 'Le mot de passe ne doit pas dépasser 50 caractères' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/, {
    message:
      'Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial (@$!%*?&)',
  })
  password: string;

  @IsEnum(UserRole, { message: 'Rôle invalide (member ou manager)' })
  @IsOptional()
  role?: UserRole = UserRole.MEMBER;
}
