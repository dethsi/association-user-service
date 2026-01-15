import { IsString, IsNotEmpty, MinLength, MaxLength, Matches } from 'class-validator';

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty({ message: 'Le token est requis' })
  token: string;

  @IsString()
  @MinLength(8, { message: 'Le mot de passe doit contenir au moins 8 caractères' })
  @MaxLength(50, { message: 'Le mot de passe ne doit pas dépasser 50 caractères' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/, {
    message:
      'Le mot de passe doit contenir au moins une majuscule, une minuscule, un chiffre et un caractère spécial (@$!%*?&)',
  })
  password: string;
}
