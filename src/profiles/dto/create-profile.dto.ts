import {
  IsString,
  IsOptional,
  IsArray,
  MinLength,
  MaxLength,
  Matches,
  IsUrl,
  ArrayMaxSize,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateProfileDto {
  @IsString()
  @MinLength(2, { message: 'Le prénom doit contenir au moins 2 caractères' })
  @MaxLength(50, { message: 'Le prénom ne doit pas dépasser 50 caractères' })
  @Matches(/^[a-zA-ZÀ-ÿ\s'-]+$/, {
    message: 'Le prénom ne doit contenir que des lettres',
  })
  @Transform(({ value }) => value?.trim())
  firstName: string;

  @IsString()
  @MinLength(2, { message: 'Le nom doit contenir au moins 2 caractères' })
  @MaxLength(50, { message: 'Le nom ne doit pas dépasser 50 caractères' })
  @Matches(/^[a-zA-ZÀ-ÿ\s'-]+$/, {
    message: 'Le nom ne doit contenir que des lettres',
  })
  @Transform(({ value }) => value?.trim())
  lastName: string;

  @IsString()
  @IsOptional()
  @Matches(/^(\+33|0)[1-9](\d{2}){4}$/, {
    message: 'Format téléphone invalide (ex: 0612345678 ou +33612345678)',
  })
  phone?: string;

  @IsUrl({}, { message: 'URL avatar invalide' })
  @IsOptional()
  avatarUrl?: string;

  @IsString()
  @IsOptional()
  @MaxLength(500, { message: 'La bio ne doit pas dépasser 500 caractères' })
  @Transform(({ value }) => value?.trim())
  bio?: string;

  @IsArray()
  @IsString({ each: true })
  @ArrayMaxSize(20, { message: 'Maximum 20 compétences' })
  @IsOptional()
  @Transform(({ value }) => value?.map((s: string) => s.trim().toLowerCase()))
  skills?: string[];

  @IsString()
  @IsOptional()
  @MaxLength(100, { message: 'La disponibilité ne doit pas dépasser 100 caractères' })
  @Transform(({ value }) => value?.trim())
  availability?: string;

  @IsString()
  @IsOptional()
  @MaxLength(200, { message: 'La localisation ne doit pas dépasser 200 caractères' })
  @Transform(({ value }) => value?.trim())
  location?: string;

  @IsString()
  @IsOptional()
  @MaxLength(100, { message: 'La ville ne doit pas dépasser 100 caractères' })
  @Transform(({ value }) => value?.trim())
  city?: string;

  @IsString()
  @IsOptional()
  @Matches(/^\d{5}$/, { message: 'Code postal invalide (5 chiffres)' })
  postalCode?: string;
}
