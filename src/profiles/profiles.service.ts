import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Profile } from './entities/profile.entity';
import { UsersService } from '../users/users.service';

export interface CreateProfileData {
  userId: string;
  firstName: string;
  lastName: string;
  phone?: string;
  avatarUrl?: string;
  bio?: string;
  skills?: string[];
  availability?: string;
  location?: string;
  city?: string;
  postalCode?: string;
}

export interface UpdateProfileData {
  firstName?: string;
  lastName?: string;
  phone?: string;
  avatarUrl?: string;
  bio?: string;
  skills?: string[];
  availability?: string;
  location?: string;
  city?: string;
  postalCode?: string;
}

export interface ProfileOutput {
  id: string;
  userId: string;
  firstName: string;
  lastName: string;
  fullName: string;
  phone: string | null;
  avatarUrl: string | null;
  bio: string | null;
  skills: string[];
  availability: string | null;
  location: string | null;
  city: string | null;
  postalCode: string | null;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class ProfilesService {
  constructor(
    @InjectRepository(Profile)
    private readonly profileRepository: Repository<Profile>,
    private readonly usersService: UsersService,
  ) {}

  async create(data: CreateProfileData): Promise<ProfileOutput> {
    // Verify user exists
    const user = await this.usersService.findById(data.userId);
    if (!user) {
      throw new NotFoundException('Utilisateur non trouvé');
    }

    const profile = new Profile();
    profile.userId = data.userId;
    profile.firstName = data.firstName.trim();
    profile.lastName = data.lastName.trim();
    profile.phone = data.phone || null;
    profile.avatarUrl = data.avatarUrl || null;
    profile.bio = data.bio?.trim() || null;
    profile.skills = data.skills?.map(s => s.trim().toLowerCase()) || [];
    profile.availability = data.availability?.trim() || null;
    profile.location = data.location?.trim() || null;
    profile.city = data.city?.trim() || null;
    profile.postalCode = data.postalCode || null;

    const savedProfile = await this.profileRepository.save(profile);

    return this.toOutput(savedProfile);
  }

  async findByUserId(userId: string): Promise<ProfileOutput> {
    const profile = await this.profileRepository.findOne({
      where: { userId },
    });

    if (!profile) {
      throw new NotFoundException('Profil non trouvé');
    }

    return this.toOutput(profile);
  }

  async update(userId: string, data: UpdateProfileData): Promise<ProfileOutput> {
    const profile = await this.profileRepository.findOne({
      where: { userId },
    });

    if (!profile) {
      throw new NotFoundException('Profil non trouvé');
    }

    // Update fields
    if (data.firstName !== undefined) {
      profile.firstName = data.firstName.trim();
    }
    if (data.lastName !== undefined) {
      profile.lastName = data.lastName.trim();
    }
    if (data.phone !== undefined) {
      profile.phone = data.phone || null;
    }
    if (data.avatarUrl !== undefined) {
      profile.avatarUrl = data.avatarUrl || null;
    }
    if (data.bio !== undefined) {
      profile.bio = data.bio?.trim() || null;
    }
    if (data.skills !== undefined) {
      profile.skills = data.skills.map(s => s.trim().toLowerCase());
    }
    if (data.availability !== undefined) {
      profile.availability = data.availability?.trim() || null;
    }
    if (data.location !== undefined) {
      profile.location = data.location?.trim() || null;
    }
    if (data.city !== undefined) {
      profile.city = data.city?.trim() || null;
    }
    if (data.postalCode !== undefined) {
      profile.postalCode = data.postalCode || null;
    }

    const updatedProfile = await this.profileRepository.save(profile);

    return this.toOutput(updatedProfile);
  }

  private toOutput(profile: Profile): ProfileOutput {
    return {
      id: profile.id,
      userId: profile.userId,
      firstName: profile.firstName,
      lastName: profile.lastName,
      fullName: profile.fullName,
      phone: profile.phone,
      avatarUrl: profile.avatarUrl,
      bio: profile.bio,
      skills: profile.skills || [],
      availability: profile.availability,
      location: profile.location,
      city: profile.city,
      postalCode: profile.postalCode,
      createdAt: profile.createdAt,
      updatedAt: profile.updatedAt,
    };
  }
}
