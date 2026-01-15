import {
  Controller,
  Post,
  Get,
  Put,
  Body,
  UseGuards,
  Req,
} from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { Request } from 'express';
import { ProfilesService } from './profiles.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { JwtPayload } from '../auth/guards/jwt.strategy';
import { CreateProfileDto, UpdateProfileDto } from './dto';

interface RequestWithUser extends Request {
  user: JwtPayload;
}

@Controller('profile')
@UseGuards(ThrottlerGuard, JwtAuthGuard)
export class ProfilesController {
  constructor(private readonly profilesService: ProfilesService) {}

  @Post()
  async create(@Req() req: RequestWithUser, @Body() dto: CreateProfileDto) {
    return this.profilesService.create({
      userId: req.user.sub,
      ...dto,
    });
  }

  @Get()
  async get(@Req() req: RequestWithUser) {
    return this.profilesService.findByUserId(req.user.sub);
  }

  @Put()
  async update(@Req() req: RequestWithUser, @Body() dto: UpdateProfileDto) {
    return this.profilesService.update(req.user.sub, dto);
  }
}
