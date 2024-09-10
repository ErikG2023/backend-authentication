// src/auth/user-activity.service.ts

import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserActivity, ActivityType } from './entities/user-activity.entity';
import { User } from './entities/user.entity';

@Injectable()
export class UserActivityService {
  constructor(
    @InjectRepository(UserActivity)
    private userActivityRepository: Repository<UserActivity>,
  ) {}

  async logActivity(
    user: User,
    activityType: ActivityType,
    ipAddress: string,
    userAgent: string,
  ) {
    const activity = new UserActivity();
    activity.user = user;
    activity.userId = user.id;
    activity.activityType = activityType;
    activity.ipAddress = ipAddress;
    activity.userAgent = userAgent;

    await this.userActivityRepository.save(activity);
  }
}
