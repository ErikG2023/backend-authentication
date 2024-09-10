import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { InvalidToken } from './entities/invalid-token.entity';

@Injectable()
export class TokenCleanupService {
  private readonly logger = new Logger(TokenCleanupService.name);

  constructor(
    @InjectRepository(InvalidToken)
    private invalidTokenRepository: Repository<InvalidToken>,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleTokenCleanup() {
    this.logger.debug('Starting token cleanup');

    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    const result = await this.invalidTokenRepository.delete({
      createdAt: LessThan(oneWeekAgo),
    });

    this.logger.debug(`Cleaned up ${result.affected} invalid tokens`);
  }
}
