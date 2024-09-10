import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('login_attempts')
export class LoginAttempt {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  email: string;

  @Column()
  ipAddress: string;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ default: false })
  successful: boolean;
}
