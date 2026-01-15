import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
} from 'typeorm';
import { Profile } from '../../profiles/entities/profile.entity';

export enum UserRole {
  MEMBER = 'member',
  MANAGER = 'manager',
  ADMIN = 'admin',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  passwordHash: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.MEMBER,
  })
  role: UserRole;

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ type: 'varchar', nullable: true })
  emailVerificationToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  emailVerificationExpires: Date | null;

  @Column({ type: 'varchar', nullable: true })
  passwordResetToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  passwordResetExpires: Date | null;

  @Column({ type: 'varchar', nullable: true })
  refreshToken: string | null;

  @OneToOne(() => Profile, (profile) => profile.user)
  profile: Profile;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Helper methods
  isEmailVerificationTokenValid(): boolean {
    if (!this.emailVerificationToken || !this.emailVerificationExpires) {
      return false;
    }
    return this.emailVerificationExpires > new Date();
  }

  isPasswordResetTokenValid(): boolean {
    if (!this.passwordResetToken || !this.passwordResetExpires) {
      return false;
    }
    return this.passwordResetExpires > new Date();
  }
}
