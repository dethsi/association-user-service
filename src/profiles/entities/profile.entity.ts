import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';

@Entity('profiles')
export class Profile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @OneToOne(() => User, (user) => user.profile)
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column({ type: 'varchar', nullable: true })
  phone: string | null;

  @Column({ type: 'varchar', nullable: true })
  avatarUrl: string | null;

  @Column({ type: 'text', nullable: true })
  bio: string | null;

  @Column('simple-array', { nullable: true })
  skills: string[];

  @Column({ type: 'varchar', nullable: true })
  availability: string | null;

  @Column({ type: 'varchar', nullable: true })
  location: string | null;

  @Column({ type: 'varchar', nullable: true })
  city: string | null;

  @Column({ type: 'varchar', nullable: true })
  postalCode: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Computed property
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`;
  }
}
