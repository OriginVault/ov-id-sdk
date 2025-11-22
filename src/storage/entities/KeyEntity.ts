import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, Index } from 'typeorm';

@Entity('keys')
@Index(['did', 'algorithm'])
@Index(['keyId'])
@Index(['keyType'])
export class KeyEntity {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 255 })
  did!: string;

  @Column({ type: 'varchar', length: 255 })
  keyId!: string;

  @Column({ type: 'varchar', length: 50 })
  algorithm!: string;

  @Column({ type: 'varchar', length: 50 })
  keyType!: string;

  @Column({ type: 'text' })
  publicKeyHex!: string;

  @Column({ type: 'text' })
  encryptedPrivateKeyHex!: string;

  @Column({ type: 'json', nullable: true })
  metadata?: any;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
