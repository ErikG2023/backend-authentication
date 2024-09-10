import { MigrationInterface, QueryRunner } from 'typeorm';

export class UpdateActivityTypeEnum1725551095919 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            ALTER TYPE user_activities_activitytype_enum ADD VALUE IF NOT EXISTS 'password_reset_request';
            ALTER TYPE user_activities_activitytype_enum ADD VALUE IF NOT EXISTS 'password_reset_success';
        `);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public async down(queryRunner: QueryRunner): Promise<void> {
    // No podemos eliminar valores de un enum en PostgreSQL, así que no hacemos nada aquí
  }
}
