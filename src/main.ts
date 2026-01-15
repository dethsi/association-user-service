import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Supprime les propriétés non déclarées dans DTO
      forbidNonWhitelisted: true, // Erreur si propriété inconnue
      transform: true, // Convertit automatiquement les types
    }),
  );

  // Enable CORS
  app.enableCors();

  // Connect to RabbitMQ
  const rabbitmqUrl = configService.get<string>('RABBITMQ_URL');
  if (rabbitmqUrl) {
    app.connectMicroservice<MicroserviceOptions>({
      transport: Transport.RMQ,
      options: {
        urls: [rabbitmqUrl],
        queue: 'user_queue',
        queueOptions: {
          durable: true,
        },
      },
    });
    await app.startAllMicroservices();
  }

  // Swagger configuration
  const swaggerConfig = new DocumentBuilder()
    .setTitle('User Service API')
    .setDescription('API pour l\'authentification et la gestion des profils utilisateurs')
    .setVersion('1.0')
    .addBearerAuth()
    .addTag('auth', 'Authentification (register, login, refresh)')
    .addTag('users', 'Gestion des utilisateurs')
    .addTag('profiles', 'Gestion des profils')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document);

  const port = configService.get<number>('PORT') || 3001;
  await app.listen(port);
  console.log(`User service is running on port ${port}`);
  console.log(`Swagger documentation available at http://localhost:${port}/api/docs`);
}

bootstrap();
