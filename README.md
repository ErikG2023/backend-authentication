# NestJS E-commerce Backend

Este proyecto es un backend de e-commerce construido con NestJS, TypeORM y PostgreSQL. Proporciona una API RESTful para manejar autenticación de usuarios, gestión de productos, y más.

## Características

- Autenticación de usuarios (registro, inicio de sesión, cierre de sesión)
- Gestión de tokens JWT (access token y refresh token)
- Roles de usuario (admin y usuario regular)
- Protección de rutas basada en roles
- Gestión de contraseñas olvidadas y restablecimiento de contraseñas
- Logging de actividades de usuario
- Limpieza automática de tokens inválidos

## Requisitos previos

- Node.js (v14 o superior)
- npm o yarn
- PostgreSQL

## Configuración

1. Clona el repositorio:
   ```
   git clone https://github.com/tu-usuario/tu-repo.git
   cd tu-repo
   ```

2. Instala las dependencias:
   ```
   npm install
   ```

3. Copia el archivo `.env.example` a `.env` y configura las variables de entorno:
   ```
   cp .env.example .env
   ```

4. Edita el archivo `.env` con tus configuraciones específicas.

5. Ejecuta las migraciones de la base de datos:
   ```
   npm run typeorm migration:run
   ```

## Ejecución

Para ejecutar el proyecto en modo de desarrollo:

```
npm run start:dev
```

Para construir y ejecutar el proyecto en modo de producción:

```
npm run build
npm run start:prod
```

## Estructura del proyecto

- `src/auth`: Módulo de autenticación y autorización
- `src/common`: Elementos comunes como enums y utilidades
- `src/config`: Configuraciones de la aplicación
- `src/migrations`: Migraciones de la base de datos

## Pruebas

Para ejecutar las pruebas unitarias:

```
npm run test
```

Para ejecutar las pruebas e2e:

```
npm run test:e2e
```

## Docker

El proyecto incluye un `docker-compose.yml` para facilitar la configuración del entorno de desarrollo. Para iniciar la base de datos PostgreSQL:

```
docker-compose up -d
```

## Contribuir

Las contribuciones son bienvenidas. Por favor, abre un issue o realiza un pull request con tus cambios.

## Licencia

[MIT](https://choosealicense.com/licenses/mit/)#   b a c k e n d - a u t h e n t i c a t i o n  
 