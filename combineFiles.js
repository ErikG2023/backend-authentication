const fs = require('fs');
const path = require('path');

// Lista de archivos a combinar
const files = [
  '.env',
  'src/auth/dto/register.dto.ts',
  'src/auth/dto/login.dto.ts',
  'src/auth/dto/refresh-token.dto.ts',
  'src/auth/dto/forgot-password.dto.ts',
  'src/auth/dto/reset-password.dto.ts',
  'src/auth/entities/user.entity.ts',
  'src/auth/entities/invalid-token.entity.ts',
  'src/auth/entities/refresh-token.entity.ts',
  'src/auth/entities/user-activity.entity.ts',
  'src/auth/entities/login-attempt.entity.ts',
  'src/auth/guards/jwt-auth.guard.ts',
  'src/auth/guards/local-auth.guard.ts',
  'src/auth/strategies/jwt.strategy.ts',
  'src/auth/strategies/local.strategy.ts',
  'src/auth/auth.controller.ts',
  'src/auth/auth.module.ts',
  'src/auth/auth.service.ts',
  'src/auth/token-cleanup.service.ts',
  'src/auth/user-activity.service.ts',
  'src/auth/auth.utils.ts',
  'src/common/enums/user-role.enum.ts',
  'src/config/typeorm.config.ts',
  'src/app.module.ts',
  'ormconfig.ts',
  'docker-compose.yml',
];

// Nombre del archivo de salida
const outputFile = 'combined.txt';

// Función para combinar los archivos
function combineFiles(fileList, output) {
  let combinedContent = '';

  fileList.forEach((filePath) => {
    const absolutePath = path.join(__dirname, filePath);
    const fileContent = fs.readFileSync(absolutePath, 'utf-8');
    combinedContent += `\n// ----- ${filePath} -----\n\n`; // Añade el nombre del archivo al contenido combinado
    combinedContent += fileContent;
    combinedContent += '\n'; // Añade un salto de línea entre archivos
  });

  fs.writeFileSync(output, combinedContent, 'utf-8');
  console.log(`Todos los archivos se han combinado en ${output}`);
}

// Ejecutar la función
combineFiles(files, outputFile);
