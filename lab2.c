 #include <stdio.h>
 #include <string.h>
 #include <libakrypt.h>
 
int main(int argc, char* argv[]){
  if (argc!= 4){
      printf("Enter file path as 1st arg, password 2nd arg and salt as the 3rd arg.\n");
      return EXIT_FAILURE;
    }
  if(strlen(argv[2]) == NULL){
      printf("Password should be\n");
      return EXIT_FAILURE;
    }
  if(strlen(argv[3]) == NULL){
      printf("Salt should be\n");
      return EXIT_FAILURE;
    }

// открываем переданный файл на чтение
  FILE *file=fopen(argv[1],"rb");
  if (file==NULL){
      printf("Can't open file\n");
      return EXIT_FAILURE;
    }

// переместить внутренний указатель в конец файла
  fseek(file,0,SEEK_END);
// размер файла в байтах
  int inlen=(int)ftell(file);
// установить внутренний указатель файла в начало
  rewind(file);
// инициализируем массивы для не входных и шифрованных данных
  ak_uint8 data[inlen];
  ak_uint8 out[inlen];
// считываем информацию из файла в массив
  fread(data,1,inlen,file);
  fclose(file);
// получаем длину пароля и соли
  int  password_len_ =strlen(argv[2]);
  int  salt_len_ = strlen(argv[3]);
// записываем значение пароля и соли в переменные
  unsigned char* password_ = (unsigned char*)argv[2];
  unsigned char* salt_ = (unsigned char*)argv[3];

 /* контекст секретного ключа */
  struct bckey ctx;

 /* значение синхропосылки */
  ak_uint8 iv[8] = { 0x03, 0x07, 0xae, 0xf1 };

 /* инициализируем криптобиблиотеку
    и явно указываем функцию вывода сообщений аудита */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* создаем ключ и присваиваем ему значение, выработанное из пароля пользователя */
  ak_bckey_create_kuznechik( &ctx );
  ak_bckey_set_key_from_password( &ctx, password_, password_len_, salt_, salt_len_ );

 /* зашифровываем данные единым фрагментом */
  ak_bckey_ctr( &ctx, data, out, inlen, iv, 8 );

// открываем переданный файл на запись
  FILE* encfile=fopen(argv[1],"wb");
// записываем зашифрованные данные в файл
  fwrite(out,1,inlen,encfile);
  fclose(encfile);

 /* освобождаем контекст секретного ключа */
  ak_bckey_destroy( &ctx );
  ak_libakrypt_destroy();

  return EXIT_SUCCESS;
}
