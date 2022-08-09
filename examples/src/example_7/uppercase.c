extern int _puts(char *str);

void uppercase_and_print(char *text)
{
    char str[15] = {0};
    for(int i=0; i<14; i++){
        // if character is a lowercase letter make it uppercase:
        if(text[i] >= 0x61 && text[i] <= 0x7A)
            str[i] = text[i]-0x20;
        else
            str[i] = text[i];
    }
    _puts(str);
}
